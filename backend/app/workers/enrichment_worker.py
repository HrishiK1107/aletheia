import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import urlparse

from app.core.config import settings
from app.db.postgres import SessionLocal
from app.ingestion.enrichment.asn_lookup import lookup_asn
from app.ingestion.enrichment.dns_lookup import lookup_dns
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment
from app.ingestion.enrichment.registrar_lookup import lookup_registrar
from app.services.timeline_service import TimelineService
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ------------------------------------------------
# Hosting platform detection (fallback enrichment)
# ------------------------------------------------

HOSTING_PLATFORMS = {
    "github.io": "GitHub Pages",
    "vercel.app": "Vercel",
    "webflow.io": "Webflow",
    "netlify.app": "Netlify",
    "pages.dev": "Cloudflare Pages",
    "blogspot.com": "Google Blogger",
    "firebaseapp.com": "Firebase Hosting",
    "appspot.com": "Google App Engine",
}

# ------------------------------------------------
# Safe lookup wrapper
# ------------------------------------------------


def safe_lookup(func, *args):
    try:
        return func(*args)
    except Exception as e:
        logger.debug(f"Lookup failed: {func.__name__} {args} {e}")
        return None


# ------------------------------------------------
# Cached network lookups. Several indicators commonly share a domain (a
# domain and its own URLs, or multiple URL paths on one site -- see the
# cluster-attribution baseline in CONTEXT.md item 2.1), so without a cache
# each one triggers its own DNS/WHOIS round-trip for the identical domain.
# functools.lru_cache is safe under the thread pool below: its internal
# lock serializes cache reads/writes. A concurrent miss on the same
# not-yet-cached key can still call through more than once -- wasted
# duplicate work, not a correctness issue. A failed lookup (None) is
# cached too, on the assumption that a DNS/WHOIS failure for a given
# domain is more likely to keep failing within one run than to be a
# transient blip worth retrying immediately.
# ------------------------------------------------


@lru_cache(maxsize=None)
def cached_lookup_dns(domain: str):
    return lookup_dns(domain)


@lru_cache(maxsize=None)
def cached_lookup_registrar(domain: str):
    return lookup_registrar(domain)


@lru_cache(maxsize=None)
def cached_lookup_asn(ip: str):
    return lookup_asn(ip)


# ------------------------------------------------
# Domain extraction helper
# ------------------------------------------------


def extract_domain(value: str) -> str:
    parsed = urlparse(value)

    if parsed.netloc:
        return parsed.netloc.lower()

    return value.lower()


# ------------------------------------------------
# Detect known hosting providers
# ------------------------------------------------


def detect_hosting_platform(domain: str) -> str | None:
    for suffix, provider in HOSTING_PLATFORMS.items():
        if domain.endswith(suffix):
            return provider

    return None


# ------------------------------------------------
# Normalize list values
# ------------------------------------------------


def normalize_list(values: list[str] | None, lowercase: bool = True) -> str | None:
    """
    Dedup + comma-join. lowercase=False for values where case is part of
    the canonical identity (ASN codes, e.g. "AS13335") rather than
    incidental (domains/nameservers, which are case-insensitive by DNS
    convention and safe to fold).
    """
    if not values:
        return None

    cleaned = []
    seen = set()

    for value in values:
        if not value:
            continue

        item = str(value).strip()

        if lowercase:
            item = item.lower()

        if not item or item in seen:
            continue

        seen.add(item)
        cleaned.append(item)

    if not cleaned:
        return None

    return ",".join(cleaned)


# ------------------------------------------------
# Pure enrichment lookups (no DB access) -- safe to run concurrently
# across worker threads. DB writes happen in the caller, each with its
# own session (SQLAlchemy sessions are not safe to share across threads).
# ------------------------------------------------


def build_enrichment_data(indicator_type: str, indicator_value: str) -> dict:

    enrichment_data = {
        "asn": None,
        "hosting_provider": None,
        "nameservers": None,
        "registrar": None,
        "resolved_ips": None,
    }

    domain = None

    # ------------------------------------------------
    # IP enrichment
    # ------------------------------------------------

    if indicator_type == "ip":

        asn_data = safe_lookup(cached_lookup_asn, indicator_value)

        if asn_data:
            enrichment_data["asn"] = asn_data.get("asn")
            enrichment_data["hosting_provider"] = asn_data.get("hosting_provider")

    # ------------------------------------------------
    # Domain extraction
    # ------------------------------------------------

    if indicator_type == "domain":
        domain = indicator_value.lower()

    if indicator_type == "url":
        domain = extract_domain(indicator_value)

    # ------------------------------------------------
    # Domain infrastructure enrichment
    # ------------------------------------------------

    if domain:

        hosting = detect_hosting_platform(domain)

        if hosting:
            enrichment_data["hosting_provider"] = hosting

        dns_data = safe_lookup(cached_lookup_dns, domain)

        if dns_data:

            nameservers = dns_data.get("nameservers")
            ips = dns_data.get("ips", [])

            if nameservers:
                enrichment_data["nameservers"] = normalize_list(nameservers)

            if ips:

                enrichment_data["resolved_ips"] = normalize_list(ips)

                # CONTEXT.md item 2.3: iterate every resolved IP, not just
                # ips[0] -- load-balanced infrastructure spanning multiple
                # ASNs is exactly what campaigns use, and a single lookup
                # was silently collapsing that to one. asn is stored
                # comma-separated (matches graph_builder.py splitting it
                # into one RESOLVES_TO_ASN edge per value, same pattern as
                # nameservers).
                asns = []

                for resolved_ip in ips:

                    asn_data = safe_lookup(cached_lookup_asn, resolved_ip)

                    if not asn_data:
                        continue

                    if asn_data.get("asn"):
                        asns.append(asn_data["asn"])

                    if not enrichment_data["hosting_provider"] and asn_data.get("hosting_provider"):
                        enrichment_data["hosting_provider"] = asn_data.get("hosting_provider")

                if asns:
                    enrichment_data["asn"] = normalize_list(asns, lowercase=False)

        registrar_data = safe_lookup(cached_lookup_registrar, domain)

        if registrar_data:
            enrichment_data["registrar"] = registrar_data.get("registrar")

    return enrichment_data


# ------------------------------------------------
# Enrich a single indicator (serial entry point -- kept for callers that
# already hold a Session, e.g. one-off/manual use)
# ------------------------------------------------


def enrich_indicator(db: Session, indicator: Indicator):

    existing = (
        db.query(IndicatorEnrichment)
        .filter(IndicatorEnrichment.indicator_id == indicator.id)
        .first()
    )

    if existing:
        db.add(existing)  # re-attach to session for potential timeline event
        db.commit()  # ensure any pending timeline events are saved
        return existing

    enrichment_data = build_enrichment_data(indicator.type, indicator.value)

    try:

        enrichment = IndicatorEnrichment(
            indicator_id=indicator.id,
            asn=enrichment_data["asn"],
            registrar=enrichment_data["registrar"],
            hosting_provider=enrichment_data["hosting_provider"],
            nameservers=enrichment_data["nameservers"],
            resolved_ips=enrichment_data["resolved_ips"],
        )

        db.add(enrichment)
        db.commit()

    except Exception as e:
        logger.error(f"DB insert failed for {indicator.value}: {e}")
        db.rollback()
        return

    # ------------------------------------------------
    # Timeline event (non-blocking)
    # ------------------------------------------------

    try:

        timeline = TimelineService()

        timeline.record_event(
            db,
            event_type="infrastructure_enriched",
            event_value=indicator.value,
            source="enrichment_worker",
        )

    except Exception as e:

        logger.debug(f"Timeline event skipped: {e}")

    return enrichment


# ------------------------------------------------
# Thread-pool task: lookups (shared cache) + its own DB session
# ------------------------------------------------


def _enrich_one(indicator_id: int, indicator_type: str, indicator_value: str) -> None:

    enrichment_data = build_enrichment_data(indicator_type, indicator_value)

    db = SessionLocal()

    try:

        enrichment = IndicatorEnrichment(
            indicator_id=indicator_id,
            asn=enrichment_data["asn"],
            registrar=enrichment_data["registrar"],
            hosting_provider=enrichment_data["hosting_provider"],
            nameservers=enrichment_data["nameservers"],
            resolved_ips=enrichment_data["resolved_ips"],
        )

        db.add(enrichment)
        db.commit()

        try:
            timeline = TimelineService()
            timeline.record_event(
                db,
                event_type="infrastructure_enriched",
                event_value=indicator_value,
                source="enrichment_worker",
            )
        except Exception as e:
            logger.debug(f"Timeline event skipped: {e}")

    except Exception as e:
        logger.error(f"Enrichment failed for indicator {indicator_id} ({indicator_value}): {e}")
        db.rollback()

    finally:
        db.close()


# ------------------------------------------------
# Post-enrichment coverage sanity check
# ------------------------------------------------

# (dependent field, prerequisite field, why the dependency exists). ASN is
# only looked up for domain/url-type indicators once DNS resolves at
# least one IP (build_enrichment_data) -- a working local ASN source
# should cover the large majority of those, since only genuinely
# private/reserved/unallocated ranges have no ASN entry. This is exactly
# the relationship whose violation (14.8%, CONTEXT.md item 2.7) would
# have caught the ip-api.com rate-limit collapse automatically, without
# needing a human to notice the discrepancy across separately-reported
# per-field percentages.
COVERAGE_DEPENDENCIES = [
    ("asn", "resolved_ips", "ASN lookups only run for indicators with a resolved IP"),
]


def check_enrichment_coverage_sanity(db: Session, warn_threshold: float = 0.5) -> list[str]:
    """
    Compare each dependent field's coverage against its prerequisite
    field's, among indicators where the prerequisite succeeded. Warn if
    it's implausibly low -- a large gap is the signature of a systemic
    lookup failure (rate limiting, a broken source, a misconfigured
    path), not sparse data.

    Returns the warning messages raised (also logged at WARNING).
    """

    warnings = []

    for dependent_field, prerequisite_field, reason in COVERAGE_DEPENDENCIES:

        prereq_count = (
            db.query(IndicatorEnrichment)
            .filter(getattr(IndicatorEnrichment, prerequisite_field).isnot(None))
            .count()
        )

        if prereq_count == 0:
            continue

        both_count = (
            db.query(IndicatorEnrichment)
            .filter(
                getattr(IndicatorEnrichment, prerequisite_field).isnot(None),
                getattr(IndicatorEnrichment, dependent_field).isnot(None),
            )
            .count()
        )

        ratio = both_count / prereq_count

        if ratio < warn_threshold:
            message = (
                f"Coverage sanity check: '{dependent_field}' is present for only "
                f"{ratio:.1%} of indicators with '{prerequisite_field}' set "
                f"({both_count}/{prereq_count}), below the {warn_threshold:.0%} "
                f"threshold. {reason}. A large gap here is the signature of a "
                f"systemic lookup failure (see CONTEXT.md item 2.7), not sparse "
                f"data -- investigate before trusting this field."
            )
            logger.warning(message)
            warnings.append(message)

    if not warnings:
        logger.info("Coverage sanity check: no implausible field-dependency gaps detected.")

    return warnings


# ------------------------------------------------
# Batch enrichment
# ------------------------------------------------


def run_enrichment_batch():
    """
    Enrich every indicator that doesn't have enrichment yet, in parallel.
    CONTEXT.md item 2.6: serial enrichment was ~1-3s/indicator (10-25 hours
    at 30k indicators); target is under an hour. Filtered to unenriched
    indicators up front (a single query) so already-enriched indicators
    from a prior run/cycle aren't resubmitted to the pool.
    """

    db = SessionLocal()

    try:
        pending = (
            db.query(Indicator.id, Indicator.type, Indicator.value)
            .outerjoin(IndicatorEnrichment, IndicatorEnrichment.indicator_id == Indicator.id)
            .filter(IndicatorEnrichment.id.is_(None))
            .all()
        )
    finally:
        db.close()

    if not pending:
        return

    logger.info(f"Enriching {len(pending)} indicators with {settings.enrichment_worker_threads} threads")

    with ThreadPoolExecutor(max_workers=settings.enrichment_worker_threads) as executor:

        futures = [
            executor.submit(_enrich_one, ind_id, ind_type, ind_value)
            for ind_id, ind_type, ind_value in pending
        ]

        for future in as_completed(futures):
            future.result()  # _enrich_one catches its own errors; surface anything that escapes that anyway

    db = SessionLocal()
    try:
        check_enrichment_coverage_sanity(db)
    finally:
        db.close()


# ------------------------------------------------
# Worker loop
# ------------------------------------------------


def run_worker():

    logger.info("Enrichment worker started")

    while True:

        run_enrichment_batch()

        time.sleep(300)


if __name__ == "__main__":
    run_worker()
