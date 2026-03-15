import logging
import time
from urllib.parse import urlparse

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


def normalize_list(values: list[str] | None) -> str | None:
    if not values:
        return None

    cleaned = []
    seen = set()

    for value in values:
        if not value:
            continue

        item = str(value).strip().lower()

        if not item or item in seen:
            continue

        seen.add(item)
        cleaned.append(item)

    if not cleaned:
        return None

    return ",".join(cleaned)


# ------------------------------------------------
# Enrich a single indicator
# ------------------------------------------------


def enrich_indicator(db: Session, indicator: Indicator):

    existing = (
        db.query(IndicatorEnrichment)
        .filter(IndicatorEnrichment.indicator_id == indicator.id)
        .first()
    )

    if existing:
        return

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

    if indicator.type == "ip":

        asn_data = safe_lookup(lookup_asn, indicator.value)

        if asn_data:
            enrichment_data["asn"] = asn_data.get("asn")
            enrichment_data["hosting_provider"] = asn_data.get("hosting_provider")

    # ------------------------------------------------
    # Domain extraction
    # ------------------------------------------------

    if indicator.type == "domain":
        domain = indicator.value.lower()

    if indicator.type == "url":
        domain = extract_domain(indicator.value)

    # ------------------------------------------------
    # Domain infrastructure enrichment
    # ------------------------------------------------

    if domain:

        hosting = detect_hosting_platform(domain)

        if hosting:
            enrichment_data["hosting_provider"] = hosting

        dns_data = safe_lookup(lookup_dns, domain)

        if dns_data:

            nameservers = dns_data.get("nameservers")
            ips = dns_data.get("ips", [])

            if nameservers:
                enrichment_data["nameservers"] = normalize_list(nameservers)

            if ips:

                enrichment_data["resolved_ips"] = normalize_list(ips)

                asn_data = safe_lookup(lookup_asn, ips[0])

                if asn_data:

                    enrichment_data["asn"] = asn_data.get("asn")

                    if not enrichment_data["hosting_provider"]:
                        enrichment_data["hosting_provider"] = asn_data.get("hosting_provider")

        registrar_data = safe_lookup(lookup_registrar, domain)

        if registrar_data:
            enrichment_data["registrar"] = registrar_data.get("registrar")

    # ------------------------------------------------
    # Store enrichment
    # ------------------------------------------------

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


# ------------------------------------------------
# Batch enrichment
# ------------------------------------------------


def run_enrichment_batch():

    db = SessionLocal()

    try:

        indicators = db.query(Indicator).all()

        for indicator in indicators:

            try:
                enrich_indicator(db, indicator)

            except Exception as e:

                logger.error(f"Enrichment failed for {indicator.value}: {e}")
                db.rollback()

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
