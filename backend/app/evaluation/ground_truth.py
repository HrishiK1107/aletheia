"""
Ground-truth label extraction for the §3 evaluation harness (CONTEXT.md item 7).

Labels were carried through ingestion into raw_indicators.raw_payload["labels"]
(item 1.2) but never previously read back out for evaluation -- this is the
first consumer.
"""

from collections import Counter

from app.ingestion.enrichment.models.raw_indicator_model import RawIndicator
from app.services.normalization_service import canonicalize_indicator_type, normalize_indicator
from sqlalchemy.orm import Session

# ThreatFox's explicit "not attributed" label, not a real family (CONTEXT.md §5) --
# clustering these together would reward grouping unrelated indicators.
EXCLUDED_THREATFOX_FAMILY = "Unknown malware"


def _canonical_key(value: str, indicator_type: str) -> str:
    """
    The join key ground-truth labels must use to match fingerprint dicts
    (keyed by Indicator.value) -- NOT the raw RawIndicator.value display
    string. create_indicator() (indicator_service.py) canonicalizes
    source-reported pseudo-types (e.g. ThreatFox's "ip:port") and
    normalizes the value (case-folding, trailing-slash stripping, scheme
    handling, ...) before the Indicator row is ever created, so
    RawIndicator.value and Indicator.value routinely differ even when they
    describe the same indicator.

    Found 2026-07-23: keying ground-truth labels on the raw value silently
    dropped 764/4,108 (18.6%) of ThreatFox-labelled indicators from every
    join against fingerprints/degrees, BEFORE the item-2.4 `ip:port`
    migration ever touched the database -- overwhelmingly URL
    trailing-slash normalization (`normalize_url()` strips it), not an
    ip:port-specific problem. That migration made the same class of gap
    worse for its own 977 rows on top of the pre-existing one. Recomputing
    the same canonical transform here (rather than adding a schema-level
    FK between RawIndicator and Indicator, which doesn't currently exist)
    keeps this a pure function of already-stored data and exactly mirrors
    what create_indicator() actually persisted -- it is not a new,
    separate notion of "canonical", it is the same one.
    """
    canonical_value, canonical_type = canonicalize_indicator_type(value, indicator_type)
    return normalize_indicator(canonical_value, canonical_type)


def build_threatfox_labels(db: Session) -> dict[str, str]:
    """indicator value (canonical, matching Indicator.value) -> malware family, ThreatFox rows only."""
    rows = db.query(RawIndicator).filter(RawIndicator.source == "threatfox").order_by(RawIndicator.id).all()

    labels: dict[str, str] = {}
    for row in rows:
        payload = row.raw_payload or {}
        family = (payload.get("labels") or {}).get("malware")

        if not family or family == EXCLUDED_THREATFOX_FAMILY:
            continue

        labels[_canonical_key(row.value, row.type)] = family

    return labels


def find_largest_otx_pulse(db: Session) -> tuple[str | None, int]:
    """
    The single largest OTX pulse by indicator count -- found dynamically
    rather than hardcoded, since which pulse is largest depends on the
    live subscription state at collection time. §5 documented one pulse
    ("The Evolution of ClickFix...") at 4,499/18,056 indicators as of the
    2026-07-23 collection; this looks it up fresh against whatever data is
    actually loaded.
    """
    rows = db.query(RawIndicator).filter(RawIndicator.source == "otx").all()

    counts: Counter = Counter()
    for row in rows:
        payload = row.raw_payload or {}
        pulse_id = (payload.get("labels") or {}).get("pulse_id")

        if pulse_id:
            counts[pulse_id] += 1

    if not counts:
        return None, 0

    pulse_id, count = counts.most_common(1)[0]
    return pulse_id, count


def build_otx_labels(db: Session, exclude_pulse_id: str | None = None) -> dict[str, str]:
    """
    indicator value -> pulse_id, OTX rows only.

    exclude_pulse_id: drop indicators belonging to this pulse -- for the
    with/without-outlier ARI comparison §5 flagged as an open decision.
    An indicator belonging to more than one pulse keeps whichever row the
    query returns last, and rows are now fetched in a fixed `ORDER BY id`
    so "last" is a stable, reproducible choice rather than whatever order
    an unordered query happened to return this time (CONTEXT.md §6k).
    Cross-pulse membership is rare enough (§5's overlap analysis) not to
    warrant a multi-label scheme here.
    """
    rows = db.query(RawIndicator).filter(RawIndicator.source == "otx").order_by(RawIndicator.id).all()

    labels: dict[str, str] = {}
    for row in rows:
        payload = row.raw_payload or {}
        pulse_id = (payload.get("labels") or {}).get("pulse_id")

        if not pulse_id or pulse_id == exclude_pulse_id:
            continue

        labels[_canonical_key(row.value, row.type)] = pulse_id

    return labels
