from app.ingestion.deduplication.dedupe_engine import find_duplicate
from app.ingestion.enrichment.models.indicator_metadata_model import IndicatorMetadata
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.rejected_indicator_model import RejectedIndicator
from app.ingestion.validation.validator import validate_indicator
from app.schemas.indicator_schema import IndicatorCreate
from app.services.normalization_service import canonicalize_indicator_type, normalize_indicator
from sqlalchemy.orm import Session


def create_indicator(db: Session, indicator: IndicatorCreate) -> Indicator | None:
    """
    Create indicator with validation, normalization and deduplication.
    """

    # Phase 0 -- canonicalize source-reported pseudo-types (e.g. ThreatFox's
    # "ip:port") into a real type before validation ever sees them, so
    # validate_indicator/normalize_indicator/enrichment all operate on the
    # corrected (value, type) rather than an unrecognized passthrough.
    canonical_value, canonical_type = canonicalize_indicator_type(indicator.value, indicator.type)
    indicator = indicator.model_copy(update={"value": canonical_value, "type": canonical_type})

    # Phase 3 — validation
    valid, reason = validate_indicator(indicator.value, indicator.type)

    if not valid:
        rejected = RejectedIndicator(
            value=indicator.value,
            type=indicator.type,
            source=indicator.source,
            reason=reason,
        )

        db.add(rejected)
        db.commit()

        return None

    # Phase 2 existing logic
    normalized_value = normalize_indicator(indicator.value, indicator.type)

    existing = find_duplicate(db, normalized_value, indicator.type)

    # Duplicate indicator → add metadata only
    if existing:

        metadata = IndicatorMetadata(
            indicator_id=existing.id,
            source=indicator.source,
            confidence=indicator.confidence,
        )

        db.add(metadata)
        db.commit()

        return existing

    # New indicator
    db_indicator = Indicator(
        value=normalized_value,
        type=indicator.type,
        source=indicator.source,
        confidence=indicator.confidence,
    )

    db.add(db_indicator)
    db.commit()
    db.refresh(db_indicator)

    # Add metadata entry
    metadata = IndicatorMetadata(
        indicator_id=db_indicator.id,
        source=indicator.source,
        confidence=indicator.confidence,
    )

    db.add(metadata)
    db.commit()

    return db_indicator


def get_indicator(db: Session, indicator_id: int) -> Indicator | None:
    return db.query(Indicator).filter(Indicator.id == indicator_id).first()


def list_indicators(db: Session):
    return db.query(Indicator).all()
