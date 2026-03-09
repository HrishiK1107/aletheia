from app.ingestion.enrichment.models.indicator_models import Indicator
from sqlalchemy.orm import Session


def find_duplicate(db: Session, value: str, indicator_type: str) -> Indicator | None:
    """
    Check if an indicator already exists.
    """

    return (
        db.query(Indicator)
        .filter(
            Indicator.value == value,
            Indicator.type == indicator_type,
        )
        .first()
    )
