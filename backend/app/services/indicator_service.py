from app.models.indicator_models import Indicator
from app.schemas.indicator_schema import IndicatorCreate
from app.services.normalization_service import normalize_indicator
from sqlalchemy.orm import Session


def create_indicator(db: Session, indicator: IndicatorCreate) -> Indicator:
    normalized_value = normalize_indicator(
        indicator.value,
        indicator.type,
    )

    db_indicator = Indicator(
        value=normalized_value,
        type=indicator.type,
        source=indicator.source,
        confidence=indicator.confidence,
    )

    db.add(db_indicator)
    db.commit()
    db.refresh(db_indicator)

    return db_indicator


def get_indicator(db: Session, indicator_id: int) -> Indicator | None:
    return db.query(Indicator).filter(Indicator.id == indicator_id).first()


def list_indicators(db: Session):
    return db.query(Indicator).all()
