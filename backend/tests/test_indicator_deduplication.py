from app.schemas.indicator_schema import IndicatorCreate
from app.services.indicator_service import create_indicator


def test_indicator_deduplication(db_session):

    indicator = IndicatorCreate(
        value="8.8.8.8",
        type="ip",
        confidence=90,
        source="test_feed",
    )

    first = create_indicator(db_session, indicator)
    second = create_indicator(db_session, indicator)

    assert first.id == second.id
