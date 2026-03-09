from app.ingestion.deduplication.dedupe_engine import find_duplicate
from app.ingestion.enrichment.models.indicator_models import Indicator


def test_find_duplicate(db_session):

    indicator = Indicator(
        value="1.2.3.4",
        type="ip",
        source="test",
        confidence=80,
    )

    db_session.add(indicator)
    db_session.commit()

    duplicate = find_duplicate(db_session, "1.2.3.4", "ip")

    assert duplicate is not None
    assert duplicate.value == "1.2.3.4"
