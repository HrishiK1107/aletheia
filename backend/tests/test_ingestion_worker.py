from app.ingestion.enrichment.models.raw_indicator_model import RawIndicator
from app.workers.ingestion_worker import process_indicator


def _raw(value, source, ind_type="url"):
    return {
        "value": value,
        "type": ind_type,
        "source": source,
        "confidence": 80,
    }


def test_process_indicator_dedupes_same_value_and_source(db_session):
    """
    CONTEXT.md item 1.4: the same feed re-reporting the same value across
    runs must not accumulate a new raw_indicators row each time.
    """

    process_indicator(db_session, _raw("http://dupe-test.example.com", "openphish"))
    process_indicator(db_session, _raw("http://dupe-test.example.com", "openphish"))

    rows = (
        db_session.query(RawIndicator)
        .filter(
            RawIndicator.value == "http://dupe-test.example.com",
            RawIndicator.source == "openphish",
        )
        .all()
    )

    assert len(rows) == 1


def test_process_indicator_keeps_same_value_different_source(db_session):
    """
    Deduplication is scoped to (value, source), not value alone: the same
    value reported by a DIFFERENT feed is cross-feed corroboration, not a
    duplicate, and must still get its own row.
    """

    process_indicator(db_session, _raw("http://cross-feed-test.example.com", "openphish"))
    process_indicator(db_session, _raw("http://cross-feed-test.example.com", "urlhaus"))

    rows = (
        db_session.query(RawIndicator)
        .filter(RawIndicator.value == "http://cross-feed-test.example.com")
        .all()
    )

    assert len(rows) == 2
    assert {r.source for r in rows} == {"openphish", "urlhaus"}


def test_process_indicator_third_repeat_still_deduped(db_session):

    for _ in range(3):
        process_indicator(db_session, _raw("http://dupe-test-2.example.com", "threatfox"))

    rows = (
        db_session.query(RawIndicator)
        .filter(
            RawIndicator.value == "http://dupe-test-2.example.com",
            RawIndicator.source == "threatfox",
        )
        .all()
    )

    assert len(rows) == 1
