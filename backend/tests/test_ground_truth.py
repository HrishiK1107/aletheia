from app.evaluation.ground_truth import build_threatfox_labels
from app.ingestion.enrichment.models.raw_indicator_model import RawIndicator
from app.schemas.indicator_schema import IndicatorCreate
from app.services.indicator_service import create_indicator


def _seed_labelled_indicator(db_session, value: str, indicator_type: str, family: str):
    db_session.add(
        RawIndicator(
            value=value,
            type=indicator_type,
            source="threatfox",
            confidence=75,
            raw_payload={"labels": {"malware": family}},
        )
    )
    db_session.commit()

    create_indicator(
        db_session,
        IndicatorCreate(value=value, type=indicator_type, source="threatfox", confidence=75),
    )


def test_ip_port_label_survives_migration_join(db_session):
    """
    An "ip:port" ThreatFox indicator's family label must be reachable
    under the join key ground_truth.py produces, matching what
    create_indicator() actually persists to Indicator.value (port-stripped,
    type "ip") -- not the raw "host:port" display string. This is the
    item-2.4-follow-up migration's own case (CONTEXT.md, 2026-07-23).
    """
    _seed_labelled_indicator(
        db_session, "203.0.113.77:1224", "ip:port", "win.cobalt_strike_test"
    )

    labels = build_threatfox_labels(db_session)

    assert labels.get("203.0.113.77") == "win.cobalt_strike_test"


def test_url_trailing_slash_label_survives_join(db_session):
    """
    normalize_url() strips a trailing slash -- the single largest
    contributor to the pre-existing (not ip:port-specific) join gap found
    2026-07-23: 764/4,108 ThreatFox-labelled indicators were silently
    unjoinable before any ip:port fix ever touched the database.
    """
    _seed_labelled_indicator(
        db_session, "https://ground-truth-join-test.example/", "url", "js.clearfake_test"
    )

    labels = build_threatfox_labels(db_session)

    assert labels.get("https://ground-truth-join-test.example") == "js.clearfake_test"


def test_labelled_count_matches_successfully_created_indicators(db_session):
    """
    Every labelled RawIndicator with a successfully created Indicator must
    appear in build_threatfox_labels() -- not silently dropped by a
    raw-value-vs-canonical-value key mismatch.
    """
    samples = [
        ("203.0.113.78:4433", "ip:port", "win.cobalt_strike_test2"),
        ("https://ground-truth-join-test-2.example/", "url", "js.clearfake_test2"),
        ("ground-truth-join-test-domain.example", "domain", "win.vidar_test"),
    ]

    for value, indicator_type, family in samples:
        _seed_labelled_indicator(db_session, value, indicator_type, family)

    labels = build_threatfox_labels(db_session)

    expected_families = {family for _, _, family in samples}
    families_found = {f for f in labels.values() if f in expected_families}
    assert families_found == expected_families
