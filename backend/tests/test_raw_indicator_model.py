from app.ingestion.enrichment.models.raw_indicator_model import RawIndicator


def test_raw_indicator_fields():

    indicator = RawIndicator(
        value="evil.com",
        type="domain",
        source="otx",
        confidence=70,
        raw_payload={"value": "evil.com"},
    )

    assert indicator.value == "evil.com"
    assert indicator.type == "domain"
    assert indicator.source == "otx"
    assert indicator.confidence == 70
