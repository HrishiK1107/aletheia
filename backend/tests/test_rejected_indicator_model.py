from app.ingestion.enrichment.models.rejected_indicator_model import RejectedIndicator


def test_rejected_indicator_model():

    r = RejectedIndicator(
        value="bad-ip",
        type="ip",
        source="test",
        reason="invalid ip",
    )

    assert r.value == "bad-ip"
    assert r.reason == "invalid ip"
