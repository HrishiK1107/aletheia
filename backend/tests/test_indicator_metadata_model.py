from app.ingestion.enrichment.models.indicator_metadata_model import IndicatorMetadata


def test_metadata_model():

    meta = IndicatorMetadata(
        indicator_id=1,
        source="otx",
        confidence=70,
    )

    assert meta.indicator_id == 1
    assert meta.source == "otx"
