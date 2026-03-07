from app.schemas.indicator_schema import IndicatorCreate


def test_indicator_schema_validation():
    indicator = IndicatorCreate(
        value="8.8.8.8",
        type="ip",
        confidence=80,
        source="test_feed",
    )

    assert indicator.value == "8.8.8.8"
    assert indicator.type == "ip"
    assert indicator.confidence == 80
