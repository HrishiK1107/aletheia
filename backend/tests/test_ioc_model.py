from app.schemas.indicator_schema import IndicatorCreate


def test_indicator_schema_fields():
    indicator = IndicatorCreate(
        value="1.1.1.1",
        type="ip",
        confidence=80,
    )

    assert indicator.value == "1.1.1.1"
    assert indicator.type == "ip"
    assert indicator.confidence == 80
