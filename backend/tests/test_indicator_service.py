from app.schemas.indicator_schema import IndicatorCreate


def test_indicator_schema_usage():
    indicator = IndicatorCreate(
        value="8.8.8.8",
        type="ip",
        confidence=80,
        source="unit_test",
    )

    assert indicator.value == "8.8.8.8"
    assert indicator.type == "ip"
