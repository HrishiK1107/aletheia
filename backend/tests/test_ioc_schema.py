from app.schemas.ioc import IOCCreate


def test_ioc_schema_validation():
    ioc = IOCCreate(
        value="8.8.8.8",
        type="ip",
        confidence=80,
        source="test_feed",
    )

    assert ioc.value == "8.8.8.8"
    assert ioc.type == "ip"
    assert ioc.confidence == 80
