from app.models.ioc import IOC


def test_ioc_model_fields():
    ioc = IOC(value="1.1.1.1", type="ip", confidence=80)

    assert ioc.value == "1.1.1.1"
    assert ioc.type == "ip"
    assert ioc.confidence == 80
