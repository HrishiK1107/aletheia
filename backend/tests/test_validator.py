from app.ingestion.validation.validator import validate_indicator


def test_valid_domain():

    valid, _ = validate_indicator("evil.com", "domain")

    assert valid


def test_invalid_domain():

    valid, _ = validate_indicator("evil..com", "domain")

    assert not valid


def test_valid_ip():

    valid, _ = validate_indicator("8.8.8.8", "ip")

    assert valid


def test_invalid_ip():

    valid, _ = validate_indicator("999.999.999.999", "ip")

    assert not valid
