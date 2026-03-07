from app.services.normalization_service import normalize_indicator


def test_domain_normalization():
    result = normalize_indicator("https://WWW.Example.com", "domain")
    assert result == "example.com"


def test_url_normalization():
    result = normalize_indicator("HTTP://example.com/test/", "url")
    assert result == "http://example.com/test"


def test_hash_normalization():
    result = normalize_indicator("ABCDEF1234567890ABCDEF1234567890ABCDEF12", "hash")

    assert result == "abcdef1234567890abcdef1234567890abcdef12"


def test_ip_normalization():
    result = normalize_indicator("8.8.8.8", "ip")
    assert result == "8.8.8.8"
