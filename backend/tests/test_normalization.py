from app.services.normalization_service import canonicalize_indicator_type, normalize_indicator


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


def test_canonicalize_ipv4_port_strips_port():
    value, indicator_type = canonicalize_indicator_type("153.75.245.123:1224", "ip:port")
    assert value == "153.75.245.123"
    assert indicator_type == "ip"


def test_canonicalize_bracketed_ipv6_port_strips_port():
    value, indicator_type = canonicalize_indicator_type("[2001:db8::1]:8080", "ip:port")
    assert value == "2001:db8::1"
    assert indicator_type == "ip"


def test_canonicalize_bare_ipv6_no_port_left_whole():
    """
    An unbracketed IPv6 address contains multiple ':' and no port. rsplit
    on the last ':' would mangle it (e.g. "2001:db8::1" -> host
    "2001:db8:", port "1") -- must fall through to trying the whole value
    as an IP instead of splitting.
    """
    value, indicator_type = canonicalize_indicator_type("2001:db8::1", "ip:port")
    assert value == "2001:db8::1"
    assert indicator_type == "ip"


def test_canonicalize_garbage_left_unchanged():
    value, indicator_type = canonicalize_indicator_type("not-an-ip:notaport", "ip:port")
    assert value == "not-an-ip:notaport"
    assert indicator_type == "ip:port"


def test_canonicalize_invalid_ip_with_valid_port_left_unchanged():
    value, indicator_type = canonicalize_indicator_type("999.999.999.999:8080", "ip:port")
    assert value == "999.999.999.999:8080"
    assert indicator_type == "ip:port"


def test_canonicalize_ignores_other_types():
    value, indicator_type = canonicalize_indicator_type("example.com", "domain")
    assert value == "example.com"
    assert indicator_type == "domain"
