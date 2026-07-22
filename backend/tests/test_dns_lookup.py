from unittest.mock import MagicMock, patch

from app.ingestion.enrichment.dns_lookup import lookup_dns


def test_dns_lookup_success():

    mock_ns = MagicMock()
    mock_ns.target = "ns1.example.com."

    mock_a = MagicMock()
    mock_a.address = "1.2.3.4"

    with patch("dns.resolver.resolve") as mock_resolve:

        mock_resolve.side_effect = [
            [mock_ns],  # NS query
            [mock_a],  # A query
        ]

        result = lookup_dns("example.com")

        assert result["nameservers"][0] == "ns1.example.com"
        assert result["ips"][0] == "1.2.3.4"


def test_dns_lookup_failure():

    with patch("dns.resolver.resolve", side_effect=Exception):

        result = lookup_dns("invalid-domain")

        assert result is None


def test_dns_lookup_logs_ns_and_a_failures_distinctly(caplog):
    """
    Silent-failure audit (CONTEXT.md item 2.7's follow-up): NS and A
    lookups fail independently and must be logged distinctly, not
    swallowed by a bare except.
    """

    with patch("dns.resolver.resolve", side_effect=[Exception("NXDOMAIN"), Exception("Timeout")]):

        with caplog.at_level("DEBUG"):
            result = lookup_dns("failing-domain.example.com")

    assert result is None
    messages = [r.message for r in caplog.records]
    assert any("NS lookup failed" in m and "failing-domain.example.com" in m for m in messages)
    assert any("A lookup failed" in m and "failing-domain.example.com" in m for m in messages)
