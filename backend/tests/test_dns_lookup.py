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
