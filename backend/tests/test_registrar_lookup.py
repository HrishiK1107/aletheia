from unittest.mock import MagicMock, patch

from app.ingestion.enrichment.registrar_lookup import lookup_registrar


def test_registrar_lookup_success():

    mock_whois = MagicMock()
    mock_whois.registrar = "Namecheap"

    with patch("whois.whois", return_value=mock_whois):

        result = lookup_registrar("example.com")

        assert result["registrar"] == "Namecheap"


def test_registrar_lookup_failure():

    with patch("whois.whois", side_effect=Exception):

        result = lookup_registrar("example.com")

        assert result is None
