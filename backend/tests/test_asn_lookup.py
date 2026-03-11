from unittest.mock import MagicMock, patch

from app.ingestion.enrichment.asn_lookup import lookup_asn


def test_asn_lookup_success():

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "success",
        "as": "AS13335 Cloudflare, Inc.",
        "isp": "Cloudflare",
    }

    with patch("requests.get", return_value=mock_response):

        result = lookup_asn("1.1.1.1")

        assert result["asn"] == "AS13335"
        assert result["hosting_provider"] == "Cloudflare"


def test_asn_lookup_failure():

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "fail"}

    with patch("requests.get", return_value=mock_response):

        result = lookup_asn("0.0.0.0")

        assert result is None
