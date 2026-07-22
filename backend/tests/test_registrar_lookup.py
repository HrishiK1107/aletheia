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


def test_registrar_lookup_logs_failure_reason(caplog):
    """
    Silent-failure audit (CONTEXT.md item 2.7's follow-up): the reason a
    WHOIS lookup failed must be recorded, not just swallowed.
    """

    with patch("whois.whois", side_effect=ConnectionError("timed out")):

        with caplog.at_level("DEBUG"):
            result = lookup_registrar("failing-domain.example.com")

    assert result is None
    assert any(
        "WHOIS lookup failed" in r.message and "failing-domain.example.com" in r.message
        for r in caplog.records
    )


def test_registrar_lookup_logs_when_no_registrar_field(caplog):

    mock_whois = MagicMock()
    mock_whois.registrar = None

    with patch("whois.whois", return_value=mock_whois):

        with caplog.at_level("DEBUG"):
            result = lookup_registrar("no-registrar.example.com")

    assert result is None
    assert any("no registrar field" in r.message for r in caplog.records)
