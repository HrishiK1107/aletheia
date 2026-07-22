import datetime
import importlib

import pytest
from app.ingestion.enrichment import asn_lookup
from app.ingestion.enrichment.asn_lookup import get_database_build_date, lookup_asn


def test_lookup_asn_known_ip():
    result = lookup_asn("1.1.1.1")

    assert result["asn"] == "AS13335"
    assert "Cloudflare" in result["hosting_provider"]


def test_lookup_asn_private_ip_returns_none():
    """
    Private/reserved ranges genuinely have no ASN -- this is a real
    negative result, not a lookup failure (CONTEXT.md item 2.7's whole
    point is telling those apart).
    """
    assert lookup_asn("192.168.1.1") is None


def test_lookup_asn_malformed_ip_returns_none():
    assert lookup_asn("not-an-ip") is None


def test_get_database_build_date_returns_aware_datetime():
    build_date = get_database_build_date()

    assert isinstance(build_date, datetime.datetime)
    assert build_date.tzinfo is not None


def test_module_raises_loudly_when_database_file_missing(monkeypatch):
    """
    CONTEXT.md item 2.7: no silent fallback to a network lookup -- fail at
    import time if the GeoLite2 snapshot isn't where configured.
    """

    from app.core.config import settings

    monkeypatch.setattr(settings, "geolite2_asn_db_path", "data/does-not-exist.mmdb")

    try:
        with pytest.raises(RuntimeError, match="not found"):
            importlib.reload(asn_lookup)
    finally:
        # Restore real state regardless of outcome so later tests (or a
        # later run of this same module) see a working asn_lookup, not
        # one left mid-reload with the bad path.
        monkeypatch.undo()
        importlib.reload(asn_lookup)


def test_module_works_normally_after_being_reloaded():
    """
    Follows the failure test above -- guards against that test leaving
    the module's internal state broken for whatever runs next.
    """
    assert asn_lookup.lookup_asn("1.1.1.1") is not None
