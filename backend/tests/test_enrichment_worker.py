from unittest.mock import MagicMock, patch

import pytest
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment
from app.workers.enrichment_worker import (
    build_enrichment_data,
    cached_lookup_asn,
    cached_lookup_dns,
    cached_lookup_registrar,
    enrich_indicator,
    run_enrichment_batch,
)


@pytest.fixture(autouse=True)
def clear_lookup_caches():
    """
    cached_lookup_* are module-level lru_caches that persist across every
    test in the session -- clear them before and after each test so one
    test's mocked return value (or a stale patched-function reference
    baked into the cache) can't leak into another's assertions.
    """
    cached_lookup_dns.cache_clear()
    cached_lookup_registrar.cache_clear()
    cached_lookup_asn.cache_clear()
    yield
    cached_lookup_dns.cache_clear()
    cached_lookup_registrar.cache_clear()
    cached_lookup_asn.cache_clear()


def test_enrichment_worker_runs():

    db = MagicMock()

    indicator = Indicator(
        id=1,
        value="1.1.1.1",
        type="ip",
    )

    with patch("app.workers.enrichment_worker.cached_lookup_asn") as mock_asn:

        mock_asn.return_value = {"asn": "AS13335", "hosting_provider": "Cloudflare"}

        enrich_indicator(db, indicator)

        assert db.add.called


def test_build_enrichment_data_for_ip():

    with patch("app.workers.enrichment_worker.cached_lookup_asn") as mock_asn:

        mock_asn.return_value = {"asn": "AS13335", "hosting_provider": "Cloudflare"}

        data = build_enrichment_data("ip", "1.1.1.1")

        assert data["asn"] == "AS13335"
        assert data["hosting_provider"] == "Cloudflare"


def test_build_enrichment_data_prefers_hardcoded_hosting_map_over_asn():

    with (
        patch("app.workers.enrichment_worker.cached_lookup_dns") as mock_dns,
        patch("app.workers.enrichment_worker.cached_lookup_registrar") as mock_reg,
        patch("app.workers.enrichment_worker.cached_lookup_asn") as mock_asn,
    ):
        mock_dns.return_value = {"nameservers": [], "ips": ["1.2.3.4"]}
        mock_reg.return_value = None
        mock_asn.return_value = {"asn": "AS999", "hosting_provider": "Some ISP"}

        data = build_enrichment_data("domain", "foo.vercel.app")

        # the suffix-map hit ("Vercel") wins even though the ASN lookup
        # also returned a hosting_provider value -- see CONTEXT.md's
        # ASN/HostingProvider merge decision for why these two paths exist
        assert data["hosting_provider"] == "Vercel"
        assert data["asn"] == "AS999"


def test_build_enrichment_data_iterates_all_resolved_ips_for_asn():
    """
    CONTEXT.md item 2.3: a domain load-balanced across multiple IPs in
    different ASNs must record all of them, not just ips[0].
    """

    with (
        patch("app.workers.enrichment_worker.cached_lookup_dns") as mock_dns,
        patch("app.workers.enrichment_worker.cached_lookup_registrar") as mock_reg,
        patch("app.workers.enrichment_worker.cached_lookup_asn") as mock_asn,
    ):
        mock_dns.return_value = {"nameservers": [], "ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]}
        mock_reg.return_value = None

        def fake_asn(ip):
            return {
                "1.1.1.1": {"asn": "AS111", "hosting_provider": "First ISP"},
                "2.2.2.2": {"asn": "AS222", "hosting_provider": "Second ISP"},
                "3.3.3.3": {"asn": "AS111", "hosting_provider": "First ISP"},  # duplicate ASN
            }[ip]

        mock_asn.side_effect = fake_asn

        data = build_enrichment_data("domain", "load-balanced.example.com")

        # all distinct ASNs across all IPs, deduped, order preserved, not lowercased
        assert data["asn"] == "AS111,AS222"
        # hosting_provider still takes the first-found value (unchanged
        # single-value semantics -- only the ASN fix was requested)
        assert data["hosting_provider"] == "First ISP"


def test_build_enrichment_data_asn_lookup_failing_for_one_ip_does_not_block_others():

    with (
        patch("app.workers.enrichment_worker.cached_lookup_dns") as mock_dns,
        patch("app.workers.enrichment_worker.cached_lookup_registrar") as mock_reg,
        patch("app.workers.enrichment_worker.cached_lookup_asn") as mock_asn,
    ):
        mock_dns.return_value = {"nameservers": [], "ips": ["1.1.1.1", "2.2.2.2"]}
        mock_reg.return_value = None

        def fake_asn(ip):
            return None if ip == "1.1.1.1" else {"asn": "AS222", "hosting_provider": "Second ISP"}

        mock_asn.side_effect = fake_asn

        data = build_enrichment_data("domain", "partial-failure.example.com")

        assert data["asn"] == "AS222"


def test_domain_lookup_is_cached_across_repeated_calls(monkeypatch):
    """
    CONTEXT.md item 2.6's "local DNS cache": the same domain must trigger
    only one real DNS lookup, however many indicators reference it.
    """

    call_count = {"n": 0}

    def fake_lookup_dns(domain):
        call_count["n"] += 1
        return {"nameservers": ["ns1.example.com"], "ips": ["1.2.3.4"]}

    monkeypatch.setattr("app.workers.enrichment_worker.lookup_dns", fake_lookup_dns)
    monkeypatch.setattr("app.workers.enrichment_worker.cached_lookup_asn", lambda ip: None)
    monkeypatch.setattr("app.workers.enrichment_worker.cached_lookup_registrar", lambda d: None)

    build_enrichment_data("url", "https://shared-domain.example.com/a")
    build_enrichment_data("url", "https://shared-domain.example.com/b")
    build_enrichment_data("domain", "shared-domain.example.com")

    assert call_count["n"] == 1


def test_run_enrichment_batch_enriches_pending_and_skips_existing(db_session, monkeypatch):

    from sqlalchemy.orm import sessionmaker

    # run_enrichment_batch()/_enrich_one open their own SessionLocal() per
    # call (each worker thread needs its own session) -- point that at the
    # test database instead of the dev one, same pattern as
    # test_collector_runner.py, but as a factory bound to db_session's own
    # engine (not a fixed session object), since threads must not share
    # one Session concurrently.
    test_session_factory = sessionmaker(bind=db_session.get_bind())
    monkeypatch.setattr("app.workers.enrichment_worker.SessionLocal", test_session_factory)
    monkeypatch.setattr("app.workers.enrichment_worker.cached_lookup_dns", lambda d: None)
    monkeypatch.setattr("app.workers.enrichment_worker.cached_lookup_registrar", lambda d: None)
    monkeypatch.setattr("app.workers.enrichment_worker.cached_lookup_asn", lambda ip: None)

    pending_indicator = Indicator(value="pending.example.com", type="domain", source="test", confidence=50)
    already_enriched_indicator = Indicator(
        value="already-enriched.example.com", type="domain", source="test", confidence=50
    )
    db_session.add_all([pending_indicator, already_enriched_indicator])
    db_session.commit()

    pre_existing = IndicatorEnrichment(indicator_id=already_enriched_indicator.id)
    db_session.add(pre_existing)
    db_session.commit()

    run_enrichment_batch()

    # scoped to this test's own two indicators -- the test DB has no
    # per-test rollback, so other tests' committed rows persist alongside
    # these for the rest of the session
    own_enrichments = (
        db_session.query(IndicatorEnrichment)
        .filter(IndicatorEnrichment.indicator_id.in_([pending_indicator.id, already_enriched_indicator.id]))
        .all()
    )
    enriched_ids = {e.indicator_id for e in own_enrichments}

    assert pending_indicator.id in enriched_ids
    # already_enriched_indicator must still have exactly its one
    # pre-existing row -- run_enrichment_batch() must not have resubmitted it
    assert len(own_enrichments) == 2


def test_run_enrichment_batch_does_nothing_when_all_enriched(db_session, monkeypatch):

    from sqlalchemy.orm import sessionmaker

    test_session_factory = sessionmaker(bind=db_session.get_bind())
    monkeypatch.setattr("app.workers.enrichment_worker.SessionLocal", test_session_factory)

    indicator = Indicator(value="fully-done.example.com", type="domain", source="test", confidence=50)
    db_session.add(indicator)
    db_session.commit()

    db_session.add(IndicatorEnrichment(indicator_id=indicator.id))
    db_session.commit()

    before = db_session.query(IndicatorEnrichment).count()

    run_enrichment_batch()

    after = db_session.query(IndicatorEnrichment).count()

    assert after == before
