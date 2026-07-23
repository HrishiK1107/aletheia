from unittest.mock import MagicMock

from app.correlation.graph_builder import GraphBuilder
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment


def test_label_mapping():

    builder = GraphBuilder()

    assert builder._get_label("domain") == "Domain"
    assert builder._get_label("ip") == "IP"
    assert builder._get_label("url") == "URL"
    assert builder._get_label("hash") == "Hash"
    assert builder._get_label("unknown") == "Indicator"


def test_ingest_indicator_creates_graph_calls():

    builder = GraphBuilder()

    mock_session = MagicMock()
    mock_driver = MagicMock()

    mock_driver.session.return_value.__enter__.return_value = mock_session
    builder.driver = mock_driver

    indicator = Indicator(
        id=1,
        value="evil.com",
        type="domain",
        source="test",
        confidence=80,
    )

    enrichment = IndicatorEnrichment(
        indicator_id=1,
        asn="AS13335",
        registrar="Namecheap",
        hosting_provider="Cloudflare",
        nameservers="ns1.cloudflare.com",
    )

    builder.ingest_indicator(indicator, enrichment)

    assert mock_session.run.called


def test_comma_separated_asn_creates_one_relationship_per_asn():
    """
    CONTEXT.md item 2.3: a domain resolving across multiple ASNs is stored
    as a comma-separated asn string -- the graph must split it into one
    RESOLVES_TO_ASN edge per ASN, the same pattern already used for
    nameservers, not a single node with a literal comma-joined value.
    """

    builder = GraphBuilder()

    mock_session = MagicMock()
    mock_driver = MagicMock()

    mock_driver.session.return_value.__enter__.return_value = mock_session
    builder.driver = mock_driver

    enrichment = IndicatorEnrichment(
        indicator_id=1,
        asn="AS111,AS222",
        registrar=None,
        hosting_provider=None,
        nameservers=None,
    )

    builder.create_domain_infrastructure_relationship("evil.com", enrichment)

    asn_calls = [
        call for call in mock_session.run.call_args_list if call.kwargs.get("asn") is not None
    ]

    assert len(asn_calls) == 2
    assert {call.kwargs["asn"] for call in asn_calls} == {"AS111", "AS222"}


def test_ip_indicator_with_enrichment_creates_infrastructure_edges():
    """
    CONTEXT.md item 2.9: GraphBuilder previously only MERGEd a bare :IP
    node and never wired an IP-type indicator's own ASN/hosting_provider
    enrichment into the graph -- confirmed graph-wide (0 RESOLVES_TO_ASN/
    HOSTED_BY edges on any of 8,120 :IP nodes) before this fix. An IP-type
    indicator with enrichment must produce both edge types, matching the
    domain/url branches' semantics.
    """

    builder = GraphBuilder()

    mock_session = MagicMock()
    mock_driver = MagicMock()

    mock_driver.session.return_value.__enter__.return_value = mock_session
    builder.driver = mock_driver

    indicator = Indicator(
        id=1,
        value="1.2.3.4",
        type="ip",
        source="test",
        confidence=80,
    )

    enrichment = IndicatorEnrichment(
        indicator_id=1,
        asn="AS13335",
        hosting_provider="Cloudflare, Inc.",
    )

    builder.ingest_indicator(indicator, enrichment)

    asn_calls = [
        call for call in mock_session.run.call_args_list if call.kwargs.get("asn") is not None
    ]
    hosting_calls = [
        call
        for call in mock_session.run.call_args_list
        if call.kwargs.get("hosting_provider") is not None
    ]

    assert len(asn_calls) == 1
    assert asn_calls[0].kwargs["asn"] == "AS13335"
    assert asn_calls[0].kwargs["ip"] == "1.2.3.4"
    assert len(hosting_calls) == 1
    assert hosting_calls[0].kwargs["hosting_provider"] == "Cloudflare, Inc."


def test_ip_comma_separated_asn_creates_one_relationship_per_asn():
    """Same multi-ASN pattern as the domain path (item 2.3), for IP-type indicators."""

    builder = GraphBuilder()

    mock_session = MagicMock()
    mock_driver = MagicMock()

    mock_driver.session.return_value.__enter__.return_value = mock_session
    builder.driver = mock_driver

    enrichment = IndicatorEnrichment(
        indicator_id=1,
        asn="AS111,AS222",
        hosting_provider=None,
    )

    builder.create_ip_infrastructure_relationship("1.2.3.4", enrichment)

    asn_calls = [
        call for call in mock_session.run.call_args_list if call.kwargs.get("asn") is not None
    ]

    assert len(asn_calls) == 2
    assert {call.kwargs["asn"] for call in asn_calls} == {"AS111", "AS222"}


def test_ip_indicator_without_enrichment_still_creates_bare_node():
    """No enrichment (or empty asn/hosting) must not prevent the bare :IP MERGE."""

    builder = GraphBuilder()

    mock_session = MagicMock()
    mock_driver = MagicMock()

    mock_driver.session.return_value.__enter__.return_value = mock_session
    builder.driver = mock_driver

    indicator = Indicator(id=1, value="5.6.7.8", type="ip", source="test", confidence=80)

    builder.ingest_indicator(indicator, None)

    assert mock_session.run.called
    merge_calls = [
        call
        for call in mock_session.run.call_args_list
        if call.kwargs.get("ip") == "5.6.7.8" and "asn" not in call.kwargs
    ]
    assert len(merge_calls) == 1
