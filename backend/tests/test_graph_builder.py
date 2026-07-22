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
