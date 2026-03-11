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
