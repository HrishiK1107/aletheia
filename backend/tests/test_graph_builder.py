from unittest.mock import MagicMock

from app.correlation.graph_builder import GraphBuilder
from app.ingestion.enrichment.models.indicator_models import Indicator


def test_label_mapping():
    builder = GraphBuilder()

    assert builder._get_label("domain") == "Domain"
    assert builder._get_label("ip") == "IP"
    assert builder._get_label("url") == "URL"
    assert builder._get_label("hash") == "Hash"
    assert builder._get_label("unknown") == "Indicator"


def test_ingest_indicator_calls_neo4j(monkeypatch):
    builder = GraphBuilder()

    mock_session = MagicMock()
    mock_driver = MagicMock()

    mock_driver.session.return_value.__enter__.return_value = mock_session

    builder.driver = mock_driver

    indicator = Indicator(
        id=1,
        value="example.com",
        type="domain",
        source="test",
        confidence=80,
    )

    builder.ingest_indicator(indicator)

    assert mock_session.run.called
