from app.ingestion.collectors.otx_collector import OTXCollector


def test_otx_parse():

    collector = OTXCollector()

    sample_data = """
example.com
malicious-domain.org
test.badsite.net
"""

    indicators = collector.parse(sample_data)

    assert len(indicators) == 3

    assert indicators[0]["value"] == "example.com"
    assert indicators[0]["type"] == "domain"
    assert indicators[0]["source"] == "otx"
