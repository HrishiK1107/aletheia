from app.ingestion.collectors.threatfox_collector import ThreatFoxCollector


def test_threatfox_parse():

    collector = ThreatFoxCollector()

    sample_data = {
        "data": [
            {"ioc": "1.2.3.4", "ioc_type": "ip"},
            {"ioc": "malicious.com", "ioc_type": "domain"},
        ]
    }

    indicators = collector.parse(sample_data)

    assert len(indicators) == 2

    assert indicators[0]["value"] == "1.2.3.4"
    assert indicators[0]["type"] == "ip"
    assert indicators[0]["source"] == "threatfox"
