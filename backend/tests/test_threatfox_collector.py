from app.ingestion.collectors.threatfox_collector import ThreatFoxCollector


def test_threatfox_parse():

    collector = ThreatFoxCollector()

    sample_data = {
        "data": [
            {"ioc": "1.2.3.4", "ioc_type": "ip"},
            {
                "ioc": "malicious.com",
                "ioc_type": "domain",
                "malware": "elf.mirai",
                "malware_printable": "Mirai",
                "threat_type": "botnet_cc",
                "tags": ["mirai", "botnet"],
                "confidence_level": 90,
                "first_seen": "2026-01-01 00:00:00 UTC",
                "reporter": "some_reporter",
            },
        ]
    }

    indicators = collector.parse(sample_data)

    assert len(indicators) == 2

    assert indicators[0]["value"] == "1.2.3.4"
    assert indicators[0]["type"] == "ip"
    assert indicators[0]["source"] == "threatfox"

    # Labels block must exist even when the feed omits every field.
    assert indicators[0]["labels"] == {
        "malware": None,
        "malware_printable": None,
        "threat_type": None,
        "tags": None,
        "confidence_level": None,
        "first_seen": None,
        "reporter": None,
    }

    assert indicators[1]["labels"] == {
        "malware": "elf.mirai",
        "malware_printable": "Mirai",
        "threat_type": "botnet_cc",
        "tags": ["mirai", "botnet"],
        "confidence_level": 90,
        "first_seen": "2026-01-01 00:00:00 UTC",
        "reporter": "some_reporter",
    }


def test_threatfox_build_payload_uses_configured_lookback_days():

    collector = ThreatFoxCollector()

    payload = collector.build_payload()

    assert payload["query"] == "get_iocs"
    assert payload["days"] == 7


def test_threatfox_build_payload_respects_overridden_lookback(monkeypatch):

    from app.core.config import settings

    monkeypatch.setattr(settings, "threatfox_lookback_days", 3)

    collector = ThreatFoxCollector()

    assert collector.build_payload()["days"] == 3


def test_threatfox_parse_logs_unrecognized_ioc_types(caplog):

    collector = ThreatFoxCollector()

    sample_data = {
        "data": [
            {"ioc": "abcd1234", "ioc_type": "md5_hash"},
        ]
    }

    with caplog.at_level("WARNING"):
        indicators = collector.parse(sample_data)

    assert indicators[0]["type"] == "md5_hash"
    assert any("md5_hash" in record.message for record in caplog.records)
