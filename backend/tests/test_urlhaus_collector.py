from app.ingestion.collectors.urlhaus_collector import URLhausCollector


def test_urlhaus_parse():

    collector = URLhausCollector()

    sample_data = {
        "query_status": "ok",
        "urls": [
            {
                "url": "http://113.237.108.171:45619/bin.sh",
                "threat": "malware_download",
                "tags": ["32-bit", "elf", "mips", "Mozi"],
                "reporter": "some_reporter",
                "date_added": "2026-07-22 19:23:19 UTC",
            },
            {
                "url": "http://phish.example.com/login",
                "threat": "malware_download",
                "tags": None,
                "reporter": "another_reporter",
                "date_added": "2026-07-22 20:00:00 UTC",
            },
        ],
    }

    indicators = collector.parse(sample_data)

    assert len(indicators) == 2

    assert indicators[0]["value"] == "http://113.237.108.171:45619/bin.sh"
    assert indicators[0]["type"] == "url"
    assert indicators[0]["source"] == "urlhaus"
    assert indicators[0]["labels"] == {
        "threat_type": "malware_download",
        "tags": ["32-bit", "elf", "mips", "Mozi"],
        "reporter": "some_reporter",
        "date_added": "2026-07-22 19:23:19 UTC",
    }

    assert indicators[1]["labels"]["tags"] is None


def test_urlhaus_parse_skips_entries_without_a_url():

    collector = URLhausCollector()

    sample_data = {"query_status": "ok", "urls": [{"threat": "malware_download"}]}

    assert collector.parse(sample_data) == []


def test_urlhaus_parse_logs_and_returns_empty_on_query_error(caplog):

    collector = URLhausCollector()

    sample_data = {"query_status": "no_results"}

    with caplog.at_level("WARNING"):
        indicators = collector.parse(sample_data)

    assert indicators == []
    assert any("no_results" in record.message for record in caplog.records)


def test_urlhaus_fetch_sends_auth_key_header(monkeypatch):

    from app.core.config import settings

    monkeypatch.setattr(settings, "abusech_api_key", "test-key-123")

    collector = URLhausCollector()

    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"query_status": "ok", "urls": []}

    def fake_get(url, headers=None, timeout=None):
        captured["headers"] = headers
        return FakeResponse()

    monkeypatch.setattr("app.ingestion.collectors.urlhaus_collector.requests.get", fake_get)

    collector.fetch()

    assert captured["headers"]["Auth-Key"] == "test-key-123"
