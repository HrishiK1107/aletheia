from app.ingestion.collectors.otx_collector import OTXCollector


def _pulse(pulse_id, name, indicators):
    return {"id": pulse_id, "name": name, "indicators": indicators}


def test_otx_parse_attaches_pulse_labels():

    collector = OTXCollector()

    sample_data = [
        _pulse(
            "pulse-1",
            "Operation Foo",
            [
                {"indicator": "malicious-domain.org", "type": "domain"},
                {"indicator": "1.2.3.4", "type": "IPv4"},
            ],
        ),
        _pulse(
            "pulse-2",
            "Operation Bar",
            [
                {"indicator": "abcd1234", "type": "FileHash-MD5"},
            ],
        ),
    ]

    indicators = collector.parse(sample_data)

    assert len(indicators) == 3

    assert indicators[0]["value"] == "malicious-domain.org"
    assert indicators[0]["type"] == "domain"
    assert indicators[0]["source"] == "otx"
    assert indicators[0]["labels"] == {"pulse_id": "pulse-1", "pulse_name": "Operation Foo"}

    assert indicators[1]["value"] == "1.2.3.4"
    assert indicators[1]["type"] == "ip"
    assert indicators[1]["labels"] == {"pulse_id": "pulse-1", "pulse_name": "Operation Foo"}

    assert indicators[2]["value"] == "abcd1234"
    assert indicators[2]["type"] == "hash"
    assert indicators[2]["labels"] == {"pulse_id": "pulse-2", "pulse_name": "Operation Bar"}


def test_otx_parse_skips_indicators_without_a_value():

    collector = OTXCollector()

    sample_data = [_pulse("pulse-1", "Operation Foo", [{"indicator": "", "type": "domain"}])]

    assert collector.parse(sample_data) == []


def test_otx_parse_passes_through_unrecognized_types(caplog):

    collector = OTXCollector()

    sample_data = [_pulse("pulse-1", "Operation Foo", [{"indicator": "1.1.1.1/24", "type": "CIDR"}])]

    with caplog.at_level("WARNING"):
        indicators = collector.parse(sample_data)

    assert indicators[0]["type"] == "CIDR"
    assert any("CIDR" in record.message for record in caplog.records)


def test_otx_fetch_pages_until_next_is_null(monkeypatch):

    collector = OTXCollector()

    responses = [
        {"results": [_pulse("p1", "A", [])], "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=2"},
        {"results": [_pulse("p2", "B", [])], "next": None},
    ]

    calls = []

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self._payload

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append((url, params))
        return FakeResponse(responses[len(calls) - 1])

    monkeypatch.setattr("app.ingestion.collectors.otx_collector.requests.get", fake_get)

    pulses = collector.fetch()

    assert [p["id"] for p in pulses] == ["p1", "p2"]
    assert len(calls) == 2
    # second call must hit the server-provided "next" URL, not rebuild params
    assert calls[1][0] == "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=2"
    assert calls[1][1] is None


def test_otx_fetch_stops_at_max_pages(monkeypatch):

    from app.core.config import settings

    monkeypatch.setattr(settings, "otx_max_pages", 2)

    collector = OTXCollector()

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "results": [_pulse("p", "P", [])],
                "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=99",
            }

    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append(url)
        return FakeResponse()

    monkeypatch.setattr("app.ingestion.collectors.otx_collector.requests.get", fake_get)

    pulses = collector.fetch()

    assert len(calls) == 2
    assert len(pulses) == 2
