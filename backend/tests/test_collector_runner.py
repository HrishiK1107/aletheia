from app.ingestion.collectors.collector_runner import run_collectors


class DummyCollector:
    name = "dummy"

    def collect(self):
        return [
            {
                "value": "1.1.1.1",
                "type": "ip",
                "source": "dummy",
                "confidence": 50,
            }
        ]


def test_run_collectors(monkeypatch):

    dummy_collector = DummyCollector()

    # mock registry
    class DummyRegistry:
        def get_collectors(self):
            return [dummy_collector]

    monkeypatch.setattr(
        "app.ingestion.collectors.collector_runner.registry",
        DummyRegistry(),
    )

    # capture queue push
    pushed = []

    def fake_enqueue(indicators):
        pushed.extend(indicators)

    monkeypatch.setattr(
        "app.ingestion.collectors.collector_runner.enqueue_indicators",
        fake_enqueue,
    )

    results = run_collectors()

    assert len(results) == 1
    assert results[0]["value"] == "1.1.1.1"

    assert len(pushed) == 1
    assert pushed[0]["type"] == "ip"
