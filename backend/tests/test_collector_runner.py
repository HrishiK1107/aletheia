from app.ingestion.collectors.collector_runner import run_collectors
from app.ingestion.enrichment.models.feed_models import Feed
from app.ingestion.enrichment.models.feed_run_model import FeedRun
from app.ingestion.enrichment.models.feed_source_model import FeedSource


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


class FailingCollector:
    """
    Mimics a real BaseCollector subclass whose collect() swallowed an
    error internally: still returns [], but exposes last_error so the
    runner can tell this apart from a genuinely empty result.
    """

    name = "failing"
    last_error = "illegal_days: Invalid value for parameter days"

    def collect(self):
        return []


def _patch_registry_and_queue(monkeypatch, collectors):

    class DummyRegistry:
        def get_collectors(self):
            return collectors

    monkeypatch.setattr(
        "app.ingestion.collectors.collector_runner.registry",
        DummyRegistry(),
    )

    pushed = []

    def fake_enqueue(indicators):
        pushed.extend(indicators)

    monkeypatch.setattr(
        "app.ingestion.collectors.collector_runner.enqueue_indicators",
        fake_enqueue,
    )

    return pushed


def _patch_db_session(monkeypatch, db_session):
    monkeypatch.setattr(
        "app.ingestion.collectors.collector_runner.SessionLocal",
        lambda: db_session,
    )


def test_run_collectors(monkeypatch, db_session):

    dummy_collector = DummyCollector()

    pushed = _patch_registry_and_queue(monkeypatch, [dummy_collector])
    _patch_db_session(monkeypatch, db_session)

    results = run_collectors()

    assert len(results) == 1
    assert results[0]["value"] == "1.1.1.1"

    assert len(pushed) == 1
    assert pushed[0]["type"] == "ip"


def test_run_collectors_persists_success(monkeypatch, db_session):

    _patch_registry_and_queue(monkeypatch, [DummyCollector()])
    _patch_db_session(monkeypatch, db_session)

    run_collectors()

    source = db_session.query(FeedSource).filter(FeedSource.name == "dummy").first()
    assert source is not None

    run = db_session.query(FeedRun).filter(FeedRun.feed_source_id == source.id).first()
    assert run.status == "success"
    assert run.indicators_collected == 1
    assert run.error is None

    feed = db_session.query(Feed).filter(Feed.name == "dummy").first()
    assert feed.status == "success"
    assert feed.indicators_collected == 1


def test_run_collectors_persists_failure_reason(monkeypatch, db_session):

    _patch_registry_and_queue(monkeypatch, [FailingCollector()])
    _patch_db_session(monkeypatch, db_session)

    results = run_collectors()

    assert results == []

    source = db_session.query(FeedSource).filter(FeedSource.name == "failing").first()
    assert source is not None

    run = db_session.query(FeedRun).filter(FeedRun.feed_source_id == source.id).first()
    assert run.status == "failed"
    assert run.indicators_collected == 0
    assert run.error == "illegal_days: Invalid value for parameter days"

    feed = db_session.query(Feed).filter(Feed.name == "failing").first()
    assert feed.status == "failed"


def test_run_collectors_one_failure_does_not_block_others(monkeypatch, db_session):

    _patch_registry_and_queue(monkeypatch, [FailingCollector(), DummyCollector()])
    _patch_db_session(monkeypatch, db_session)

    results = run_collectors()

    assert len(results) == 1
    assert results[0]["source"] == "dummy"

    failing_feed = db_session.query(Feed).filter(Feed.name == "failing").first()
    dummy_feed = db_session.query(Feed).filter(Feed.name == "dummy").first()

    assert failing_feed.status == "failed"
    assert dummy_feed.status == "success"
