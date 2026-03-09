from app.ingestion.enrichment.models.feed_run_model import FeedRun


def test_feed_run_defaults():

    run = FeedRun(feed_source_id=1)

    assert run.feed_source_id == 1
    assert run.status == "running"
    assert run.indicators_collected == 0
