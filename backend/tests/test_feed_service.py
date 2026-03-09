from app.ingestion.enrichment.models.feed_models import Feed
from app.services.feed_service import update_feed_status


def test_feed_created(db_session):

    update_feed_status(db_session, "openphish", 100, True)

    feed = db_session.query(Feed).filter(Feed.name == "openphish").first()

    assert feed is not None
    assert feed.name == "openphish"
    assert feed.indicators_collected == 100
    assert feed.status == "success"


def test_feed_update_existing(db_session):

    update_feed_status(db_session, "openphish", 50, True)
    update_feed_status(db_session, "openphish", 200, True)

    feed = db_session.query(Feed).filter(Feed.name == "openphish").first()

    assert feed.indicators_collected == 200


def test_feed_failure_status(db_session):

    update_feed_status(db_session, "openphish", 0, False)

    feed = db_session.query(Feed).filter(Feed.name == "openphish").first()

    assert feed.status == "failed"
