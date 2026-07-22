from datetime import UTC, datetime

from app.ingestion.enrichment.models.feed_models import Feed
from app.ingestion.enrichment.models.feed_run_model import FeedRun
from app.ingestion.enrichment.models.feed_source_model import FeedSource
from sqlalchemy.orm import Session


def get_or_create_feed_source(db: Session, name: str) -> FeedSource:

    source = db.query(FeedSource).filter(FeedSource.name == name).first()

    if not source:
        source = FeedSource(name=name)
        db.add(source)
        db.commit()
        db.refresh(source)

    return source


def record_feed_run(
    db: Session, name: str, count: int, success: bool, error: str | None = None
) -> FeedRun:
    """
    Persist one row per collector run -- the history that per-feed
    reliability reporting (success rate, failure reasons over time) is
    built from. `Feed`/`update_feed_status` only holds the latest snapshot.
    """

    source = get_or_create_feed_source(db, name)

    run = FeedRun(
        feed_source_id=source.id,
        status="success" if success else "failed",
        indicators_collected=count,
        error=error,
        completed_at=datetime.now(UTC),
    )

    db.add(run)
    db.commit()
    db.refresh(run)

    return run


def update_feed_status(db: Session, name: str, count: int, success: bool) -> Feed:

    feed = db.query(Feed).filter(Feed.name == name).first()

    status = "success" if success else "failed"

    if not feed:
        feed = Feed(
            name=name,
            indicators_collected=count,
            status=status,
        )
        db.add(feed)

    else:
        feed.indicators_collected = count
        feed.status = status

    db.commit()
    db.refresh(feed)

    return feed
