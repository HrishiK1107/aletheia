from app.ingestion.enrichment.models.feed_models import Feed
from sqlalchemy.orm import Session


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
