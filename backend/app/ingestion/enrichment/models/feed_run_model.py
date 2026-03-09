from app.db.base import Base
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func


class FeedRun(Base):
    __tablename__ = "feed_runs"

    id = Column(Integer, primary_key=True, index=True)

    feed_source_id = Column(Integer, ForeignKey("feed_sources.id"))

    status = Column(String, default="running", nullable=False)

    indicators_collected = Column(Integer, default=0, nullable=False)

    started_at = Column(DateTime(timezone=True), server_default=func.now())

    completed_at = Column(DateTime(timezone=True), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        if self.status is None:
            self.status = "running"

        if self.indicators_collected is None:
            self.indicators_collected = 0
