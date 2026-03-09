from datetime import UTC, datetime

from app.db.base import Base
from sqlalchemy import Column, DateTime, Integer, String


class Feed(Base):
    __tablename__ = "feeds"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String, unique=True, nullable=False)

    last_run = Column(DateTime, default=lambda: datetime.now(UTC))

    last_success = Column(DateTime, nullable=True)

    indicators_collected = Column(Integer, default=0)

    status = Column(String, default="unknown")
