from app.db.base import Base
from sqlalchemy import JSON, Column, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.sql import func


class RawIndicator(Base):
    """
    (value, source) is unique, not value alone: the same value legitimately
    appears from more than one feed (cross-feed corroboration -- see
    CONTEXT.md §5's overlap analysis), and that's real signal worth keeping
    as separate rows. What accumulated unbounded across repeated runs
    (CONTEXT.md item 1.4: 1,344 rows from two ~670-indicator collections)
    was the same feed re-reporting the same value on every run.
    """

    __tablename__ = "raw_indicators"
    __table_args__ = (UniqueConstraint("value", "source", name="uq_raw_indicators_value_source"),)

    id = Column(Integer, primary_key=True, index=True)

    value = Column(String, nullable=False)
    type = Column(String, nullable=False)

    source = Column(String, nullable=True)

    confidence = Column(Integer, default=50)

    raw_payload = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
