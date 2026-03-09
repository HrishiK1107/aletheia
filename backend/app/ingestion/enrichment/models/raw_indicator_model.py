from app.db.base import Base
from sqlalchemy import JSON, Column, DateTime, Integer, String
from sqlalchemy.sql import func


class RawIndicator(Base):
    __tablename__ = "raw_indicators"

    id = Column(Integer, primary_key=True, index=True)

    value = Column(String, nullable=False)
    type = Column(String, nullable=False)

    source = Column(String, nullable=True)

    confidence = Column(Integer, default=50)

    raw_payload = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
