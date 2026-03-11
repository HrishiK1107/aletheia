from app.db.base import Base
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func


class IndicatorMetadata(Base):
    __tablename__ = "indicator_metadata"

    id = Column(Integer, primary_key=True)

    indicator_id = Column(Integer, ForeignKey("indicators.id"), index=True)

    source = Column(String)

    confidence = Column(Integer)

    first_seen = Column(DateTime(timezone=True), server_default=func.now())
