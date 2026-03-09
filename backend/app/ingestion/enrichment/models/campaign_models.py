from app.db.base import Base
from sqlalchemy import Column, DateTime, Integer, String, func


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)

    campaign_id = Column(String, unique=True, index=True)

    confidence = Column(Integer)

    strength = Column(String)

    indicator_count = Column(Integer)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
