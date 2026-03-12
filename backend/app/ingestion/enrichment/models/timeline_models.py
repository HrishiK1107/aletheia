from app.db.base import Base
from sqlalchemy import Column, DateTime, Integer, String, func


class CampaignTimeline(Base):
    """
    Records timeline events for campaigns and indicators.
    """

    __tablename__ = "campaign_timeline"

    id = Column(Integer, primary_key=True, index=True)

    campaign_id = Column(String, index=True, nullable=True)

    event_type = Column(String, nullable=False)

    event_value = Column(String, nullable=True)

    source = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
