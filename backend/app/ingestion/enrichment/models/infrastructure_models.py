from app.db.base import Base
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func


class IndicatorEnrichment(Base):
    """
    Stores infrastructure intelligence for indicators.
    Each indicator may have one enrichment record.
    """

    __tablename__ = "indicator_enrichment"

    id = Column(Integer, primary_key=True, index=True)

    indicator_id = Column(Integer, ForeignKey("indicators.id"), index=True)

    # Infrastructure attributes
    asn = Column(String, nullable=True)

    registrar = Column(String, nullable=True)

    hosting_provider = Column(String, nullable=True)

    nameservers = Column(Text, nullable=True)

    ssl_fingerprint = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
