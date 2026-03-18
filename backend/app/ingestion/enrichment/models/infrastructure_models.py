from app.db.base import Base
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func


class IndicatorEnrichment(Base):
    __tablename__ = "indicator_enrichment"

    id = Column(Integer, primary_key=True)

    indicator_id = Column(Integer, ForeignKey("indicators.id"), index=True)

    asn = Column(String, nullable=True)

    registrar = Column(String, nullable=True)

    hosting_provider = Column(String, nullable=True)

    nameservers = Column(String, nullable=True)

    resolved_ips = Column(String, nullable=True)

    # ✅ FIX: ADD THIS FIELD
    ssl_fingerprint = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
