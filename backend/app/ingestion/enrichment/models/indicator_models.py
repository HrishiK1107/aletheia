from app.db.base import Base
from sqlalchemy import Column, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.sql import func


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)

    value = Column(String, nullable=False, index=True)

    type = Column(String, nullable=False)

    source = Column(String, nullable=True)

    confidence = Column(Integer, default=50)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("value", "type", name="uq_indicator_value_type"),)
