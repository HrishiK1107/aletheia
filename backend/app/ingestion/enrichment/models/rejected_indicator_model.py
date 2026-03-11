from app.db.base import Base
from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.sql import func


class RejectedIndicator(Base):
    __tablename__ = "rejected_indicators"

    id = Column(Integer, primary_key=True)

    value = Column(String)

    type = Column(String)

    source = Column(String)

    reason = Column(String)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
