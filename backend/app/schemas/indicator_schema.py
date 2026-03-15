from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class IndicatorCreate(BaseModel):
    value: str = Field(..., min_length=1, max_length=2000)

    type: str = Field(
        ...,
        description="IOC type: ip, domain, url, hash",
    )

    source: Optional[str] = Field(
        default="manual",
        description="Source of the IOC",
    )

    confidence: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Confidence score (0-100)",
    )


class IndicatorResponse(BaseModel):
    id: int
    value: str
    type: str
    source: Optional[str]
    confidence: int
    created_at: datetime

    model_config = {"from_attributes": True}
