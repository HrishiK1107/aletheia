from app.db.postgres import get_db
from app.schemas.indicator_schema import IndicatorCreate, IndicatorResponse
from app.services.indicator_service import create_indicator, get_indicator, list_indicators
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter(prefix="/indicators", tags=["Indicators"])


@router.post("/", response_model=IndicatorResponse)
def create_indicator_endpoint(
    indicator: IndicatorCreate,
    db: Session = Depends(get_db),
):
    return create_indicator(db, indicator)


@router.get("/", response_model=list[IndicatorResponse])
def list_indicators_endpoint(
    db: Session = Depends(get_db),
):
    return list_indicators(db)


@router.get("/{indicator_id}", response_model=IndicatorResponse)
def get_indicator_endpoint(
    indicator_id: int,
    db: Session = Depends(get_db),
):
    indicator = get_indicator(db, indicator_id)

    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")

    return indicator
