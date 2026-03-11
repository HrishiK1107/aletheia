from app.db.postgres import get_db
from app.ingestion.enrichment.models.indicator_models import Indicator
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

router = APIRouter(prefix="/pivot", tags=["Pivot"])


@router.get("/domain/{domain}")
def pivot_domain(domain: str, db: Session = Depends(get_db)):

    indicators = db.query(Indicator).filter(Indicator.value.contains(domain)).all()

    return indicators


@router.get("/ip/{ip}")
def pivot_ip(ip: str, db: Session = Depends(get_db)):

    indicators = db.query(Indicator).filter(Indicator.value == ip).all()

    return indicators
