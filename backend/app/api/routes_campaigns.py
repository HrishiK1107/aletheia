from app.db.postgres import get_db
from app.ingestion.enrichment.models.campaign_models import Campaign
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


@router.get("/")
def list_campaigns(db: Session = Depends(get_db)):

    campaigns = db.query(Campaign).all()

    return campaigns


@router.get("/{campaign_id}")
def get_campaign(campaign_id: str, db: Session = Depends(get_db)):

    campaign = db.query(Campaign).filter(Campaign.campaign_id == campaign_id).first()

    return campaign
