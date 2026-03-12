from app.db.postgres import get_db
from app.ingestion.enrichment.models.campaign_models import Campaign
from app.services.timeline_service import TimelineService
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


@router.get("/{campaign_id}/timeline")
def campaign_timeline(campaign_id: str, db: Session = Depends(get_db)):

    timeline = TimelineService()

    events = timeline.get_campaign_timeline(db, campaign_id)

    return events
