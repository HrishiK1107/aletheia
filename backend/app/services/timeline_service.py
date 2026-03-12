from app.ingestion.enrichment.models.timeline_models import CampaignTimeline
from sqlalchemy.orm import Session


class TimelineService:

    def record_event(
        self,
        db: Session,
        event_type: str,
        event_value: str | None = None,
        campaign_id: str | None = None,
        source: str | None = None,
    ):

        event = CampaignTimeline(
            campaign_id=campaign_id,
            event_type=event_type,
            event_value=event_value,
            source=source,
        )

        db.add(event)
        db.commit()

        return event

    def get_campaign_timeline(self, db: Session, campaign_id: str):

        return (
            db.query(CampaignTimeline)
            .filter(CampaignTimeline.campaign_id == campaign_id)
            .order_by(CampaignTimeline.created_at)
            .all()
        )
