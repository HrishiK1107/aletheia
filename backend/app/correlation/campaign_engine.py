from app.correlation.infrastructure_engine import InfrastructureEngine
from app.ingestion.enrichment.models.campaign_models import Campaign
from app.services.timeline_service import TimelineService
from sqlalchemy.orm import Session


class CampaignEngine:
    """
    Convert infrastructure clusters into persistent campaigns.
    """

    def __init__(self):
        self.infrastructure_engine = InfrastructureEngine()
        self.timeline = TimelineService()

    def detect_campaigns(self, db: Session):

        clusters = self.infrastructure_engine.detect_clusters(db)

        campaigns = []

        for i, cluster in enumerate(clusters):

            campaign_id = f"campaign_{i+1}"

            campaign = Campaign(
                campaign_id=campaign_id,
                indicator_count=len(cluster),
                confidence=60,
                strength="emerging",
            )

            db.add(campaign)

            # Record timeline event
            self.timeline.record_event(
                db=db,
                event_type="campaign_created",
                event_value=campaign_id,
                campaign_id=campaign_id,
                source="campaign_engine",
            )

            campaigns.append(
                {
                    "campaign_id": campaign_id,
                    "indicators": cluster,
                    "size": len(cluster),
                }
            )

        db.commit()

        return campaigns
