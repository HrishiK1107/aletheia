from app.correlation.infrastructure_engine import InfrastructureEngine
from app.ingestion.enrichment.models.campaign_models import Campaign
from app.services.timeline_service import TimelineService
from sqlalchemy.orm import Session


class CampaignEngine:
    """
    Convert infrastructure clusters into persistent campaigns.
    Prevent duplicate campaign creation.
    """

    def __init__(self):
        self.infrastructure_engine = InfrastructureEngine()
        self.timeline = TimelineService()

    def generate_campaign_id(self, cluster):
        """
        Generate deterministic campaign ID based on cluster indicators.
        """
        sorted_cluster = sorted(cluster)
        return "campaign_" + str(abs(hash("|".join(sorted_cluster))) % 10**10)

    def detect_campaigns(self, db: Session):

        clusters = self.infrastructure_engine.detect_clusters(db)

        campaigns = []

        for cluster in clusters:

            campaign_id = self.generate_campaign_id(cluster)

            # check if campaign already exists
            existing = db.query(Campaign).filter(Campaign.campaign_id == campaign_id).first()

            if existing:
                # ✅ FIX: DO NOT SKIP RETURN
                campaigns.append(
                    {
                        "campaign_id": campaign_id,
                        "indicators": cluster,
                        "size": len(cluster),
                    }
                )
                continue

            campaign = Campaign(
                campaign_id=campaign_id,
                indicator_count=len(cluster),
                confidence=60,
                strength="emerging",
            )

            db.add(campaign)

            # timeline event
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
