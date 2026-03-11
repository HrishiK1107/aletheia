from app.correlation.infrastructure_engine import InfrastructureEngine
from app.ingestion.enrichment.models.campaign_models import Campaign
from sqlalchemy.orm import Session


class CampaignEngine:
    """
    Convert infrastructure clusters into persistent campaigns.
    """

    def __init__(self):
        self.infrastructure_engine = InfrastructureEngine()

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

            campaigns.append(
                {
                    "campaign_id": campaign_id,
                    "indicators": cluster,
                    "size": len(cluster),
                }
            )

        db.commit()

        return campaigns
