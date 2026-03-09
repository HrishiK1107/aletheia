from app.ingestion.enrichment.models.campaign_models import Campaign
from sqlalchemy.orm import Session


class CampaignService:
    """
    Persist campaign candidates detected by correlation engine.
    """

    def create_campaign(self, db: Session, campaign_data):

        campaign = Campaign(
            campaign_id=campaign_data["campaign_id"],
            confidence=campaign_data["confidence"],
            strength=campaign_data["strength"],
            indicator_count=campaign_data["size"],
        )

        db.add(campaign)
        db.commit()
        db.refresh(campaign)

        return campaign

    def materialize_campaigns(self, db: Session, campaigns):

        stored_campaigns = []

        for campaign_data in campaigns:
            stored_campaigns.append(self.create_campaign(db, campaign_data))

        return stored_campaigns
