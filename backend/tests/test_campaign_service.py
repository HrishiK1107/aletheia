from unittest.mock import MagicMock

from app.services.campaign_service import CampaignService


def test_materialize_campaign():

    service = CampaignService()

    db = MagicMock()

    campaign = {"campaign_id": "candidate_1", "confidence": 70, "strength": "medium", "size": 4}

    result = service.create_campaign(db, campaign)

    assert result.campaign_id == "candidate_1"
