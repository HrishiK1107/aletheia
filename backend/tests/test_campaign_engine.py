from unittest.mock import MagicMock

from app.correlation.campaign_engine import CampaignEngine


def test_campaign_engine_detects_clusters():

    engine = CampaignEngine()

    db = MagicMock()

    engine.infrastructure_engine.detect_clusters = MagicMock(
        return_value=[["evil.com", "evil2.com"]]
    )

    campaigns = engine.detect_campaigns(db)

    assert len(campaigns) == 1
    assert campaigns[0]["size"] == 2
