from app.correlation.confidence_scorer import CampaignConfidenceScorer


def test_campaign_scoring():

    scorer = CampaignConfidenceScorer()

    campaign = {
        "campaign_id": "candidate_1",
        "indicators": ["evil.com", "1.1.1.1", "http://evil.com/login"],
        "size": 3,
    }

    result = scorer.score_campaign(campaign)

    assert "confidence" in result
    assert "strength" in result
    assert result["confidence"] > 0
