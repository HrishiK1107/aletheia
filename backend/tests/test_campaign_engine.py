from unittest.mock import MagicMock

from app.correlation.campaign_engine import CampaignEngine


def test_campaign_engine_detects_clusters():

    engine = CampaignEngine()

    db = MagicMock()

    engine.campaign_detector.find_connected_clusters = MagicMock(
        return_value=[["evil.com", "evil2.com"]]
    )
    engine.infrastructure_engine.build_weighted_fingerprints = MagicMock(return_value={})

    campaigns = engine.detect_campaigns(db)

    assert len(campaigns) == 1
    assert campaigns[0]["size"] == 2


def test_campaign_engine_uses_bfs_detector_not_jaccard():
    """
    CONTEXT.md item 1.1: the paper describes BFS clustering but the pipeline
    used to run Jaccard fingerprint similarity instead. detect_campaigns()
    must call CampaignDetector, and must NOT call
    InfrastructureEngine.detect_clusters (the retired-as-live-path Jaccard
    baseline), or that mismatch is back.
    """

    engine = CampaignEngine()

    db = MagicMock()

    engine.campaign_detector.find_connected_clusters = MagicMock(return_value=[])
    engine.infrastructure_engine.build_weighted_fingerprints = MagicMock(return_value={})
    engine.infrastructure_engine.detect_clusters = MagicMock(
        side_effect=AssertionError("Jaccard detect_clusters should not be called")
    )

    engine.detect_campaigns(db)

    engine.campaign_detector.find_connected_clusters.assert_called_once()
    engine.infrastructure_engine.detect_clusters.assert_not_called()


def test_campaign_engine_scoring_uses_postgres_fingerprints():
    """
    Fingerprints (for R(C)/E(C)) still come from InfrastructureEngine's
    Postgres enrichment data regardless of which algorithm produced the
    clusters -- clustering and scoring are independent. Item 6: the live
    engine uses the degree-weighted fingerprint builder, not the unmerged
    one that feeds the retained Jaccard baseline.
    """

    engine = CampaignEngine()

    db = MagicMock()

    engine.campaign_detector.find_connected_clusters = MagicMock(
        return_value=[["evil.com", "evil2.com"]]
    )
    engine.infrastructure_engine.build_weighted_fingerprints = MagicMock(
        return_value={"evil.com": {"org:1234"}, "evil2.com": {"org:1234"}}
    )

    campaigns = engine.detect_campaigns(db)

    engine.infrastructure_engine.build_weighted_fingerprints.assert_called_once_with(db)
    assert campaigns[0]["size"] == 2
