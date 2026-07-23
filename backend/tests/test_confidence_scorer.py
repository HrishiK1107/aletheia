import pytest

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


def test_weighted_reuse_ratio_suppresses_high_degree_hub():
    """
    CONTEXT.md item 6's success metric: a commodity-only cluster (its only
    shared evidence is a feature with very high global degree, e.g. the
    Cloudflare ASN documented in item 2.1) must score near-zero on R(C)
    once degree-weighted, versus the flat-count baseline which would give
    it full credit just like a genuinely rare shared feature.
    """
    scorer = CampaignConfidenceScorer()

    indicators = ["a.com", "b.com", "c.com"]
    fingerprints = {
        "a.com": {"org:AS13335"},
        "b.com": {"org:AS13335"},
        "c.com": {"org:AS13335"},
    }
    # AS13335 shared by 2,048 domains globally (CONTEXT.md item 2.1) --
    # only 3 of which happen to be in this cluster.
    degrees = {"org:AS13335": 2048}

    unweighted = scorer._infrastructure_reuse_ratio(indicators, fingerprints)
    weighted = scorer._infrastructure_reuse_ratio_weighted(indicators, fingerprints, degrees)

    assert unweighted == pytest.approx(1 / 3)  # flat count: full credit regardless of degree
    assert weighted < unweighted / 100  # degree-weighted: same feature contributes almost nothing


def test_weighted_reuse_ratio_retains_score_for_rare_shared_feature():
    """
    The other half of item 6's success metric: a genuinely rare shared
    feature (low global degree) must NOT be suppressed -- otherwise the
    weighting is too aggressive and collapses real evidence along with
    commodity noise.
    """
    scorer = CampaignConfidenceScorer()

    indicators = ["a.com", "b.com", "c.com"]
    fingerprints = {
        "a.com": {"ns:ns1.rare-attacker-infra.com"},
        "b.com": {"ns:ns1.rare-attacker-infra.com"},
        "c.com": {"ns:ns1.rare-attacker-infra.com"},
    }
    # Shared by exactly these 3 domains globally -- a real, specific signal.
    degrees = {"ns:ns1.rare-attacker-infra.com": 3}

    weighted = scorer._infrastructure_reuse_ratio_weighted(indicators, fingerprints, degrees)

    # weight = 1/degree = 1/3, mean over the 3 cluster members = (1/3)/3 = 1/9
    assert weighted == pytest.approx(1 / 9)


def test_compute_score_uses_weighted_r_when_degrees_supplied():
    scorer = CampaignConfidenceScorer()

    campaign = {"campaign_id": "c1", "indicators": ["a.com", "b.com", "c.com"], "size": 3}
    fingerprints = {
        "a.com": {"org:AS13335"},
        "b.com": {"org:AS13335"},
        "c.com": {"org:AS13335"},
    }

    baseline_score = scorer.compute_score(campaign, fingerprints)
    weighted_score = scorer.compute_score(campaign, fingerprints, degrees={"org:AS13335": 2048})

    assert weighted_score < baseline_score
