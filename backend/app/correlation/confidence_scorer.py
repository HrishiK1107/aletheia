class CampaignConfidenceScorer:
    """
    Deterministic scoring engine for campaign clusters.
    """

    def __init__(self):
        pass

    def compute_score(self, campaign):
        """
        Score a campaign candidate using simple heuristics.
        """

        indicators = campaign["indicators"]
        size = campaign["size"]

        score = 0

        # Cluster size weight
        if size >= 10:
            score += 40
        elif size >= 5:
            score += 25
        elif size >= 3:
            score += 15
        else:
            score += 5

        # Indicator diversity
        types = set()

        for value in indicators:
            if value.startswith("http"):
                types.add("url")
            elif "." in value and not value.startswith("http"):
                types.add("domain")
            elif value.count(".") == 3:
                types.add("ip")
            else:
                types.add("hash")

        diversity_score = len(types) * 10
        score += diversity_score

        return min(score, 100)

    def classify_strength(self, score):
        """
        Convert numeric score into severity class.
        """

        if score >= 80:
            return "high"

        if score >= 50:
            return "medium"

        return "low"

    def score_campaign(self, campaign):
        """
        Produce final scored campaign object.
        """

        score = self.compute_score(campaign)

        return {
            **campaign,
            "confidence": score,
            "strength": self.classify_strength(score),
        }

    def score_campaigns(self, campaigns):
        """
        Score a list of campaign candidates.
        """

        return [self.score_campaign(c) for c in campaigns]
