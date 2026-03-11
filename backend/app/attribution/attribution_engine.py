from app.attribution.technique_mapper import TechniqueMapper


class AttributionEngine:
    """
    Produce threat actor attribution hypotheses.
    """

    def __init__(self):

        self.mapper = TechniqueMapper()

        # Example actor profiles
        self.actor_profiles = {
            "APT29": {
                "registrars": ["Namecheap"],
                "asn": ["AS13335"],
                "techniques": ["T1566", "T1071"],
            },
            "Lazarus": {
                "registrars": ["GoDaddy"],
                "asn": ["AS20940"],
                "techniques": ["T1105"],
            },
        }

    def score_actor(self, campaign, enrichment):

        actor_scores = {}

        for actor, profile in self.actor_profiles.items():

            score = 0

            if enrichment.registrar in profile["registrars"]:
                score += 0.3

            if enrichment.asn in profile["asn"]:
                score += 0.3

            techniques = self.mapper.map_domain(campaign["indicators"][0])

            overlap = set(techniques).intersection(profile["techniques"])

            score += 0.2 * len(overlap)

            actor_scores[actor] = score

        return actor_scores

    def attribute_campaign(self, campaign, enrichment):

        scores = self.score_actor(campaign, enrichment)

        actor = max(scores, key=scores.get)

        return {
            "campaign_id": campaign["campaign_id"],
            "actor": actor,
            "confidence": scores[actor],
        }
