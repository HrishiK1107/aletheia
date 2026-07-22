from app.correlation.campaign_detector import CampaignDetector
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.ingestion.enrichment.models.campaign_models import Campaign
from app.services.timeline_service import TimelineService
from sqlalchemy.orm import Session


class CampaignEngine:
    """
    Convert infrastructure clusters into persistent, confidence-scored campaigns.

    Clustering is performed by CampaignDetector: deterministic BFS traversal
    of the Neo4j graph (d=2, k=3 -- see campaign_detector.py, paper Section
    3.5). This is the algorithm the paper describes and the one this engine
    now actually runs.

    InfrastructureEngine's Jaccard fingerprint clustering (threshold 0.75)
    is deliberately NOT used for clustering here -- it was the prior "v1"
    method and is kept only as an explicit, separately-callable baseline for
    the results table in CONTEXT.md (§3): call
    `InfrastructureEngine().detect_clusters(db)` directly for that
    comparison. Do not wire it back into this engine; that reintroduces the
    exact defect this fixed (paper describes one algorithm, pipeline runs
    another).

    `InfrastructureEngine.build_fingerprints()` (Postgres enrichment data)
    is still used here, independent of which algorithm produced the
    clusters, because CampaignConfidenceScorer's R(C)/E(C) components need
    per-indicator enrichment features regardless of clustering method.

    Confidence scoring uses CampaignConfidenceScorer, implementing the
    weighted additive formula described in the paper:

        score(C) = α·N(C) + β·D(C) + γ·R(C) + δ·E(C)
    """

    def __init__(self):
        self.campaign_detector = CampaignDetector()
        self.infrastructure_engine = InfrastructureEngine()
        self.scorer = CampaignConfidenceScorer()
        self.timeline = TimelineService()

    def generate_campaign_id(self, cluster: list[str]) -> str:
        """Deterministic campaign ID derived from sorted cluster membership."""
        return "campaign_" + str(abs(hash("|".join(sorted(cluster)))) % 10**10)

    def detect_campaigns(self, db: Session) -> list[dict]:
        """
        Run the full clustering → scoring → persistence pipeline.

        Returns a list of scored campaign dicts (one per cluster), including
        both newly created and pre-existing campaigns.
        """
        # Clusters come from the Neo4j BFS traversal (paper algorithm).
        # Fingerprints come from Postgres enrichment, used only for scoring.
        fingerprints = self.infrastructure_engine.build_fingerprints(db)
        clusters = self.campaign_detector.find_connected_clusters()

        # Assemble raw campaign dicts
        raw_campaigns = [
            {
                "campaign_id": self.generate_campaign_id(cluster),
                "indicators": cluster,
                "size": len(cluster),
            }
            for cluster in clusters
        ]

        # Score all campaigns together so N(C) is normalised across the full batch
        scored_campaigns = self.scorer.score_campaigns(raw_campaigns, fingerprints=fingerprints)

        result = []

        for campaign in scored_campaigns:
            campaign_id = campaign["campaign_id"]

            existing = db.query(Campaign).filter(Campaign.campaign_id == campaign_id).first()

            if existing:
                result.append(campaign)
                continue

            record = Campaign(
                campaign_id=campaign_id,
                indicator_count=campaign["size"],
                confidence=campaign["confidence"],
                strength=campaign["strength"],
            )

            db.add(record)

            self.timeline.record_event(
                db=db,
                event_type="campaign_created",
                event_value=campaign_id,
                campaign_id=campaign_id,
                source="campaign_engine",
            )

            result.append(campaign)

        db.commit()
        return result
