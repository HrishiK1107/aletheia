from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment
from sqlalchemy.orm import Session


class InfrastructureEngine:
    """
    Detect infrastructure clusters using enrichment fingerprints.
    """

    SIMILARITY_THRESHOLD = 0.75

    # ------------------------------------------------
    # Build infrastructure fingerprint
    # ------------------------------------------------

    def fingerprint(self, enrichment: IndicatorEnrichment):

        features = set()

        if enrichment.asn:
            features.add(f"asn:{enrichment.asn}")

        if enrichment.registrar:
            features.add(f"registrar:{enrichment.registrar}")

        if enrichment.hosting_provider:
            features.add(f"hosting:{enrichment.hosting_provider}")

        if enrichment.nameservers:

            for ns in enrichment.nameservers.split(","):

                ns = ns.strip()

                if ns:
                    features.add(f"ns:{ns}")

        return features

    # ------------------------------------------------
    # Jaccard similarity
    # ------------------------------------------------

    def similarity(self, f1, f2):

        if not f1 or not f2:
            return 0

        intersection = len(f1.intersection(f2))
        union = len(f1.union(f2))

        if union == 0:
            return 0

        return intersection / union

    # ------------------------------------------------
    # Build indicator fingerprints
    # ------------------------------------------------

    def build_fingerprints(self, db: Session):

        fingerprints = {}

        enrichments = db.query(IndicatorEnrichment).all()

        for e in enrichments:

            indicator = db.query(Indicator).filter(Indicator.id == e.indicator_id).first()

            if not indicator:
                continue

            fingerprints[indicator.value] = self.fingerprint(e)

        return fingerprints

    # ------------------------------------------------
    # Cluster detection
    # ------------------------------------------------

    def detect_clusters(self, db: Session):

        fingerprints = self.build_fingerprints(db)

        indicators = list(fingerprints.keys())

        clusters = []
        visited = set()

        for i, ind1 in enumerate(indicators):

            if ind1 in visited:
                continue

            cluster = [ind1]

            visited.add(ind1)

            for ind2 in indicators[i + 1 :]:

                sim = self.similarity(
                    fingerprints[ind1],
                    fingerprints[ind2],
                )

                if sim >= self.SIMILARITY_THRESHOLD:

                    cluster.append(ind2)

                    visited.add(ind2)

            if len(cluster) > 1:
                clusters.append(cluster)

        return clusters
