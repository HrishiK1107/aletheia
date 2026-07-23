from collections import Counter

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
    # Degree-weighted fingerprint (item 6 / CONTEXT.md 2.1)
    # ------------------------------------------------

    def weighted_fingerprint(self, enrichment: IndicatorEnrichment) -> set:
        """
        Four feature classes, not five: org (hosting_provider merged with
        asn), registrar, nameserver, resolved_ip. hosting_provider and asn
        are collinear -- the same company reported via two fields of the
        same lookup, verified 1:1 at both N=9 and N=1,396 in CONTEXT.md item
        2.1 -- so counting both separately would double-count one fact as
        two pieces of corroborating evidence. hosting_provider wins when
        present (more legible identity); asn is the fallback only when
        hosting_provider never resolved a name.

        Deliberately separate from fingerprint() above: that one stays
        unmerged and untouched because it feeds the retained Jaccard
        baseline (CONTEXT.md item 1.1), which must remain a faithful,
        unchanged "v1 method" comparison point. This merge applies only to
        the new degree-weighted construction.
        """
        features = set()

        if enrichment.hosting_provider:
            features.add(f"org:{enrichment.hosting_provider}")
        elif enrichment.asn:
            for asn in enrichment.asn.split(","):
                asn = asn.strip()
                if asn:
                    features.add(f"org:{asn}")

        if enrichment.registrar:
            features.add(f"registrar:{enrichment.registrar}")

        if enrichment.nameservers:
            for ns in enrichment.nameservers.split(","):
                ns = ns.strip()
                if ns:
                    features.add(f"ns:{ns}")

        if enrichment.resolved_ips:
            for ip in enrichment.resolved_ips.split(","):
                ip = ip.strip()
                if ip:
                    features.add(f"ip:{ip}")

        return features

    def build_weighted_fingerprints(self, db: Session) -> dict:
        """Same access pattern as build_fingerprints(), weighted_fingerprint() per indicator."""
        fingerprints = {}

        enrichments = db.query(IndicatorEnrichment).all()

        for e in enrichments:
            indicator = db.query(Indicator).filter(Indicator.id == e.indicator_id).first()

            if not indicator:
                continue

            fingerprints[indicator.value] = self.weighted_fingerprint(e)

        return fingerprints

    def compute_feature_degrees(self, fingerprints: dict) -> Counter:
        """
        Global degree of every infrastructure feature: how many distinct
        indicators, across the whole run (not just one cluster), carry it.
        This is the indicator-granularity analogue of Neo4j node degree --
        confirmed against the live graph (CONTEXT.md item 2.1): the
        1,849-member cluster is held together almost entirely by one hub,
        ASN AS13335 (100% of members) / HostingProvider "Cloudflare, Inc."
        (97.8%), and AS13335 alone has degree 2,048 among domains with any
        ASN edge. Computed here as a single pass over fingerprints already
        loaded for scoring, so no second Neo4j traversal is needed (a
        dedicated per-cluster Neo4j attribute query timed out at 280s on
        this exact cluster).
        """
        degrees: Counter = Counter()

        for feature_set in fingerprints.values():
            for feature in feature_set:
                degrees[feature] += 1

        return degrees

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
