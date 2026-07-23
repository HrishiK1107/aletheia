"""
Baseline cluster generators for the §3 results table (CONTEXT.md item 7).

Random, GROUP BY ASN/resolved-IP/hosting_provider, and the retained Jaccard
v1 method all live here or are thin wrappers over existing engines. BFS
(unweighted and degree-weighted) is CampaignDetector.find_connected_clusters()
directly -- no wrapper needed, called straight from the evaluation runner.
"""

import random

MIN_CLUSTER = 3  # matches CampaignDetector.MIN_CLUSTER (k=3), for a fair comparison


def random_baseline(values: list[str], num_clusters: int, seed: int = 42) -> list[list[str]]:
    """
    Deterministic random partition of `values` into `num_clusters` groups --
    the ARI floor every other method in the table has to clear. Seeded so
    re-runs are reproducible (CONTEXT.md §7's determinism rule).
    """
    if num_clusters < 1:
        return []

    rng = random.Random(seed)
    shuffled = list(values)
    rng.shuffle(shuffled)

    clusters: list[list[str]] = [[] for _ in range(num_clusters)]
    for i, value in enumerate(shuffled):
        clusters[i % num_clusters].append(value)

    return [c for c in clusters if len(c) >= MIN_CLUSTER]


def group_by_feature_prefix(fingerprints: dict[str, set], prefix: str) -> list[list[str]]:
    """
    GROUP BY baseline built directly from an already-computed fingerprint
    dict (InfrastructureEngine.build_fingerprints() for "asn:"/"hosting:"/
    "registrar:"/"ns:", or build_weighted_fingerprints() for "org:"/"ip:")
    -- reuses the Postgres pass item 6 already pays for instead of a third
    N+1 query for the same enrichment data.

    An indicator with more than one value under this prefix (e.g. multiple
    resolved IPs, item 2.3) contributes to more than one group, matching
    how a naive single-attribute GROUP BY would behave for each of its
    values -- this is deliberately the naive, unweighted baseline the
    paper's method is contrasted against, not a refined version of it.
    """
    groups: dict[str, list[str]] = {}

    for value, features in fingerprints.items():
        for feat in features:
            if feat.startswith(prefix):
                groups.setdefault(feat, []).append(value)

    return [members for members in groups.values() if len(members) >= MIN_CLUSTER]
