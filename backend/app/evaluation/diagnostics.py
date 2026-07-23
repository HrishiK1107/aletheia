"""
Diagnoses why ARI came back low (~0.07) for every method in item 7's first
run, including the baselines -- CONTEXT.md item 7 follow-up, 2026-07-23.
Answers: does infrastructure sharing even correlate with the ground-truth
label at all, for any method, or is ARI-against-label the wrong metric?
"""

from collections import Counter


def label_infra_cohesion(
    labels: dict[str, str], fingerprints: dict[str, set], top_n: int = 10
) -> list[dict]:
    """
    For the top_n largest labels (malware family or OTX pulse) by member
    count: what fraction of that label's members share at least one
    infrastructure feature with at least one OTHER member of the SAME
    label? Split into enrichment coverage (has any fingerprint at all) vs.
    cohesion-among-enriched (has a fingerprint AND it overlaps a same-label
    peer), so "family looks orthogonal to infra" isn't confounded with
    "family members mostly were never enriched."
    """
    by_label: dict[str, list[str]] = {}
    for value, label in labels.items():
        by_label.setdefault(label, []).append(value)

    ranked = sorted(by_label.items(), key=lambda kv: len(kv[1]), reverse=True)[:top_n]

    results = []
    for label, members in ranked:
        n_total = len(members)

        # in-label feature degree: how many members of THIS label share each feature
        in_label_counts: Counter = Counter()
        for v in members:
            for feat in fingerprints.get(v, set()):
                in_label_counts[feat] += 1

        n_enriched = sum(1 for v in members if fingerprints.get(v))
        n_cohesive = sum(
            1
            for v in members
            if any(in_label_counts[feat] >= 2 for feat in fingerprints.get(v, set()))
        )

        results.append(
            {
                "label": label,
                "n_total": n_total,
                "n_enriched": n_enriched,
                "n_cohesive": n_cohesive,
                "enriched_fraction": n_enriched / n_total if n_total else 0.0,
                "cohesion_among_enriched": (n_cohesive / n_enriched if n_enriched else 0.0),
                "cohesion_overall": n_cohesive / n_total if n_total else 0.0,
            }
        )

    return results


class _UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def connectivity_components(
    fingerprints: dict[str, set], degrees: dict, max_degree: float | None = None
) -> list[list[str]]:
    """
    Connected components over the "shares an infrastructure feature" graph
    -- full transitive closure, no depth limit, no k-minimum. Every
    indicator with at least one fingerprint feature is a node.

    max_degree: if given, edges only exist through features with global
    degree <= max_degree -- i.e. this simulates "what if we only ever
    connected on genuinely specific (non-hub) infrastructure." None means
    every feature can connect, matching BFS's traversal rule but with
    unlimited depth instead of d=2.
    """
    uf = _UnionFind()

    feature_to_indicators: dict[str, list[str]] = {}
    for value, features in fingerprints.items():
        for feat in features:
            if max_degree is not None and degrees.get(feat, 0) > max_degree:
                continue
            feature_to_indicators.setdefault(feat, []).append(value)

    for indicators in feature_to_indicators.values():
        for other in indicators[1:]:
            uf.union(indicators[0], other)

    components: dict[str, list[str]] = {}
    for value in fingerprints:
        root = uf.find(value)  # values never unioned become their own singleton root
        components.setdefault(root, []).append(value)

    return list(components.values())


def connectivity_threshold_sweep(
    fingerprints: dict[str, set],
    degrees: dict,
    true_labels: dict[str, str],
    thresholds: list[float | None],
) -> list[dict]:
    """
    For each degree threshold, build connectivity components restricted to
    that threshold and report ARI/precision/recall against true_labels.

    This is NOT a theoretical ceiling on infrastructure-based clustering in
    general. It is the best ARI achieved by one specific method family
    (single global degree threshold, all feature types pooled) swept over
    that family's one parameter. CONTEXT.md's item-7 ARI diagnosis found
    actual BFS (depth + relation-type-combined traversal) beats every point
    in this sweep for the OTX-without-outlier ground truth -- direct proof
    this sweep is not an upper bound over infra-clustering methods
    generally, just over this one family of them.
    """
    # local import to avoid a module-level cycle with metrics<->diagnostics
    from app.evaluation.metrics import (
        adjusted_rand_index,
        build_predicted_labels,
        pairwise_precision_recall,
    )

    results = []
    for threshold in thresholds:
        clusters = connectivity_components(fingerprints, degrees, max_degree=threshold)
        clusters = [c for c in clusters if len(c) >= 2]  # singletons carry no clustering info

        universe = {v for c in clusters for v in c} | set(true_labels)
        pred = build_predicted_labels(clusters, universe)

        ari = adjusted_rand_index(true_labels, pred)
        precision, recall = pairwise_precision_recall(true_labels, pred)

        sizes = sorted((len(c) for c in clusters), reverse=True)
        results.append(
            {
                "threshold": threshold,
                "n_components": len(clusters),
                "largest_component": sizes[0] if sizes else 0,
                "ari": ari,
                "precision": precision,
                "recall": recall,
            }
        )

    return results
