"""
Evaluation metrics for the §3 results table (CONTEXT.md item 7): Adjusted
Rand Index and pairwise precision/recall against ground-truth labels, plus
cluster-size-band stratification.

Implemented directly rather than depending on scikit-learn: ARI is a closed
contingency-table formula (identical to sklearn.metrics.adjusted_rand_score),
and pulling in scikit-learn/numpy/scipy for one function is more dependency
than this project's "everything must be free, keep it simple" stance
(CONTEXT.md §1) buys back.
"""

from collections import Counter

SIZE_BANDS: list[tuple[str, int, int | float]] = [
    ("3-5", 3, 5),
    ("6-10", 6, 10),
    ("11-50", 11, 50),
    ("50+", 51, float("inf")),
]


def build_predicted_labels(clusters: list[list[str]], universe: set) -> dict[str, int]:
    """
    Assign a predicted-cluster id to every value in `universe`. Values that
    landed in a detected cluster share that cluster's id; every value in
    `universe` that no cluster claimed gets its own singleton id, so a
    method that fails to group two same-labelled items is correctly
    penalised by ARI/recall instead of those items being silently dropped
    from the comparison.

    Some baselines (e.g. GROUP BY on a multi-valued feature, or Jaccard)
    deliberately return overlapping clusters -- a value with two resolved
    IPs lands in both IP groups. `clusters` is therefore sorted into a
    canonical order (by each cluster's own sorted membership) before ids
    are assigned, and the first cluster in that order to claim a value
    keeps it. This makes the resulting partition a pure function of
    cluster *content*, not of whatever order the caller's clusters
    happened to be built in -- which otherwise varies run to run when that
    order comes from iterating a Python `set` (hash-randomized per
    process, see CONTEXT.md's audit-fixes entry).
    """
    labels: dict[str, int] = {}
    next_id = 0

    ordered_clusters = sorted(clusters, key=lambda cluster: sorted(cluster))

    for cluster in ordered_clusters:
        for value in cluster:
            if value in universe and value not in labels:
                labels[value] = next_id
        next_id += 1

    for value in universe:
        if value not in labels:
            labels[value] = next_id
            next_id += 1

    return labels


def _comb2(n: int) -> float:
    return n * (n - 1) / 2


def _contingency_sums(true_labels: dict, pred_labels: dict) -> dict:
    """Shared contingency-table bookkeeping ARI and pairwise precision/recall both need."""
    common = [v for v in true_labels if v in pred_labels]

    contingency: Counter = Counter()
    row_sums: Counter = Counter()  # per true label
    col_sums: Counter = Counter()  # per predicted cluster

    for value in common:
        t, p = true_labels[value], pred_labels[value]
        contingency[(t, p)] += 1
        row_sums[t] += 1
        col_sums[p] += 1

    return {
        "n": len(common),
        "sum_comb_c": sum(_comb2(c) for c in contingency.values()),
        "sum_comb_a": sum(_comb2(c) for c in row_sums.values()),
        "sum_comb_b": sum(_comb2(c) for c in col_sums.values()),
    }


def adjusted_rand_index(true_labels: dict, pred_labels: dict) -> float:
    """
    ARI over the intersection of both label dicts' keys. Returns float('nan')
    if fewer than 2 common items (undefined). Matches
    sklearn.metrics.adjusted_rand_score's formula exactly.
    """
    s = _contingency_sums(true_labels, pred_labels)
    n = s["n"]

    if n < 2:
        return float("nan")

    total_pairs = _comb2(n)
    expected = s["sum_comb_a"] * s["sum_comb_b"] / total_pairs if total_pairs else 0.0
    max_index = 0.5 * (s["sum_comb_a"] + s["sum_comb_b"])
    denom = max_index - expected

    if denom == 0:
        # Degenerate: either every item is its own cluster/label, or all in one.
        return 1.0 if s["sum_comb_c"] == expected else 0.0

    return (s["sum_comb_c"] - expected) / denom


def pairwise_precision_recall(true_labels: dict, pred_labels: dict) -> tuple[float, float]:
    """
    Pairwise precision/recall over the intersection of both label dicts:
    precision = (pairs correctly grouped) / (pairs predicted grouped)
    recall    = (pairs correctly grouped) / (pairs that should be grouped)
    """
    s = _contingency_sums(true_labels, pred_labels)

    precision = s["sum_comb_c"] / s["sum_comb_b"] if s["sum_comb_b"] else 0.0
    recall = s["sum_comb_c"] / s["sum_comb_a"] if s["sum_comb_a"] else 0.0

    return precision, recall


def size_band(size: int) -> str | None:
    for label, lo, hi in SIZE_BANDS:
        if lo <= size <= hi:
            return label
    return None


def stratify_by_size(
    clusters: list[list[str]], true_labels: dict
) -> dict[str, dict]:
    """
    Per size band: restrict the evaluation to items belonging to clusters
    whose size falls in that band (items outside the band's clusters are
    excluded entirely, not folded into a shared background) and report
    ARI/precision/recall for that subset alone. This is what CONTEXT.md
    item 2.2 requires: R(C) before/after comparisons are confounded with
    cluster size, so any aggregate ARI/precision claim needs this
    breakdown to show whether an advantage holds across scales or is an
    artifact of one band.
    """
    results: dict[str, dict] = {}

    for label, lo, hi in SIZE_BANDS:
        band_clusters = [c for c in clusters if lo <= len(c) <= hi]
        universe = {v for c in band_clusters for v in c}

        if not universe:
            results[label] = {"n_clusters": 0, "n_labelled": 0, "ari": None, "precision": None, "recall": None}
            continue

        pred = build_predicted_labels(band_clusters, universe)
        labelled_in_band = {v: t for v, t in true_labels.items() if v in universe}

        ari = adjusted_rand_index(labelled_in_band, pred)
        precision, recall = pairwise_precision_recall(labelled_in_band, pred)

        results[label] = {
            "n_clusters": len(band_clusters),
            "n_labelled": len(labelled_in_band),
            "ari": ari,
            "precision": precision,
            "recall": recall,
        }

    return results


def commodity_fp_rate(clusters: list[list[str]], commodity_only_flags: list[bool]) -> float:
    """Fraction of clusters flagged commodity-only (item 2.1's per-cluster classification)."""
    if not clusters:
        return 0.0
    return sum(commodity_only_flags) / len(clusters)
