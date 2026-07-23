from app.evaluation.metrics import (
    adjusted_rand_index,
    build_predicted_labels,
    pairwise_precision_recall,
    size_band,
    stratify_by_size,
)


def test_ari_perfect_match_is_one():
    true_labels = {"a": "fam1", "b": "fam1", "c": "fam2", "d": "fam2"}
    pred_labels = {"a": 0, "b": 0, "c": 1, "d": 1}

    assert adjusted_rand_index(true_labels, pred_labels) == 1.0


def test_ari_everything_singleton_is_zero_or_defined():
    """Every predicted cluster a singleton -- no pairs agree, ARI should not be > 0."""
    true_labels = {"a": "fam1", "b": "fam1", "c": "fam2", "d": "fam2"}
    pred_labels = {"a": 0, "b": 1, "c": 2, "d": 3}

    ari = adjusted_rand_index(true_labels, pred_labels)
    assert ari <= 0.0


def test_ari_matches_known_sklearn_value():
    """
    Cross-checked against sklearn.metrics.adjusted_rand_score for this
    exact input (computed by hand via the contingency-table formula, not
    just asserted to run) -- true=[0,0,0,1,1,1], pred=[0,0,1,1,2,2].
    """
    true_labels = {f"i{i}": v for i, v in enumerate([0, 0, 0, 1, 1, 1])}
    pred_labels = {f"i{i}": v for i, v in enumerate([0, 0, 1, 1, 2, 2])}

    ari = adjusted_rand_index(true_labels, pred_labels)
    assert abs(ari - 0.2424242424242424) < 1e-9


def test_ari_degenerate_both_all_singletons_returns_one():
    """
    adjusted_rand_index()'s denom==0 branch, previously untested (audit
    fix A3, CONTEXT.md audit-fixes entry). Every item is its own true
    label AND its own predicted cluster: sum_comb_a = sum_comb_b = 0, so
    max_index == expected == 0 and the formula's normal division would be
    0/0. This is the exact shape of the already-flagged production case
    (ThreatFox 6-10 size band, weighted, n_labelled=2: ARI=1.0000 despite
    precision=recall=0.0000) -- confirms it's the degenerate branch
    firing, not a bug in the main formula.
    """
    true_labels = {"a": "fam1", "b": "fam2"}
    pred_labels = {"a": 0, "b": 1}

    assert adjusted_rand_index(true_labels, pred_labels) == 1.0

    precision, recall = pairwise_precision_recall(true_labels, pred_labels)
    assert precision == 0.0
    assert recall == 0.0


def test_ari_degenerate_both_all_one_cluster_returns_one():
    """
    The other side of the denom==0 branch: every item shares the one
    true label AND the one predicted cluster (sum_comb_a = sum_comb_b =
    max possible = C(n,2), same degenerate max_index == expected shape
    as the all-singletons case, but from the opposite extreme).
    """
    true_labels = {"a": "fam1", "b": "fam1", "c": "fam1"}
    pred_labels = {"a": 0, "b": 0, "c": 0}

    assert adjusted_rand_index(true_labels, pred_labels) == 1.0


def test_pairwise_precision_recall_perfect():
    true_labels = {"a": "fam1", "b": "fam1", "c": "fam2"}
    pred_labels = {"a": 0, "b": 0, "c": 1}

    precision, recall = pairwise_precision_recall(true_labels, pred_labels)

    assert precision == 1.0
    assert recall == 1.0


def test_pairwise_precision_recall_over_grouping():
    """Everything in one predicted cluster: recall perfect, precision suffers."""
    true_labels = {"a": "fam1", "b": "fam1", "c": "fam2", "d": "fam2"}
    pred_labels = {"a": 0, "b": 0, "c": 0, "d": 0}

    precision, recall = pairwise_precision_recall(true_labels, pred_labels)

    assert recall == 1.0
    assert precision < 1.0


def test_build_predicted_labels_gives_singletons_to_unclustered_items():
    clusters = [["a", "b"]]
    universe = {"a", "b", "c", "d"}

    labels = build_predicted_labels(clusters, universe)

    assert labels["a"] == labels["b"]
    assert labels["c"] != labels["d"]
    assert labels["c"] != labels["a"]


def test_build_predicted_labels_multi_membership_is_order_independent():
    """
    CONTEXT.md §6j (2026-07-23): overlapping baselines (GROUP BY,
    Jaccard) can put one value in more than one cluster. This used to be
    resolved by unconditional overwrite -- "last cluster in `clusters`
    wins" -- so the predicted partition depended on whatever order the
    caller's `clusters` list happened to be built in. That order came
    from iterating a Python `set` upstream (group_by_feature_prefix's
    per-value feature set), which is hash-randomized per process, so two
    runs of identical code could disagree. Regression test: the same
    overlapping input, in three different list orders, must produce the
    exact same partition every time -- a pure function of cluster
    content, not of input order. (This covers only the Python-layer
    resolution; it doesn't test whatever upstream order Postgres/Neo4j
    actually return rows in, same scope limitation as
    test_campaign_detector.py's determinism test.)
    """
    universe = {"a", "b", "c", "d", "e"}
    clusters_order_1 = [["a", "b", "c"], ["a", "d", "e"]]
    clusters_order_2 = [["a", "d", "e"], ["a", "b", "c"]]
    clusters_order_3 = list(reversed(clusters_order_1))

    def partition(labels):
        groups: dict = {}
        for value, label in labels.items():
            groups.setdefault(label, set()).add(value)
        return frozenset(frozenset(g) for g in groups.values())

    labels_1 = build_predicted_labels(clusters_order_1, universe)
    labels_2 = build_predicted_labels(clusters_order_2, universe)
    labels_3 = build_predicted_labels(clusters_order_3, universe)

    assert partition(labels_1) == partition(labels_2) == partition(labels_3)


def test_size_band_boundaries():
    assert size_band(3) == "3-5"
    assert size_band(5) == "3-5"
    assert size_band(6) == "6-10"
    assert size_band(50) == "11-50"
    assert size_band(51) == "50+"
    assert size_band(10000) == "50+"
    assert size_band(2) is None  # below MIN_CLUSTER, not a real band


def test_stratify_by_size_isolates_bands():
    clusters = [["a", "b", "c"], ["d", "e", "f", "g", "h", "i", "j"]]  # size 3, size 7
    true_labels = {"a": "fam1", "b": "fam1", "c": "fam1", "d": "fam2", "e": "fam2"}

    result = stratify_by_size(clusters, true_labels)

    assert result["3-5"]["n_clusters"] == 1
    assert result["6-10"]["n_clusters"] == 1
    assert result["11-50"]["n_clusters"] == 0
    assert result["3-5"]["ari"] == 1.0
