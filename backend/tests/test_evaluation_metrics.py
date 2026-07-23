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
