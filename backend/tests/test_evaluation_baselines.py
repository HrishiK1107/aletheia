from app.evaluation.baselines import group_by_feature_prefix, random_baseline


def test_random_baseline_is_deterministic():
    values = [f"v{i}" for i in range(20)]

    a = random_baseline(values, num_clusters=4, seed=42)
    b = random_baseline(values, num_clusters=4, seed=42)

    assert a == b


def test_random_baseline_different_seed_differs():
    values = [f"v{i}" for i in range(20)]

    a = random_baseline(values, num_clusters=4, seed=1)
    b = random_baseline(values, num_clusters=4, seed=2)

    assert a != b


def test_random_baseline_drops_undersized_groups():
    values = [f"v{i}" for i in range(5)]

    # 5 values into 5 clusters -> every group has 1 member, all below MIN_CLUSTER=3
    clusters = random_baseline(values, num_clusters=5, seed=42)

    assert clusters == []


def test_group_by_feature_prefix_groups_shared_values():
    fingerprints = {
        "a.com": {"asn:AS1", "registrar:X"},
        "b.com": {"asn:AS1", "registrar:Y"},
        "c.com": {"asn:AS1"},
        "d.com": {"asn:AS2"},  # only 1 member on AS2 -- below MIN_CLUSTER
    }

    clusters = group_by_feature_prefix(fingerprints, "asn:")

    assert len(clusters) == 1
    assert sorted(clusters[0]) == ["a.com", "b.com", "c.com"]


def test_group_by_feature_prefix_multi_valued_membership():
    """An indicator with two IPs contributes to both IP groups."""
    fingerprints = {
        "a.com": {"ip:1.1.1.1", "ip:2.2.2.2"},
        "b.com": {"ip:1.1.1.1"},
        "c.com": {"ip:1.1.1.1"},
        "d.com": {"ip:2.2.2.2"},
        "e.com": {"ip:2.2.2.2"},
    }

    clusters = group_by_feature_prefix(fingerprints, "ip:")

    groups = {tuple(sorted(c)) for c in clusters}
    assert ("a.com", "b.com", "c.com") in groups
    assert ("a.com", "d.com", "e.com") in groups
