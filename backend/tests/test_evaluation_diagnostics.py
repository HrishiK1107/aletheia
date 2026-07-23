from app.evaluation.diagnostics import connectivity_components, label_infra_cohesion


def test_label_infra_cohesion_distinguishes_unenriched_from_orthogonal():
    labels = {"a": "fam1", "b": "fam1", "c": "fam1", "d": "fam2", "e": "fam2"}
    fingerprints = {
        "a": {"org:X"},
        "b": {"org:X"},  # a & b cohesive (share org:X within fam1)
        "c": set(),  # c never enriched
        "d": {"org:Y"},
        "e": {"org:Z"},  # d & e enriched but share nothing -- orthogonal, not unenriched
    }

    result = label_infra_cohesion(labels, fingerprints, top_n=10)
    by_label = {r["label"]: r for r in result}

    fam1 = by_label["fam1"]
    assert fam1["n_total"] == 3
    assert fam1["n_enriched"] == 2
    assert fam1["n_cohesive"] == 2
    assert fam1["cohesion_among_enriched"] == 1.0

    fam2 = by_label["fam2"]
    assert fam2["n_enriched"] == 2
    assert fam2["n_cohesive"] == 0
    assert fam2["cohesion_among_enriched"] == 0.0


def test_label_infra_cohesion_ranks_by_size():
    labels = {f"i{i}": "big" for i in range(5)} | {"j0": "small", "j1": "small"}
    fingerprints = {k: set() for k in labels}

    result = label_infra_cohesion(labels, fingerprints, top_n=1)

    assert len(result) == 1
    assert result[0]["label"] == "big"


def test_connectivity_components_unrestricted_merges_via_hub():
    fingerprints = {
        "a": {"org:HUB", "ns:rare1"},
        "b": {"org:HUB", "ns:rare2"},
        "c": {"org:HUB"},
    }
    degrees = {"org:HUB": 3, "ns:rare1": 1, "ns:rare2": 1}

    components = connectivity_components(fingerprints, degrees, max_degree=None)

    assert len(components) == 1
    assert sorted(components[0]) == ["a", "b", "c"]


def test_connectivity_components_degree_restricted_breaks_hub():
    fingerprints = {
        "a": {"org:HUB", "ns:rare1"},
        "b": {"org:HUB", "ns:rare2"},
        "c": {"org:HUB"},
        "d": {"ns:rare1"},  # shares rare1 with a, nothing else
    }
    degrees = {"org:HUB": 3, "ns:rare1": 2, "ns:rare2": 1}

    # exclude org:HUB (degree 3) by capping at max_degree=2
    components = connectivity_components(fingerprints, degrees, max_degree=2)

    groups = {frozenset(c) for c in components}
    assert frozenset({"a", "d"}) in groups  # still connected via rare ns
    assert frozenset({"b"}) in groups  # hub edge removed, isolated
    assert frozenset({"c"}) in groups  # hub edge removed, isolated
