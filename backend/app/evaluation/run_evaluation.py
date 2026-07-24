"""
CONTEXT.md item 7: builds the §3 results table.

Run with: python -m app.evaluation.run_evaluation

Persists its own output (CONTEXT.md §7 "persist every run") to a
timestamped JSON file under evaluation_runs/, in addition to printing the
table, since this is exactly the kind of run-once, cite-in-the-paper result
that must not be lost by re-running the pipeline.
"""

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from app.correlation.campaign_detector import CampaignDetector
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.db.postgres import SessionLocal
from app.evaluation.baselines import group_by_feature_prefix, random_baseline
from app.evaluation.diagnostics import (
    connectivity_components,
    connectivity_threshold_sweep,
    label_infra_cohesion,
)
from app.evaluation.ground_truth import (
    build_otx_labels,
    build_threatfox_labels,
    find_largest_otx_pulse,
)
from app.evaluation.metrics import (
    adjusted_rand_index,
    build_predicted_labels,
    pairwise_precision_recall,
    stratify_by_size,
)

CONFIDENCE_THRESHOLD = 40  # CampaignConfidenceScorer.classify_confidence's medium/low boundary

# Matches analysis/final/diagnose_ari.py's original ad hoc sweep (CONTEXT.md
# §6d) -- same fingerprint choice (weighted) and threshold list, so this
# wiring reproduces those numbers rather than silently picking new ones.
DIAGNOSTIC_DEGREE_THRESHOLDS: list[float | None] = [1, 2, 3, 5, 10, 20, 50, 100, 500, None]

# CONTEXT.md Spine 4 (analysis/final/population_check.py): the five families
# whose achievable-vs-actual pairwise recall gap was measured, population-
# matched via explicit Postgres/Neo4j intersection. ThreatFox-only -- this
# specific analysis was never run against OTX.
SPINE4_TARGET_FAMILIES = ["unknown", "js.clearfake", "win.cobalt_strike", "win.vidar", "win.adaptix_c2"]


def evaluate_method(name: str, clusters: list[list[str]], true_labels: dict) -> dict:
    universe = {v for c in clusters for v in c} | set(true_labels)
    pred = build_predicted_labels(clusters, universe)

    ari = adjusted_rand_index(true_labels, pred)
    precision, recall = pairwise_precision_recall(true_labels, pred)
    strata = stratify_by_size(clusters, true_labels)

    return {
        "method": name,
        "n_clusters": len(clusters),
        "n_members": sum(len(c) for c in clusters),
        "ari": ari,
        "precision": precision,
        "recall": recall,
        "by_size_band": strata,
    }


def restrict_to_scope(true_labels: dict, fp_weighted: dict) -> dict:
    """
    CONTEXT.md §6g's scope condition, ported from analysis/final/scoped_pr.py
    and analysis/final/final_table.py: an indicator is in scope iff it
    carries >=1 enriched infrastructure attribute --
    `InfrastructureEngine.build_weighted_fingerprints()` returns a non-empty
    feature set for it (an indicator with an enrichment row but every field
    null maps to an empty set and is correctly excluded, same as an
    indicator never enriched at all). Declared once, applied identically to
    every method and every ground truth -- an input property, not tuned per
    method.

    Strictly additive alongside evaluate_method()'s existing full-population
    computation above: this function does not change how that is computed,
    it only produces a second, smaller `true_labels`-shaped dict that
    `evaluate_method_scoped()` below runs through the exact same metric
    functions.
    """
    return {value: label for value, label in true_labels.items() if fp_weighted.get(value)}


def evaluate_method_scoped(clusters: list[list[str]], scoped_labels: dict) -> dict:
    """
    Same computation as evaluate_method(), restricted to the scope
    condition's labelled subset (`scoped_labels`, from restrict_to_scope()
    above) instead of the full ground truth. Precision is mathematically
    identical to the full-population value either way (CONTEXT.md §6g's
    proof: an out-of-scope indicator always lands as its own predicted
    singleton, contributing zero pairs to precision's numerator or
    denominator) -- computed here anyway, matching
    analysis/final/scoped_pr.py, as a live internal-consistency check each
    run performs rather than a proof cited once and assumed forever.
    """
    universe = {v for c in clusters for v in c} | set(scoped_labels)
    pred = build_predicted_labels(clusters, universe)

    ari = adjusted_rand_index(scoped_labels, pred)
    precision, recall = pairwise_precision_recall(scoped_labels, pred)

    return {
        "n_scoped": len(scoped_labels),
        "ari_scoped": ari,
        "precision_scoped": precision,
        "recall_scoped": recall,
    }


def confidence_filtered_clusters(
    clusters: list[list[str]],
    fingerprints: dict,
    scorer: CampaignConfidenceScorer,
    degrees: dict | None,
) -> list[list[str]]:
    """Only clusters whose confidence score clears the medium-confidence
    threshold count as "reported campaigns" -- see CONTEXT.md item 7's
    methodology note on why this is how the two BFS rows are told apart."""
    raw = [{"campaign_id": f"c{i}", "indicators": c, "size": len(c)} for i, c in enumerate(clusters)]
    scored = scorer.score_campaigns(raw, fingerprints=fingerprints, degrees=degrees)
    return [c["indicators"] for c in scored if c["confidence"] >= CONFIDENCE_THRESHOLD]


def is_commodity_only(cluster: list[str], weighted_fingerprints: dict) -> bool:
    """CONTEXT.md item 2.1's classification: only 'org' shared, nothing else."""
    from collections import Counter

    counts: Counter = Counter()
    for value in cluster:
        for feat in weighted_fingerprints.get(value, set()):
            counts[feat] += 1
    shared_types = {f.split(":", 1)[0] for f, c in counts.items() if c >= 2}
    return shared_types == {"org"}


def _family_pairwise_recall(labels: dict, clusters: list[list[str]]) -> float:
    """Matches analysis/final/population_check.py's pairwise_recall() helper exactly."""
    universe = {v for c in clusters for v in c} | set(labels)
    pred = build_predicted_labels(clusters, universe)
    _, recall = pairwise_precision_recall(labels, pred)
    return recall


def achievable_vs_actual_by_family(
    threatfox_labels: dict,
    fp_weighted: dict,
    degrees,
    bfs_clusters: list[list[str]],
    bfs_weighted_reported: list[list[str]],
) -> dict:
    """
    CONTEXT.md Spine 4, ported from analysis/final/population_check.py: for
    each of SPINE4_TARGET_FAMILIES, the achievable ceiling (unrestricted
    Postgres connectivity, `connectivity_components(..., max_degree=None)`)
    vs. the actual pairwise recall (Neo4j BFS, weighted/reported clusters),
    both on the full population and restricted to the explicit
    Postgres-connectivity/Neo4j-BFS population intersection -- the
    population-mismatch correction CONTEXT.md §6i found necessary (the two
    sides are measurably different populations; correcting widens every
    gap, it does not narrow any of them). ThreatFox-only, matching the
    reference script -- this analysis was never run against OTX.

    Deliberately does NOT include the d/k traversal sweep
    (analysis/final/dk_sweep_corrected.py): that sweep re-runs BFS
    clustering 9 times (d in {1,2,3} x k in {2,3,5}, each a full graph
    traversal costing roughly as much as the one default-parameter BFS run
    this entrypoint already does), for a conclusion already settled and
    explicitly marked "not to be re-tested without a new reason" in
    CONTEXT.md's Spine 4 write-up. Adding a ~10x-slower BFS re-run to every
    routine invocation of the results-table entrypoint for an
    already-settled diagnostic is not a reproducibility gap worth closing
    here; see CONTEXT.md's final reproduction instructions for the exact
    command that reproduces the sweep on demand instead.
    """
    conn_clusters = connectivity_components(fp_weighted, degrees, max_degree=None)
    conn_clusters = [c for c in conn_clusters if len(c) >= 2]

    postgres_pop = {v for c in conn_clusters for v in c}
    neo4j_pop = {v for c in bfs_clusters for v in c}
    intersection = postgres_pop & neo4j_pop

    by_family = {}
    for fam in SPINE4_TARGET_FAMILIES:
        labels = {v: label for v, label in threatfox_labels.items() if label == fam}

        achievable_full = _family_pairwise_recall(labels, conn_clusters)
        actual_full = _family_pairwise_recall(labels, bfs_weighted_reported)

        labels_int = {v: label for v, label in labels.items() if v in intersection}
        conn_clusters_int = [[v for v in c if v in intersection] for c in conn_clusters]
        conn_clusters_int = [c for c in conn_clusters_int if len(c) >= 2]
        reported_int = [[v for v in c if v in intersection] for c in bfs_weighted_reported]
        reported_int = [c for c in reported_int if len(c) >= 2]

        achievable_int = (
            _family_pairwise_recall(labels_int, conn_clusters_int) if labels_int else float("nan")
        )
        actual_int = (
            _family_pairwise_recall(labels_int, reported_int) if labels_int else float("nan")
        )

        by_family[fam] = {
            "n_labelled": len(labels),
            "n_labelled_intersection": len(labels_int),
            "achievable_full": achievable_full,
            "actual_full": actual_full,
            "achievable_intersection": achievable_int,
            "actual_intersection": actual_int,
            "gap_intersection": (
                achievable_int - actual_int
                if achievable_int == achievable_int and actual_int == actual_int
                else float("nan")
            ),
        }

    return {
        "postgres_population": len(postgres_pop),
        "neo4j_population": len(neo4j_pop),
        "intersection_population": len(intersection),
        "families": by_family,
    }


def main():
    t0 = time.time()
    db = SessionLocal()
    ie = InfrastructureEngine()
    scorer = CampaignConfidenceScorer()

    print("Loading ground truth labels...", flush=True)
    threatfox_labels = build_threatfox_labels(db)
    outlier_pulse_id, outlier_count = find_largest_otx_pulse(db)
    otx_labels_with_outlier = build_otx_labels(db)
    otx_labels_no_outlier = build_otx_labels(db, exclude_pulse_id=outlier_pulse_id)
    print(
        f"  ThreatFox: {len(threatfox_labels)} labelled indicators, "
        f"OTX: {len(otx_labels_with_outlier)} ({len(otx_labels_no_outlier)} excluding "
        f"outlier pulse {outlier_pulse_id!r}, {outlier_count} members)",
        flush=True,
    )

    print("Clustering (BFS)...", flush=True)
    bfs_clusters = CampaignDetector().find_connected_clusters()
    print(f"  {len(bfs_clusters)} clusters in {time.time() - t0:.1f}s", flush=True)

    print("Building fingerprints...", flush=True)
    fp_unweighted = ie.build_fingerprints(db)
    fp_weighted = ie.build_weighted_fingerprints(db)
    degrees = ie.compute_feature_degrees(fp_weighted)

    print("Clustering (Jaccard v1 baseline)...", flush=True)
    jaccard_clusters = ie.detect_clusters(db)

    print("Building GROUP BY baselines...", flush=True)
    group_asn = group_by_feature_prefix(fp_unweighted, "asn:")
    group_hosting = group_by_feature_prefix(fp_unweighted, "hosting:")
    group_ip = group_by_feature_prefix(fp_weighted, "ip:")

    all_indicator_values = list(fp_unweighted.keys())
    random_clusters = random_baseline(all_indicator_values, num_clusters=len(bfs_clusters))

    print("Filtering BFS rows by confidence threshold...", flush=True)
    bfs_unweighted_reported = confidence_filtered_clusters(bfs_clusters, fp_unweighted, scorer, None)
    bfs_weighted_reported = confidence_filtered_clusters(bfs_clusters, fp_weighted, scorer, degrees)

    print(
        "Filtering remaining baselines by confidence threshold too (CONTEXT.md "
        "§6g's apples-to-apples extension, analysis/final/final_table.py -- same "
        "unweighted-fingerprints/degrees=None convention as bfs_unweighted_reported "
        "above)...",
        flush=True,
    )
    random_baseline_reported = confidence_filtered_clusters(random_clusters, fp_unweighted, scorer, None)
    group_asn_reported = confidence_filtered_clusters(group_asn, fp_unweighted, scorer, None)
    group_ip_reported = confidence_filtered_clusters(group_ip, fp_unweighted, scorer, None)
    group_hosting_reported = confidence_filtered_clusters(group_hosting, fp_unweighted, scorer, None)
    jaccard_reported = confidence_filtered_clusters(jaccard_clusters, fp_unweighted, scorer, None)

    print("Computing commodity-only FP rates...", flush=True)
    commodity_flags_all = [is_commodity_only(c, fp_weighted) for c in bfs_clusters]
    commodity_flags_unweighted_reported = [
        is_commodity_only(c, fp_weighted) for c in bfs_unweighted_reported
    ]
    commodity_flags_weighted_reported = [
        is_commodity_only(c, fp_weighted) for c in bfs_weighted_reported
    ]

    methods = {
        "random_baseline": random_clusters,
        "group_by_asn": group_asn,
        "group_by_resolved_ip": group_ip,
        "group_by_hosting_provider": group_hosting,
        "jaccard_v1": jaccard_clusters,
        "bfs_unweighted_all_clusters": bfs_clusters,
        "bfs_unweighted_reported_only": bfs_unweighted_reported,
        "bfs_weighted_reported_only": bfs_weighted_reported,
    }

    # CONTEXT.md §6g's apples-to-apples extension (analysis/final/final_table.py):
    # every baseline above gets its own confidence-filtered "__reported" row too,
    # not just the two existing BFS ones. Additive -- the eight keys above are
    # unchanged.
    methods["random_baseline__reported"] = random_baseline_reported
    methods["group_by_asn__reported"] = group_asn_reported
    methods["group_by_resolved_ip__reported"] = group_ip_reported
    methods["group_by_hosting_provider__reported"] = group_hosting_reported
    methods["jaccard_v1__reported"] = jaccard_reported

    results = {"generated_at": datetime.now(UTC).isoformat(), "ground_truth": {}}

    for gt_name, gt_labels in [
        ("threatfox", threatfox_labels),
        ("otx_with_outlier", otx_labels_with_outlier),
        ("otx_without_outlier", otx_labels_no_outlier),
    ]:
        print(f"\nEvaluating against {gt_name} ground truth...", flush=True)
        results["ground_truth"][gt_name] = {}

        # CONTEXT.md §6g's scope condition -- additive alongside the existing
        # full-population evaluate_method() call below, not a replacement for it.
        scoped_labels = restrict_to_scope(gt_labels, fp_weighted)
        print(
            f"  scope condition: {len(scoped_labels)}/{len(gt_labels)} labelled "
            f"indicators carry >=1 enriched attribute "
            f"({100 * len(scoped_labels) / len(gt_labels):.1f}%)",
            flush=True,
        )

        for method_name, clusters in methods.items():
            r = evaluate_method(method_name, clusters, gt_labels)
            r["scoped"] = evaluate_method_scoped(clusters, scoped_labels)
            results["ground_truth"][gt_name][method_name] = r
            print(
                f"  {method_name:32s} n={r['n_clusters']:5d}  "
                f"ARI={r['ari']:.4f}  P={r['precision']:.4f}  R={r['recall']:.4f}  "
                f"| scoped ARI={r['scoped']['ari_scoped']:.4f}  "
                f"R={r['scoped']['recall_scoped']:.4f}"
            )

    print("\nComputing diagnostics (label/infrastructure cohesion, connectivity-degree-threshold sweep)...", flush=True)
    results["diagnostics"] = {}
    for gt_name, gt_labels in [
        ("threatfox", threatfox_labels),
        ("otx_with_outlier", otx_labels_with_outlier),
        ("otx_without_outlier", otx_labels_no_outlier),
    ]:
        cohesion = label_infra_cohesion(gt_labels, fp_weighted, top_n=10)
        sweep = connectivity_threshold_sweep(
            fp_weighted, degrees, gt_labels, DIAGNOSTIC_DEGREE_THRESHOLDS
        )
        results["diagnostics"][gt_name] = {"label_infra_cohesion": cohesion, "connectivity_sweep": sweep}
        best = max(sweep, key=lambda r: r["ari"])
        print(
            f"  {gt_name}: best connectivity-sweep ARI={best['ari']:.4f} "
            f"at threshold={best['threshold']} (n_components={best['n_components']})",
            flush=True,
        )

    print(
        "\nComputing Spine 4 achievable-vs-actual pairwise recall by family "
        "(ThreatFox only, analysis/final/population_check.py)...",
        flush=True,
    )
    results["spine4_achievable_vs_actual"] = achievable_vs_actual_by_family(
        threatfox_labels, fp_weighted, degrees, bfs_clusters, bfs_weighted_reported
    )
    pop = results["spine4_achievable_vs_actual"]
    print(
        f"  populations: postgres={pop['postgres_population']} "
        f"neo4j={pop['neo4j_population']} intersection={pop['intersection_population']}",
        flush=True,
    )
    for fam, row in pop["families"].items():
        print(
            f"  {fam:20s} achievable(int)={row['achievable_intersection']:.4f}  "
            f"actual(int)={row['actual_intersection']:.4f}  "
            f"gap={row['gap_intersection']:.4f}  (n_int={row['n_labelled_intersection']})",
            flush=True,
        )

    results["commodity_fp_rate"] = {
        "bfs_all_clusters": sum(commodity_flags_all) / len(bfs_clusters) if bfs_clusters else 0,
        "bfs_unweighted_reported": (
            sum(commodity_flags_unweighted_reported) / len(bfs_unweighted_reported)
            if bfs_unweighted_reported
            else 0
        ),
        "bfs_weighted_reported": (
            sum(commodity_flags_weighted_reported) / len(bfs_weighted_reported)
            if bfs_weighted_reported
            else 0
        ),
        "n_reported_unweighted": len(bfs_unweighted_reported),
        "n_reported_weighted": len(bfs_weighted_reported),
    }

    print(f"\nCommodity-only FP rate (all {len(bfs_clusters)} BFS clusters): "
          f"{results['commodity_fp_rate']['bfs_all_clusters']:.4f}")
    print(f"Commodity-only FP rate (unweighted, reported/confidence>={CONFIDENCE_THRESHOLD}, "
          f"n={len(bfs_unweighted_reported)}): "
          f"{results['commodity_fp_rate']['bfs_unweighted_reported']:.4f}")
    print(f"Commodity-only FP rate (weighted, reported/confidence>={CONFIDENCE_THRESHOLD}, "
          f"n={len(bfs_weighted_reported)}): "
          f"{results['commodity_fp_rate']['bfs_weighted_reported']:.4f}")

    out_dir = Path(__file__).resolve().parents[3] / "evaluation_runs"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"item7_eval_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nWrote {out_path}")
    print(f"Total runtime: {time.time() - t0:.1f}s")

    db.close()


if __name__ == "__main__":
    from app.core.hash_safety import ensure_deterministic_hashing

    ensure_deterministic_hashing()
    sys.exit(main())
