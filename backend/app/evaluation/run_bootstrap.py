"""
CONTEXT.md peer-review strengthening, Task 1: bootstrap 95% CIs for every
ARI figure in §8's Spine 3/4 tables (7 methods x 3 ground truths, full and
scoped).

Run with: python -m app.evaluation.run_bootstrap

Does NOT modify run_evaluation.py, metrics.py, or any other existing
evaluation code -- it imports run_evaluation.py's setup helpers
(`confidence_filtered_clusters`, `restrict_to_scope`) and reproduces the
identical clustering / fingerprint / confidence-filtering pipeline that
script already uses to build the same seven "__reported" methods §8 cites,
then layers bootstrap resampling (app/evaluation/bootstrap.py, new) on top.
Persists its own output (CONTEXT.md §7 "persist every run") to a timestamped
JSON file under evaluation_runs/.
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
from app.evaluation.bootstrap import (
    bootstrap_ari,
    sanity_check_bias_magnitude,
    verify_bootstrap_calibration,
)
from app.evaluation.ground_truth import (
    build_otx_labels,
    build_threatfox_labels,
    find_largest_otx_pulse,
)
from app.evaluation.metrics import build_predicted_labels
from app.evaluation.run_evaluation import (
    CONFIDENCE_THRESHOLD,
    confidence_filtered_clusters,
    restrict_to_scope,
)

N_ITERATIONS = 10000
SEED = 42  # matches baselines.py's own convention (random_baseline's default seed)
VERIFY_ITERATIONS = 2000  # smaller-scale calibration check, run once before the full grid


def build_methods_and_ground_truth():
    """
    Reproduces run_evaluation.main()'s setup for exactly the seven
    "__reported" (confidence-filtered) methods §8's Spine 3/4 tables cite --
    same function calls, same CONFIDENCE_THRESHOLD, same convention. Not a
    copy of the metric-computation logic (evaluate_method/evaluate_method_scoped
    stay in run_evaluation.py, untouched); this only rebuilds the inputs
    those functions already consume.
    """
    db = SessionLocal()
    ie = InfrastructureEngine()
    scorer = CampaignConfidenceScorer()

    print("Loading ground truth labels...", flush=True)
    threatfox_labels = build_threatfox_labels(db)
    outlier_pulse_id, _ = find_largest_otx_pulse(db)
    otx_labels_with_outlier = build_otx_labels(db)
    otx_labels_no_outlier = build_otx_labels(db, exclude_pulse_id=outlier_pulse_id)

    print("Clustering (BFS)...", flush=True)
    bfs_clusters = CampaignDetector().find_connected_clusters()

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

    print("Filtering all seven rows by confidence threshold (>=%d)..." % CONFIDENCE_THRESHOLD, flush=True)
    bfs_unweighted_reported = confidence_filtered_clusters(bfs_clusters, fp_unweighted, scorer, None)
    bfs_weighted_reported = confidence_filtered_clusters(bfs_clusters, fp_weighted, scorer, degrees)
    random_baseline_reported = confidence_filtered_clusters(random_clusters, fp_unweighted, scorer, None)
    group_asn_reported = confidence_filtered_clusters(group_asn, fp_unweighted, scorer, None)
    group_ip_reported = confidence_filtered_clusters(group_ip, fp_unweighted, scorer, None)
    group_hosting_reported = confidence_filtered_clusters(group_hosting, fp_unweighted, scorer, None)
    jaccard_reported = confidence_filtered_clusters(jaccard_clusters, fp_unweighted, scorer, None)

    methods = {
        "random_baseline__reported": random_baseline_reported,
        "group_by_asn__reported": group_asn_reported,
        "group_by_resolved_ip__reported": group_ip_reported,
        "group_by_hosting_provider__reported": group_hosting_reported,
        "jaccard_v1__reported": jaccard_reported,
        "bfs_unweighted_reported_only": bfs_unweighted_reported,
        "bfs_weighted_reported_only": bfs_weighted_reported,
    }

    ground_truths = {
        "threatfox": threatfox_labels,
        "otx_with_outlier": otx_labels_with_outlier,
        "otx_without_outlier": otx_labels_no_outlier,
    }

    db.close()
    return methods, ground_truths, fp_weighted


def main():
    t0 = time.time()
    methods, ground_truths, fp_weighted = build_methods_and_ground_truth()

    # --- Step 2: verify at small scale before running at full scale (task instruction) ---
    print(
        f"\nCalibration check ({VERIFY_ITERATIONS} iterations, seed={SEED}): "
        "bfs_unweighted_reported_only / threatfox / full population",
        flush=True,
    )
    calib_clusters = methods["bfs_unweighted_reported_only"]
    calib_true = ground_truths["threatfox"]
    calib_universe = {v for c in calib_clusters for v in c} | set(calib_true)
    calib_pred = build_predicted_labels(calib_clusters, calib_universe)
    calib_result = bootstrap_ari(calib_true, calib_pred, n_iterations=VERIFY_ITERATIONS, seed=SEED)
    strict_ok, strict_msg = verify_bootstrap_calibration(calib_result)
    bias_ok, bias_msg = sanity_check_bias_magnitude(calib_result)
    print(f"  strict Monte-Carlo-error check (expected to fail, see bootstrap.py docstring): {strict_msg}", flush=True)
    print(f"  bias-magnitude sanity gate (actual go/no-go): {bias_msg}", flush=True)
    if not bias_ok:
        print(
            "\nBIAS-MAGNITUDE CHECK FAILED -- this is larger than every previously "
            "characterised case (synthetic data to n=60,000, real ThreatFox slice). "
            "Stopping, not running at scale -- this looks like a real bug, not the "
            "known artifact."
        )
        sys.exit(1)
    print(
        "  Proceeding to the full 10,000-iteration grid, reporting the pivotal "
        "(bias-corrected) interval per the diagnosed percentile bias.",
        flush=True,
    )

    # --- Step 3: full grid, all 7 methods x 3 ground truths x (full, scoped) ---
    results = {
        "generated_at": datetime.now(UTC).isoformat(),
        "n_iterations": N_ITERATIONS,
        "seed": SEED,
        "ci_level": 0.95,
        "reported_ci": "pivotal",
        "calibration_check": {
            "n_iterations": VERIFY_ITERATIONS,
            "strict_monte_carlo_check": {"passed": strict_ok, "detail": strict_msg},
            "bias_magnitude_gate": {"passed": bias_ok, "detail": bias_msg},
        },
        "ground_truth": {},
    }

    for gt_name, gt_labels in ground_truths.items():
        print(f"\nBootstrapping against {gt_name} ground truth...", flush=True)
        results["ground_truth"][gt_name] = {}

        for method_name, clusters in methods.items():
            universe_full = {v for c in clusters for v in c} | set(gt_labels)
            pred_full = build_predicted_labels(clusters, universe_full)

            scoped_labels = restrict_to_scope(gt_labels, fp_weighted)
            universe_scoped = {v for c in clusters for v in c} | set(scoped_labels)
            pred_scoped = build_predicted_labels(clusters, universe_scoped)

            t_method = time.time()
            full_ci = bootstrap_ari(gt_labels, pred_full, n_iterations=N_ITERATIONS, seed=SEED)
            scoped_ci = bootstrap_ari(scoped_labels, pred_scoped, n_iterations=N_ITERATIONS, seed=SEED)

            results["ground_truth"][gt_name][method_name] = {"full": full_ci, "scoped": scoped_ci}

            print(
                f"  {method_name:38s} "
                f"full ARI={full_ci['point_estimate']:.4f} "
                f"pivotal=[{full_ci['pivotal_ci_lower']:.4f}, {full_ci['pivotal_ci_upper']:.4f}] "
                f"pctile=[{full_ci['percentile_ci_lower']:.4f}, {full_ci['percentile_ci_upper']:.4f}]  "
                f"| scoped ARI={scoped_ci['point_estimate']:.4f} "
                f"pivotal=[{scoped_ci['pivotal_ci_lower']:.4f}, {scoped_ci['pivotal_ci_upper']:.4f}] "
                f"pctile=[{scoped_ci['percentile_ci_lower']:.4f}, {scoped_ci['percentile_ci_upper']:.4f}]  "
                f"({time.time() - t_method:.1f}s)",
                flush=True,
            )

    out_dir = Path(__file__).resolve().parents[3] / "evaluation_runs"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"bootstrap_ci_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nWrote {out_path}")
    print(f"Total runtime: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    from app.core.hash_safety import ensure_deterministic_hashing

    ensure_deterministic_hashing()
    sys.exit(main())
