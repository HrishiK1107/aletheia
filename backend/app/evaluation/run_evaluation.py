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

    results = {"generated_at": datetime.now(UTC).isoformat(), "ground_truth": {}}

    for gt_name, gt_labels in [
        ("threatfox", threatfox_labels),
        ("otx_with_outlier", otx_labels_with_outlier),
        ("otx_without_outlier", otx_labels_no_outlier),
    ]:
        print(f"\nEvaluating against {gt_name} ground truth...", flush=True)
        results["ground_truth"][gt_name] = {}
        for method_name, clusters in methods.items():
            r = evaluate_method(method_name, clusters, gt_labels)
            results["ground_truth"][gt_name][method_name] = r
            print(
                f"  {method_name:32s} n={r['n_clusters']:5d}  "
                f"ARI={r['ari']:.4f}  P={r['precision']:.4f}  R={r['recall']:.4f}"
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
