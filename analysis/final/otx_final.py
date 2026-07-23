import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from app.evaluation.ground_truth import build_otx_labels, find_largest_otx_pulse
from app.evaluation.baselines import group_by_feature_prefix, random_baseline
from app.evaluation.metrics import adjusted_rand_index, build_predicted_labels, pairwise_precision_recall

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()

outlier_id, outlier_n = find_largest_otx_pulse(db)
otx_with = build_otx_labels(db)
otx_without = build_otx_labels(db, exclude_pulse_id=outlier_id)
print(f"OTX labels: with_outlier={len(otx_with)}  without_outlier={len(otx_without)}  outlier_pulse={outlier_id} (n={outlier_n})", flush=True)

bfs_clusters = CampaignDetector().find_connected_clusters()
fp_unweighted = ie.build_fingerprints(db)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)
jaccard_clusters = ie.detect_clusters(db)
print(f"clustering+fingerprints done in {time.time()-t0:.1f}s ({len(bfs_clusters)} BFS clusters)", flush=True)

group_asn = group_by_feature_prefix(fp_unweighted, "asn:")
group_hosting = group_by_feature_prefix(fp_unweighted, "hosting:")
group_ip = group_by_feature_prefix(fp_weighted, "ip:")
random_clusters = random_baseline(list(fp_unweighted.keys()), num_clusters=len(bfs_clusters))

def confidence_filtered(cl, fp, deg):
    raw = [{"campaign_id": f"c{i}", "indicators": c, "size": len(c)} for i, c in enumerate(cl)]
    scored = scorer.score_campaigns(raw, fingerprints=fp, degrees=deg)
    return [c["indicators"] for c in scored if c["confidence"] >= 40]

reported = {
    "random_baseline": confidence_filtered(random_clusters, fp_unweighted, None),
    "group_by_asn": confidence_filtered(group_asn, fp_unweighted, None),
    "group_by_resolved_ip": confidence_filtered(group_ip, fp_unweighted, None),
    "group_by_hosting_provider": confidence_filtered(group_hosting, fp_unweighted, None),
    "jaccard_v1": confidence_filtered(jaccard_clusters, fp_unweighted, None),
    "bfs_unweighted": confidence_filtered(bfs_clusters, fp_unweighted, None),
    "bfs_weighted": confidence_filtered(bfs_clusters, fp_weighted, degrees),
}
print(f"confidence-filtering done in {time.time()-t0:.1f}s", flush=True)

def evaluate(clusters, labels):
    universe = {v for c in clusters for v in c} | set(labels)
    pred = build_predicted_labels(clusters, universe)
    ari = adjusted_rand_index(labels, pred)
    p, r = pairwise_precision_recall(labels, pred)
    return ari, p, r

for gt_name, gt_labels in [("OTX with outlier", otx_with), ("OTX without outlier", otx_without)]:
    scoped = {v: l for v, l in gt_labels.items() if fp_weighted.get(v)}
    print(f"\n=== {gt_name} (n={len(gt_labels)}, scoped={len(scoped)}, {100*len(scoped)/len(gt_labels):.1f}%) ===")
    print(f"{'method':28s}{'n':>6}{'ARI_full':>10}{'ARI_scop':>10}{'P_full':>9}{'R_full':>9}{'R_scop':>9}")
    for name, cl in reported.items():
        af, pf, rf = evaluate(cl, gt_labels)
        as_, ps, rs = evaluate(cl, scoped)
        print(f"{name:28s}{len(cl):6d}{af:10.4f}{as_:10.4f}{pf:9.4f}{rf:9.4f}{rs:9.4f}")

db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
