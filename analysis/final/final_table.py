import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from app.evaluation.ground_truth import build_threatfox_labels
from app.evaluation.baselines import group_by_feature_prefix, random_baseline
from app.evaluation.metrics import adjusted_rand_index, build_predicted_labels, pairwise_precision_recall

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()

threatfox_labels = build_threatfox_labels(db)
print(f"labels: {len(threatfox_labels)}", flush=True)

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

# SCOPE CONDITION -- input property, declared once, applied identically everywhere:
# an indicator carries >=1 enriched infrastructure attribute iff it has a
# non-empty entry in fp_weighted (built from IndicatorEnrichment; an indicator
# with an enrichment row but every field null maps to an empty set, correctly
# excluded; an indicator never enriched at all is simply absent, also excluded).
scoped_labels = {v: l for v, l in threatfox_labels.items() if fp_weighted.get(v)}
print(f"scope condition: {len(scoped_labels)}/{len(threatfox_labels)} labelled indicators carry >=1 enriched attribute ({100*len(scoped_labels)/len(threatfox_labels):.1f}%)", flush=True)

def confidence_filtered(clusters, fingerprints, deg):
    raw = [{"campaign_id": f"c{i}", "indicators": c, "size": len(c)} for i, c in enumerate(clusters)]
    scored = scorer.score_campaigns(raw, fingerprints=fingerprints, degrees=deg)
    return [c["indicators"] for c in scored if c["confidence"] >= 40]

def evaluate(clusters, labels):
    universe = {v for c in clusters for v in c} | set(labels)
    pred = build_predicted_labels(clusters, universe)
    ari = adjusted_rand_index(labels, pred)
    p, r = pairwise_precision_recall(labels, pred)
    return ari, p, r

# every method's "unweighted-scored, confidence-filtered" reported set --
# same treatment the two BFS rows already got, now applied to every baseline too
methods_all = {
    "random_baseline": random_clusters,
    "group_by_asn": group_asn,
    "group_by_resolved_ip": group_ip,
    "group_by_hosting_provider": group_hosting,
    "jaccard_v1": jaccard_clusters,
    "bfs_all_clusters": bfs_clusters,
}

methods_reported = {}
for name, clusters in methods_all.items():
    methods_reported[f"{name}__reported"] = confidence_filtered(clusters, fp_unweighted, None)
# weighted BFS reported row uses its own weighted fingerprints/degrees, as always
methods_reported["bfs_weighted__reported"] = confidence_filtered(bfs_clusters, fp_weighted, degrees)

print(f"\nconfidence-filtering done in {time.time()-t0:.1f}s", flush=True)

print("\n=== ALL CLUSTERS (unfiltered) -- full-population vs. scoped ARI ===")
print(f"{'method':30s}{'n':>6}{'ARI(full)':>12}{'ARI(scoped)':>13}{'P(full)':>10}{'R(full)':>10}")
results = {"scope": {"n_scoped": len(scoped_labels), "n_total": len(threatfox_labels)}, "all_clusters": {}, "reported": {}}
for name, clusters in methods_all.items():
    ari_f, p_f, r_f = evaluate(clusters, threatfox_labels)
    ari_s, p_s, r_s = evaluate(clusters, scoped_labels)
    print(f"{name:30s}{len(clusters):6d}{ari_f:12.4f}{ari_s:13.4f}{p_f:10.4f}{r_f:10.4f}")
    results["all_clusters"][name] = {"n": len(clusters), "ari_full": ari_f, "ari_scoped": ari_s, "p_full": p_f, "r_full": r_f}

print("\n=== REPORTED (confidence>=40, unweighted scoring except BFS-weighted row) -- full-population vs. scoped ARI ===")
print(f"{'method':30s}{'n':>6}{'ARI(full)':>12}{'ARI(scoped)':>13}{'P(full)':>10}{'R(full)':>10}")
for name, clusters in methods_reported.items():
    ari_f, p_f, r_f = evaluate(clusters, threatfox_labels)
    ari_s, p_s, r_s = evaluate(clusters, scoped_labels)
    print(f"{name:30s}{len(clusters):6d}{ari_f:12.4f}{ari_s:13.4f}{p_f:10.4f}{r_f:10.4f}")
    results["reported"][name] = {"n": len(clusters), "ari_full": ari_f, "ari_scoped": ari_s, "p_full": p_f, "r_full": r_f}

json.dump(results, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/final_table_results.json", "w"))
db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
