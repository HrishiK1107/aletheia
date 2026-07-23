import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()

print("clustering...", flush=True)
clusters = CampaignDetector().find_connected_clusters()
print(f"  {len(clusters)} clusters in {time.time()-t0:.1f}s", flush=True)

t1 = time.time()
print("building unweighted fingerprints...", flush=True)
fp_unweighted = ie.build_fingerprints(db)
print(f"  {len(fp_unweighted)} in {time.time()-t1:.1f}s", flush=True)

t2 = time.time()
print("building weighted fingerprints...", flush=True)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)
print(f"  {len(fp_weighted)} fp, {len(degrees)} distinct features, in {time.time()-t2:.1f}s", flush=True)

raw = [{"campaign_id": f"c{i}", "indicators": c, "size": len(c)} for i, c in enumerate(clusters)]

scored_baseline = scorer.score_campaigns(raw, fingerprints=fp_unweighted)
scored_weighted = scorer.score_campaigns(raw, fingerprints=fp_weighted, degrees=degrees)

# classify each cluster by which feature TYPES are shared by >=2 members, using weighted (merged) fingerprints
def shared_types(cluster):
    from collections import Counter
    counts = Counter()
    for ind in cluster:
        for feat in fp_weighted.get(ind, set()):
            counts[feat] += 1
    types = set()
    for feat, c in counts.items():
        if c >= 2:
            types.add(feat.split(":", 1)[0])
    return types

commodity_only = []
genuine = []
no_infra = []
for i, c in enumerate(clusters):
    types = shared_types(c)
    if types == {"org"}:
        commodity_only.append(i)
    elif types - {"org"}:
        genuine.append(i)
    else:
        no_infra.append(i)

print(f"\ncommodity-only (org only): {len(commodity_only)} / {len(clusters)} ({100*len(commodity_only)/len(clusters):.1f}%)")
print(f"genuine (org + something else, or something else alone): {len(genuine)} / {len(clusters)} ({100*len(genuine)/len(clusters):.1f}%)")
print(f"no shared infra type at all: {len(no_infra)} / {len(clusters)} ({100*len(no_infra)/len(clusters):.1f}%)")

def stats(indices):
    if not indices:
        return None
    b = [scored_baseline[i]["confidence"] for i in indices]
    w = [scored_weighted[i]["confidence"] for i in indices]
    mean_b = sum(b)/len(b)
    mean_w = sum(w)/len(w)
    drop = 100*(mean_b-mean_w)/mean_b if mean_b else 0
    return mean_b, mean_w, drop

for name, idx in [("commodity-only", commodity_only), ("genuine", genuine), ("no-infra", no_infra), ("ALL", list(range(len(clusters))))]:
    s = stats(idx)
    if s:
        print(f"{name:15s}  mean_before={s[0]:6.2f}  mean_after={s[1]:6.2f}  drop={s[2]:5.1f}%  (n={len(idx)})")

# the 1849-cluster specifically
big_i = max(range(len(clusters)), key=lambda i: len(clusters[i]))
print(f"\n1849-cluster (idx {big_i}, size {len(clusters[big_i])}): before={scored_baseline[big_i]['confidence']}  after={scored_weighted[big_i]['confidence']}")

json.dump({
    "commodity_only": len(commodity_only), "genuine": len(genuine), "no_infra": len(no_infra),
    "total": len(clusters),
    "stats": {n: stats(i) for n, i in [("commodity_only", commodity_only), ("genuine", genuine), ("no_infra", no_infra), ("all", list(range(len(clusters))))]},
    "big_cluster_before": scored_baseline[big_i]["confidence"],
    "big_cluster_after": scored_weighted[big_i]["confidence"],
}, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/degree_weighting_results.json", "w"))
db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
