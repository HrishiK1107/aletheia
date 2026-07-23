import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from collections import Counter

db = SessionLocal()
ie = InfrastructureEngine()

clusters = CampaignDetector().find_connected_clusters()
fp_unweighted = ie.build_fingerprints(db)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)

def shared_types(cluster):
    counts = Counter()
    for ind in cluster:
        for feat in fp_weighted.get(ind, set()):
            counts[feat] += 1
    types = set()
    for feat, c in counts.items():
        if c >= 2:
            types.add(feat.split(":", 1)[0])
    return types

commodity_only, genuine, no_infra = [], [], []
for i, c in enumerate(clusters):
    types = shared_types(c)
    if types == {"org"}:
        commodity_only.append(i)
    elif types - {"org"}:
        genuine.append(i)
    else:
        no_infra.append(i)

def R_unweighted(cluster):
    counts = Counter()
    for ind in cluster:
        for feat in fp_unweighted.get(ind, set()):
            counts[feat] += 1
    shared = sum(1 for c in counts.values() if c >= 2)
    return min(shared / len(cluster), 1.0)

def R_weighted_v2(cluster):
    """mean inverse-degree of shared infrastructure -- no cluster-size normalization."""
    counts = Counter()
    for ind in cluster:
        for feat in fp_weighted.get(ind, set()):
            counts[feat] += 1
    shared_feats = [f for f, c in counts.items() if c >= 2]
    if not shared_feats:
        return 0.0
    weights = [1.0 / degrees.get(f, 1) for f in shared_feats]
    return sum(weights) / len(weights)

R_before = [R_unweighted(c) for c in clusters]
R_after_v2 = [R_weighted_v2(c) for c in clusters]

def stats(indices, label, arr_b, arr_a):
    if not indices:
        print(f"{label:15s} n=0"); return
    b = [arr_b[i] for i in indices]
    w = [arr_a[i] for i in indices]
    mb, mw = sum(b)/len(b), sum(w)/len(w)
    drop = 100*(mb-mw)/mb if mb else 0
    print(f"{label:15s}  before={mb:6.4f}  after={mw:6.4f}  drop={drop:6.1f}%  (n={len(indices)})")

print("=== v2 formula: mean(1/degree) over shared feature TYPES, no /cluster_size ===")
stats(commodity_only, "commodity-only", R_before, R_after_v2)
stats(genuine, "genuine", R_before, R_after_v2)
stats(list(range(len(clusters))), "ALL", R_before, R_after_v2)

big_i = max(range(len(clusters)), key=lambda i: len(clusters[i]))
print(f"\n1849-cluster: before={R_before[big_i]:.4f}  after_v2={R_after_v2[big_i]:.4f}")

# distribution check for genuine bucket
import statistics
g_after = [R_after_v2[i] for i in genuine]
print(f"\ngenuine after_v2: median={statistics.median(g_after):.4f} min={min(g_after):.4f} max={max(g_after):.4f}")
c_after = [R_after_v2[i] for i in commodity_only]
print(f"commodity after_v2: median={statistics.median(c_after):.4f} min={min(c_after):.4f} max={max(c_after):.4f}")
db.close()
