import sys, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from collections import Counter

db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()

clusters = CampaignDetector().find_connected_clusters()
fp_unweighted = ie.build_fingerprints(db)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)

def shared_feats(cluster):
    counts = Counter()
    for ind in cluster:
        for feat in fp_weighted.get(ind, set()):
            counts[feat] += 1
    return [f for f, c in counts.items() if c >= 2]

R_before = [scorer._infrastructure_reuse_ratio(c, fp_unweighted) for c in clusters]
R_after = [scorer._infrastructure_reuse_ratio_weighted(c, fp_weighted, degrees) for c in clusters]

LOW, HIGH = 10, 100
low_exp, med_exp, high_exp, no_infra = [], [], [], []
max_deg_per_cluster = []
for i, c in enumerate(clusters):
    feats = shared_feats(c)
    if not feats:
        no_infra.append(i)
        max_deg_per_cluster.append(None)
        continue
    max_deg = max(degrees.get(f, 1) for f in feats)
    max_deg_per_cluster.append(max_deg)
    if max_deg <= LOW:
        low_exp.append(i)
    elif max_deg <= HIGH:
        med_exp.append(i)
    else:
        high_exp.append(i)

def stats(indices, label):
    if not indices:
        print(f"{label:30s} n=0"); return None
    b = [R_before[i] for i in indices]; w = [R_after[i] for i in indices]
    mb, mw = sum(b)/len(b), sum(w)/len(w)
    drop = 100*(mb-mw)/mb if mb else 0
    print(f"{label:30s}  R_before={mb:6.4f}  R_after={mw:6.4f}  drop={drop:6.1f}%  (n={len(indices)}, {100*len(indices)/len(clusters):.1f}%)")
    return mb, mw, drop

print(f"total clusters: {len(clusters)}\n")
print("=== bucketed by measured max shared-feature degree (commodity exposure) ===")
s_low = stats(low_exp, f"low exposure (max deg<={LOW})")
s_med = stats(med_exp, f"medium exposure ({LOW}<max deg<={HIGH})")
s_high = stats(high_exp, f"high exposure (max deg>{HIGH})")
stats(no_infra, "no shared infra (excluded/n.a.)")

print("\nmonotonicity check (drop%): low < medium < high expected")
print(f"  low={s_low[2]:.1f}%  medium={s_med[2]:.1f}%  high={s_high[2]:.1f}%")
print(f"  monotonic: {s_low[2] <= s_med[2] <= s_high[2]}")

# 1849-cluster rank by absolute R drop
abs_drops = [(R_before[i] - R_after[i], i, len(clusters[i])) for i in range(len(clusters))]
abs_drops.sort(reverse=True)
big_i = max(range(len(clusters)), key=lambda i: len(clusters[i]))
rank = [i for i, (d, idx, sz) in enumerate(abs_drops) if idx == big_i][0]
print(f"\n1,849-cluster: R_before={R_before[big_i]:.4f}  R_after={R_after[big_i]:.4f}  abs_drop={R_before[big_i]-R_after[big_i]:.4f}")
print(f"  rank by absolute R(C) drop: #{rank+1} of {len(clusters)}")
print(f"  top 5 by absolute R(C) drop:")
for d, idx, sz in abs_drops[:5]:
    print(f"    cluster idx={idx} size={sz}  R_before={R_before[idx]:.4f} R_after={R_after[idx]:.4f} abs_drop={d:.4f}")

json.dump({
    "low": s_low, "medium": s_med, "high": s_high,
    "no_infra_n": len(no_infra),
    "big_cluster_rank": rank+1, "big_cluster_R_before": R_before[big_i], "big_cluster_R_after": R_after[big_i],
    "top5_by_abs_drop": [(idx, sz, R_before[idx], R_after[idx]) for d, idx, sz in abs_drops[:5]],
}, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/degree_bucket_final_results.json", "w"))
db.close()
