import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer

db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()

clusters = CampaignDetector().find_connected_clusters()
fp_unweighted = ie.build_fingerprints(db)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)

from collections import Counter
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

R_before = []
R_after = []
for c in clusters:
    R_before.append(scorer._infrastructure_reuse_ratio(c, fp_unweighted))
    R_after.append(scorer._infrastructure_reuse_ratio_weighted(c, fp_weighted, degrees))

def stats(indices, label):
    if not indices:
        print(f"{label:15s}  n=0")
        return
    b = [R_before[i] for i in indices]
    w = [R_after[i] for i in indices]
    mb, mw = sum(b)/len(b), sum(w)/len(w)
    drop = 100*(mb-mw)/mb if mb else 0
    print(f"{label:15s}  R_before={mb:6.4f}  R_after={mw:6.4f}  drop={drop:6.1f}%  (n={len(indices)})")

print(f"commodity-only: {len(commodity_only)}, genuine: {len(genuine)}, no-infra: {len(no_infra)}, total: {len(clusters)}")
stats(commodity_only, "commodity-only")
stats(genuine, "genuine")
stats(no_infra, "no-infra")
stats(list(range(len(clusters))), "ALL")

big_i = max(range(len(clusters)), key=lambda i: len(clusters[i]))
print(f"\n1849-cluster: R_before={R_before[big_i]:.4f}  R_after={R_after[big_i]:.4f}")

# score contribution (gamma * R) in confidence-score points, gamma=0.20
GAMMA = scorer.GAMMA
def contrib_stats(indices, label):
    if not indices:
        return
    b = [GAMMA*R_before[i]*100 for i in indices]
    w = [GAMMA*R_after[i]*100 for i in indices]
    mb, mw = sum(b)/len(b), sum(w)/len(w)
    print(f"{label:15s}  score_pts_before={mb:5.2f}  score_pts_after={mw:5.2f}  (of 100)")

print()
contrib_stats(commodity_only, "commodity-only")
contrib_stats(genuine, "genuine")

json.dump({
    "commodity_only_n": len(commodity_only), "genuine_n": len(genuine), "no_infra_n": len(no_infra), "total": len(clusters),
    "R_commodity_before": sum(R_before[i] for i in commodity_only)/len(commodity_only) if commodity_only else None,
    "R_commodity_after": sum(R_after[i] for i in commodity_only)/len(commodity_only) if commodity_only else None,
    "R_genuine_before": sum(R_before[i] for i in genuine)/len(genuine) if genuine else None,
    "R_genuine_after": sum(R_after[i] for i in genuine)/len(genuine) if genuine else None,
    "R_big_before": R_before[big_i], "R_big_after": R_after[big_i],
}, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/degree_weighting_rc_results.json", "w"))
db.close()
