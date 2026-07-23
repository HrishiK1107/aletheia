import sys
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

LOW, HIGH = 10, 100
commodity_only, has_specific, other = [], [], []
for i, c in enumerate(clusters):
    feats = shared_feats(c)
    if not feats:
        other.append(i)
        continue
    degs = [degrees.get(f, 1) for f in feats]
    if any(d <= LOW for d in degs):
        has_specific.append(i)
    elif all(d > HIGH for d in feats and degs):
        commodity_only.append(i)
    else:
        other.append(i)

R_before = [scorer._infrastructure_reuse_ratio(c, fp_unweighted) for c in clusters]
R_after = [scorer._infrastructure_reuse_ratio_weighted(c, fp_weighted, degrees) for c in clusters]

def stats(indices, label):
    if not indices:
        print(f"{label:20s} n=0"); return
    b = [R_before[i] for i in indices]; w = [R_after[i] for i in indices]
    mb, mw = sum(b)/len(b), sum(w)/len(w)
    drop = 100*(mb-mw)/mb if mb else 0
    print(f"{label:20s}  R_before={mb:6.4f}  R_after={mw:6.4f}  drop={drop:6.1f}%  (n={len(indices)}, {100*len(indices)/len(clusters):.1f}%)")

print(f"total clusters: {len(clusters)}")
stats(commodity_only, "commodity-only (deg>100 only)")
stats(has_specific, "has specific (some deg<=10)")
stats(other, "other/mixed")
db.close()
