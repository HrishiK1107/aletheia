import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from collections import Counter

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()

clusters = CampaignDetector().find_connected_clusters()
fp_unweighted = ie.build_fingerprints(db)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)
print(f"clusters={len(clusters)}, setup done in {time.time()-t0:.1f}s", flush=True)

# ============ TASK 1: Spine 1 baseline -- commodity hub bridging ============
def shared_features(cluster, fp, prefix=None):
    counts = Counter()
    for v in cluster:
        for feat in fp.get(v, set()):
            if prefix is None or feat.startswith(prefix):
                counts[feat] += 1
    return {f for f, c in counts.items() if c >= 2}

# per-cluster shared ASN and shared HostingProvider sets (unmerged fingerprint)
cluster_asn = [shared_features(c, fp_unweighted, "asn:") for c in clusters]
cluster_hosting = [shared_features(c, fp_unweighted, "hosting:") for c in clusters]

# global recurrence: which asn/hosting values appear as a shared attribute in >1 cluster
asn_cluster_count = Counter()
hosting_cluster_count = Counter()
for s in cluster_asn:
    for v in s:
        asn_cluster_count[v] += 1
for s in cluster_hosting:
    for v in s:
        hosting_cluster_count[v] += 1

recurring_asn = {v for v, c in asn_cluster_count.items() if c >= 2}
recurring_hosting = {v for v, c in hosting_cluster_count.items() if c >= 2}

touching_clusters = 0
for i in range(len(clusters)):
    if (cluster_asn[i] & recurring_asn) or (cluster_hosting[i] & recurring_hosting):
        touching_clusters += 1

print(f"\n=== TASK 1: Spine 1 baseline (commodity hub bridging), current {len(clusters)}-cluster set ===")
print(f"clusters touching a recurring hub value: {touching_clusters}/{len(clusters)} ({100*touching_clusters/len(clusters):.1f}%)")

# top hub bridge counts, matching original methodology (Cloudflare, Hostinger, Amazon)
print("\ntop HostingProvider bridge counts:")
for name, count in hosting_cluster_count.most_common(10):
    print(f"  {name:40s} {count}")
print("\ntop ASN bridge counts:")
for name, count in asn_cluster_count.most_common(10):
    print(f"  {name:40s} {count}")

# collinearity check: does every cluster sharing an ASN also share the SAME clusters' HostingProvider, and vice versa
one_without_other = 0
for i in range(len(clusters)):
    has_asn = bool(cluster_asn[i])
    has_hosting = bool(cluster_hosting[i])
    if has_asn != has_hosting:
        one_without_other += 1
print(f"\nclusters with ASN shared but not HostingProvider (or vice versa): {one_without_other}/{len(clusters)}")

# global collinearity: does every ASN value correspond to exactly one HostingProvider value across all indicators
asn_to_hosting = {}
hosting_to_asn = {}
collinearity_violations = 0
for v, feats in fp_unweighted.items():
    asns = {f[4:] for f in feats if f.startswith("asn:")}
    hosts = {f[8:] for f in feats if f.startswith("hosting:")}
    for a in asns:
        for h in hosts:
            asn_to_hosting.setdefault(a, set()).add(h)
            hosting_to_asn.setdefault(h, set()).add(a)
multi_hosting_per_asn = sum(1 for h in asn_to_hosting.values() if len(h) > 1)
multi_asn_per_hosting = sum(1 for a in hosting_to_asn.values() if len(a) > 1)
print(f"ASN values mapping to >1 HostingProvider: {multi_hosting_per_asn}/{len(asn_to_hosting)}")
print(f"HostingProvider values mapping to >1 ASN: {multi_asn_per_hosting}/{len(hosting_to_asn)}")

# ============ TASK 2: Spine 3 -- monotonic R(C) gradient by exposure band ============
print(f"\n=== TASK 2: Spine 3 R(C) gradient, current {len(clusters)}-cluster set ===")
LOW, HIGH = 10, 100
bands = {"low": [], "medium": [], "high": [], "none": []}
for c in clusters:
    feats = shared_features(c, fp_weighted)
    if not feats:
        bands["none"].append(c)
        continue
    max_deg = max(degrees.get(f, 1) for f in feats)
    if max_deg <= LOW:
        bands["low"].append(c)
    elif max_deg <= HIGH:
        bands["medium"].append(c)
    else:
        bands["high"].append(c)

for band_name in ["low", "medium", "high", "none"]:
    band_clusters = bands[band_name]
    if not band_clusters:
        print(f"  {band_name:8s} n=0")
        continue
    r_before = [scorer._infrastructure_reuse_ratio(c, fp_unweighted) for c in band_clusters]
    r_after = [scorer._infrastructure_reuse_ratio_weighted(c, fp_weighted, degrees) for c in band_clusters]
    mb, ma = sum(r_before)/len(r_before), sum(r_after)/len(r_after)
    drop = 100*(mb-ma)/mb if mb else 0
    print(f"  {band_name:8s} n={len(band_clusters):4d} ({100*len(band_clusters)/len(clusters):.1f}%)  R_before={mb:.4f}  R_after={ma:.4f}  drop={drop:.1f}%")

# ============ TASK 3: the 1,849-member cluster ============
print(f"\n=== TASK 3: the largest cluster, current graph ===")
big = max(clusters, key=len)
print(f"largest cluster size: {len(big)}")
big_asn_count = sum(1 for v in big if "asn:AS13335" in fp_unweighted.get(v, set()))
print(f"members with asn:AS13335: {big_asn_count}/{len(big)} ({100*big_asn_count/len(big):.1f}%)")

json.dump({
    "n_clusters": len(clusters),
    "touching_pct": 100*touching_clusters/len(clusters),
    "touching_n": touching_clusters,
    "hosting_top": hosting_cluster_count.most_common(10),
    "asn_top": asn_cluster_count.most_common(10),
    "big_cluster_size": len(big),
    "big_cluster_asn_pct": 100*big_asn_count/len(big),
}, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/final_spine1_spine3_results.json", "w"))

db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
