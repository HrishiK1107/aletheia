import sys, time, json, os
sys.path.insert(0, '.')
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.db.neo4j import driver
from app.db.postgres import SessionLocal
from collections import Counter

t0 = time.time()
clusters = CampaignDetector().find_connected_clusters()
big = max(clusters, key=len)
print(f"n_clusters={len(clusters)}  big_cluster_size={len(big)}  ({time.time()-t0:.1f}s)", flush=True)

# ============ PART 1: turn the 1,849-cluster's manual illustration into a
# measurement -- every shared feature, its in-cluster member count, and its
# global degree, matching the exact 2-hop traversal pattern already
# established for this cluster (big_cluster_recheck.py, spine1_neo4j_correct.py),
# broadened from HostingProvider/ASN-only to also include Registrar/Nameserver
# ============

REL_PATTERN = "HOSTS|RESOLVES_TO_IP|RESOLVES_TO_ASN|HOSTED_BY|REGISTERED_WITH|USES_NS"

census_query = f"""
UNWIND $members AS mval
MATCH (n {{value: mval}})
WHERE n:URL OR n:Domain OR n:IP
MATCH (n)-[:{REL_PATTERN}*1..2]-(attr)
WHERE attr:HostingProvider OR attr:ASN OR attr:Registrar OR attr:Nameserver
RETURN labels(attr)[0] AS type, coalesce(attr.name, attr.value) AS attr_value, count(DISTINCT n) AS members_in_cluster
ORDER BY members_in_cluster DESC
"""

with driver.session() as session:
    rows = [dict(r) for r in session.run(census_query, members=big)]
print(f"distinct attrs touched by the {len(big)}-member cluster: {len(rows)}  ({time.time()-t0:.1f}s)", flush=True)

# global degree of each of those same attrs, same 2-hop pattern, unrestricted
# to this cluster's membership -- one bulk UNWIND query, not one per attr.
degree_query = f"""
UNWIND $attrs AS attr
MATCH (a)
WHERE (attr.type = 'HostingProvider' AND a:HostingProvider AND a.name = attr.value)
   OR (attr.type = 'ASN' AND a:ASN AND a.value = attr.value)
   OR (attr.type = 'Registrar' AND a:Registrar AND a.name = attr.value)
   OR (attr.type = 'Nameserver' AND a:Nameserver AND a.value = attr.value)
MATCH (a)-[:{REL_PATTERN}*1..2]-(n)
WHERE n:URL OR n:Domain OR n:IP
RETURN attr.type AS type, attr.value AS value, count(DISTINCT n) AS global_degree
"""

attr_keys = [{"type": r["type"], "value": r["attr_value"]} for r in rows]
with driver.session() as session:
    degree_rows = {(r["type"], r["value"]): r["global_degree"] for r in session.run(degree_query, attrs=attr_keys)}
print(f"global degree computed for all {len(degree_rows)} attrs  ({time.time()-t0:.1f}s)", flush=True)

census = []
for r in rows:
    key = (r["type"], r["attr_value"])
    census.append({
        "type": r["type"],
        "value": r["attr_value"],
        "in_cluster_members": r["members_in_cluster"],
        "global_degree": degree_rows.get(key, 0),
    })
census.sort(key=lambda x: -x["in_cluster_members"])

print(f"\n=== Spine 2, measured: 1,849-cluster's shared features, in-cluster count vs. global degree ===")
print(f"{'type':14s} {'value':45s} {'in-cluster':>10s} {'global degree':>14s}")
for c in census[:20]:
    print(f"{c['type']:14s} {c['value']:45s} {c['in_cluster_members']:>10d} {c['global_degree']:>14d}")

harlee = next((c for c in census if c["value"] == "harlee.ns.cloudflare.com"), None)
tosana = next((c for c in census if c["value"] == "tosana.ns.cloudflare.com"), None)
as13335 = next((c for c in census if c["value"] == "AS13335"), None)
cloudflare = next((c for c in census if c["value"] == "Cloudflare, Inc."), None)
print("\nSpot-check against the §8/CONTEXT.md illustration:")
print(f"  harlee.ns.cloudflare.com  in-cluster={harlee['in_cluster_members'] if harlee else 'MISSING'} (expect ~160)  global_degree={harlee['global_degree'] if harlee else '-'}")
print(f"  tosana.ns.cloudflare.com  in-cluster={tosana['in_cluster_members'] if tosana else 'MISSING'} (expect ~160)  global_degree={tosana['global_degree'] if tosana else '-'}")
print(f"  AS13335                  in-cluster={as13335['in_cluster_members'] if as13335 else 'MISSING'} (expect 1,849)  global_degree={as13335['global_degree'] if as13335 else '-'}")
print(f"  Cloudflare, Inc.          in-cluster={cloudflare['in_cluster_members'] if cloudflare else 'MISSING'} (expect ~1,808)  global_degree={cloudflare['global_degree'] if cloudflare else '-'}")

# ============ PART 2: generalise across ALL clusters -- of the clusters a
# type-level check classifies as "has additional non-org evidence" (shares
# a registrar/nameserver/resolved-ip feature, not just the merged org
# feature), how many have that additional evidence supplied ONLY by
# features whose global degree exceeds a threshold? Uses the Postgres
# weighted-fingerprint feature set (org/registrar/ns/ip, item 6's merged
# four-class construction) and its degree table, the same population-scale
# tool already used for Spine 3's exposure-band gradient.
# ============

db = SessionLocal()
ie = InfrastructureEngine()
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)


def shared_features(cluster, fp):
    counts = Counter()
    for v in cluster:
        for feat in fp.get(v, set()):
            counts[feat] += 1
    return {f for f, c in counts.items() if c >= 2}


THRESHOLDS = [100, 500]
has_additional_evidence = 0
commodity_only_evidence = {t: 0 for t in THRESHOLDS}
commodity_any_evidence = {t: 0 for t in THRESHOLDS}

for c in clusters:
    shared = shared_features(c, fp_weighted)
    non_org = {f for f in shared if not f.startswith("org:")}
    if not non_org:
        continue
    has_additional_evidence += 1
    for t in THRESHOLDS:
        if all(degrees.get(f, 0) > t for f in non_org):
            commodity_only_evidence[t] += 1
        if any(degrees.get(f, 0) > t for f in non_org):
            commodity_any_evidence[t] += 1

print(f"\n=== Spine 2, population statistic: {len(clusters)} clusters ===")
print(f"clusters a type-level check classifies as \"has additional non-org evidence\": {has_additional_evidence}/{len(clusters)} ({100*has_additional_evidence/len(clusters):.1f}%)")
for t in THRESHOLDS:
    n_only = commodity_only_evidence[t]
    n_any = commodity_any_evidence[t]
    print(f"  threshold > {t}:")
    print(f"    additional evidence supplied ONLY by high-degree features: "
          f"{n_only}/{has_additional_evidence} ({100*n_only/has_additional_evidence:.1f}% of that bucket, "
          f"{100*n_only/len(clusters):.1f}% of all {len(clusters)} clusters)")
    print(f"    additional evidence includes AT LEAST ONE high-degree feature: "
          f"{n_any}/{has_additional_evidence} ({100*n_any/has_additional_evidence:.1f}% of that bucket, "
          f"{100*n_any/len(clusters):.1f}% of all {len(clusters)} clusters)")

out_dir = os.path.join(os.path.dirname(__file__), "..", "output")
json.dump({
    "n_clusters": len(clusters),
    "big_cluster_size": len(big),
    "big_cluster_census": census,
    "has_additional_evidence": has_additional_evidence,
    "commodity_only_evidence_by_threshold": commodity_only_evidence,
    "commodity_any_evidence_by_threshold": commodity_any_evidence,
}, open(os.path.join(out_dir, "spine2_ns_pool_census_results.json"), "w"), indent=2)

db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
