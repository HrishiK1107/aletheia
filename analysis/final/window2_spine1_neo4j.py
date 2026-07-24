"""
CONTEXT.md §6p / Task 2 (second collection window): Spine 1's commodity-
hub-bridging methodology, run against window 2's Neo4j instance. Same
query/logic as analysis/final/spine1_neo4j_correct.py (window 1's script
of record for this exact figure) -- copied rather than edited in place, so
that script's own output path (a different agent session's tmp directory)
is untouched, and so window 1's script stays exactly reproducible against
window 1's data with no risk of drift. Output path here is local to this
task instead.

Must be run with NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD environment
variables already pointed at window 2's instance before this process
starts (module-level settings are read at import time).
"""

import sys
import time
import json
from collections import Counter, defaultdict

sys.path.insert(0, ".")

from app.correlation.campaign_detector import CampaignDetector  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.db.neo4j import driver  # noqa: E402

assert ":7688" in settings.neo4j_uri, "REFUSING: neo4j_uri does not look like window2"

t0 = time.time()
clusters = CampaignDetector().find_connected_clusters()
print(f"clusters={len(clusters)}, BFS done in {time.time()-t0:.1f}s", flush=True)

pairs = [{"value": v, "cluster_idx": i} for i, c in enumerate(clusters) for v in c]
print(f"total (cluster_idx, member) pairs: {len(pairs)}", flush=True)

query = """
UNWIND $pairs AS pair
MATCH (n {value: pair.value})
WHERE n:URL OR n:Domain OR n:IP
MATCH (n)-[:HOSTS|RESOLVES_TO_IP|RESOLVES_TO_ASN|HOSTED_BY|REGISTERED_WITH|USES_NS*1..2]-(attr)
WHERE attr:HostingProvider OR attr:ASN
RETURN pair.cluster_idx AS cluster_idx, labels(attr)[0] AS type, coalesce(attr.name, attr.value) AS attr_value, pair.value AS member
"""

t1 = time.time()
with driver.session() as session:
    result = session.run(query, pairs=pairs)
    rows = [(r["cluster_idx"], r["type"], r["attr_value"], r["member"]) for r in result]
print(f"query returned {len(rows)} rows in {time.time()-t1:.1f}s", flush=True)

per_cluster_attr_members = defaultdict(lambda: defaultdict(set))
for cluster_idx, atype, aval, member in rows:
    per_cluster_attr_members[cluster_idx][(atype, aval)].add(member)

cluster_asn_shared = [set() for _ in clusters]
cluster_hosting_shared = [set() for _ in clusters]
for cluster_idx, attr_map in per_cluster_attr_members.items():
    for (atype, aval), members in attr_map.items():
        if len(members) >= 2:
            if atype == "ASN":
                cluster_asn_shared[cluster_idx].add(aval)
            elif atype == "HostingProvider":
                cluster_hosting_shared[cluster_idx].add(aval)

asn_bridge_count = Counter()
hosting_bridge_count = Counter()
for s in cluster_asn_shared:
    for v in s:
        asn_bridge_count[v] += 1
for s in cluster_hosting_shared:
    for v in s:
        hosting_bridge_count[v] += 1

recurring_asn = {v for v, c in asn_bridge_count.items() if c >= 2}
recurring_hosting = {v for v, c in hosting_bridge_count.items() if c >= 2}

touching = sum(
    1 for i in range(len(clusters))
    if (cluster_asn_shared[i] & recurring_asn) or (cluster_hosting_shared[i] & recurring_hosting)
)

print(f"\n=== Spine 1, Neo4j-graph-based (matching window-1 methodology), window 2, {len(clusters)} clusters ===")
print(f"clusters touching a recurring hub value: {touching}/{len(clusters)} ({100*touching/len(clusters):.1f}%)")
print("\ntop HostingProvider bridge counts:")
for name, c in hosting_bridge_count.most_common(10):
    print(f"  {name:40s} {c}")
print("\ntop ASN bridge counts:")
for name, c in asn_bridge_count.most_common(10):
    print(f"  {name:40s} {c}")

one_without_other = sum(
    1 for i in range(len(clusters))
    if bool(cluster_asn_shared[i]) != bool(cluster_hosting_shared[i])
)
print(f"\nclusters with ASN shared but not HostingProvider (or vice versa): {one_without_other}/{len(clusters)}")

out_path = "../evaluation_runs/window2_dumps/spine1_neo4j_window2.json"
json.dump({
    "n_clusters": len(clusters), "touching": touching,
    "hosting_top": hosting_bridge_count.most_common(10), "asn_top": asn_bridge_count.most_common(10),
    "collinearity_violations": one_without_other,
}, open(out_path, "w"), indent=2)
print(f"\nWrote {out_path}")
