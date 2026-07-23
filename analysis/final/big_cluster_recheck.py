import sys, time, json
sys.path.insert(0, '.')
from app.correlation.campaign_detector import CampaignDetector
from app.db.neo4j import driver

t0 = time.time()
clusters = CampaignDetector().find_connected_clusters()
big = max(clusters, key=len)
print(f"largest cluster size (current graph): {len(big)}", flush=True)

query = '''
UNWIND $members AS mval
MATCH (n {value: mval})
WHERE n:URL OR n:Domain OR n:IP
MATCH (n)-[:HOSTS|RESOLVES_TO_IP|RESOLVES_TO_ASN|HOSTED_BY|REGISTERED_WITH|USES_NS*1..2]-(attr)
WHERE attr:HostingProvider OR attr:ASN
RETURN labels(attr)[0] AS type, coalesce(attr.name, attr.value) AS attr_value, count(DISTINCT n) AS members_in_cluster
ORDER BY members_in_cluster DESC
'''
with driver.session() as session:
    result = session.run(query, members=big)
    rows = [dict(r) for r in result]

print(f"distinct attrs touched: {len(rows)}")
for r in rows[:6]:
    print(f"  {r}")

as13335_row = next((r for r in rows if r["attr_value"] == "AS13335"), None)
if as13335_row:
    print(f"\nAS13335 coverage: {as13335_row['members_in_cluster']}/{len(big)} ({100*as13335_row['members_in_cluster']/len(big):.1f}%)")
else:
    print("\nAS13335 not found as a shared attribute of this cluster")

print(f"\ntotal runtime: {time.time()-t0:.1f}s")
