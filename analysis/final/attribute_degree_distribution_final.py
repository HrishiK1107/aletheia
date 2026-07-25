import sys, csv
sys.path.insert(0, '.')
from app.db.neo4j import driver

query = """
MATCH (n)
WHERE n:ASN OR n:HostingProvider OR n:Registrar OR n:Nameserver
OPTIONAL MATCH (n)--(m)
WITH n, count(m) AS degree
RETURN labels(n)[0] AS label, coalesce(n.value, n.name) AS name, degree
ORDER BY label, degree DESC
"""

with driver.session() as session:
    rows = list(session.run(query))

out_path = "../analysis/output/attribute_degree_distribution.csv"
with open(out_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["label", "name", "degree"])
    for r in rows:
        w.writerow([r["label"], r["name"], r["degree"]])

print(f"wrote {len(rows)} rows to {out_path}")
for label in ["ASN", "HostingProvider", "Registrar", "Nameserver"]:
    degrees = [r["degree"] for r in rows if r["label"] == label]
    print(f"  {label:<16} n={len(degrees):>5}  min={min(degrees)}  max={max(degrees)}  "
          f"mean={sum(degrees)/len(degrees):.2f}")
