import sys, time
sys.path.insert(0, '.')
from app.db.neo4j import driver

t0 = time.time()

node_query = "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY label"
rel_query = "MATCH ()-[r]->() RETURN type(r) AS rel, count(*) AS n ORDER BY rel"

with driver.session() as session:
    print("--- node counts, by label ---", flush=True)
    for record in session.run(node_query):
        print(f"  {record['label']:<16} {record['n']:>7,}")

    print("\n--- relationship counts, by type ---", flush=True)
    for record in session.run(rel_query):
        print(f"  {record['rel']:<16} {record['n']:>7,}")

print(f"\ntotal runtime: {time.time()-t0:.1f}s")
