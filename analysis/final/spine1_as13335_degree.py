import sys, json, os
sys.path.insert(0, '.')
from app.db.neo4j import driver

# Neo4j graph-traversal count, matching the original methodology
# (CONTEXT.md item 2.1, "1,849-cluster resolved") that produced the
# 2,048/7,439/27.5% figures cited in §8's Spine 1 entry. §6i established
# that the equivalent Postgres-fingerprint-based count (build_weighted_fingerprints()
# + compute_feature_degrees(), the approach §6m's table entry speculated
# would work) gives a different, wrong answer for this same class of
# question -- confirmed empirically below, not assumed: "org:AS13335" never
# appears as a fp_weighted feature at all, because weighted_fingerprint()
# prefers hosting_provider ("Cloudflare, Inc.") over the asn fallback
# whenever both are present, which they are for effectively every
# Cloudflare-fronted domain in this graph.

query = """
MATCH (d:Domain)-[:RESOLVES_TO_ASN]->(a:ASN)
RETURN a.value AS asn, count(DISTINCT d) AS degree
"""

with driver.session() as session:
    rows = {r["asn"]: r["degree"] for r in session.run(query)}
    # domains can resolve through more than one ASN (item 2.3), so summing
    # per-ASN degree would overcount the distinct-domain denominator --
    # count distinct domains directly instead.
    domain_asn_count = session.run(
        "MATCH (d:Domain)-[:RESOLVES_TO_ASN]->(:ASN) RETURN count(DISTINCT d) AS n"
    ).single()["n"]

as13335_degree = rows.get("AS13335", 0)

ratio = 100 * as13335_degree / domain_asn_count if domain_asn_count else 0.0

print("=== Spine 1: AS13335 global degree (Neo4j graph traversal) ===")
print(f'AS13335 degree (Domain nodes with a RESOLVES_TO_ASN edge to AS13335) = {as13335_degree}  (expect 2,048)')
print(f"domain-type indicators with any ASN feature (any RESOLVES_TO_ASN edge) = {domain_asn_count}  (expect 7,439)")
print(f"ratio = {ratio:.1f}%  (expect 27.5%)")

EXPECTED = {"as13335_degree": 2048, "domain_asn_count": 7439, "ratio_pct": 27.5}
mismatches = []
if as13335_degree != EXPECTED["as13335_degree"]:
    mismatches.append(f'as13335_degree {as13335_degree} != expected {EXPECTED["as13335_degree"]}')
if domain_asn_count != EXPECTED["domain_asn_count"]:
    mismatches.append(f'domain_asn_count {domain_asn_count} != expected {EXPECTED["domain_asn_count"]}')
if round(ratio, 1) != EXPECTED["ratio_pct"]:
    mismatches.append(f'ratio {ratio:.1f}% != expected {EXPECTED["ratio_pct"]}%')

if mismatches:
    print("\nMISMATCH vs §8:")
    for m in mismatches:
        print(f"  {m}")
else:
    print("\nMatches §8 exactly.")

out_dir = os.path.join(os.path.dirname(__file__), "..", "output")
json.dump({
    "as13335_degree": as13335_degree,
    "domain_asn_count": domain_asn_count,
    "ratio_pct": ratio,
    "mismatches": mismatches,
}, open(os.path.join(out_dir, "spine1_as13335_degree_results.json"), "w"), indent=2)
