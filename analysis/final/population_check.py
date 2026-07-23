import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from app.evaluation.ground_truth import build_threatfox_labels
from app.evaluation.diagnostics import connectivity_components
from app.evaluation.metrics import build_predicted_labels, pairwise_precision_recall

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()

threatfox_labels = build_threatfox_labels(db)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)

conn_clusters = connectivity_components(fp_weighted, degrees, max_degree=None)
conn_clusters = [c for c in conn_clusters if len(c) >= 2]

bfs_clusters = CampaignDetector().find_connected_clusters()
reported_w = [
    c["indicators"] for c in scorer.score_campaigns(
        [{"campaign_id": f"c{i}", "indicators": c, "size": len(c)} for i, c in enumerate(bfs_clusters)],
        fingerprints=fp_weighted, degrees=degrees,
    ) if c["confidence"] >= 40
]
print(f"setup done in {time.time()-t0:.1f}s", flush=True)

postgres_pop = {v for c in conn_clusters for v in c}
neo4j_pop = {v for c in bfs_clusters for v in c}
neo4j_reported_pop = {v for c in reported_w for v in c}

print(f"\n=== Population comparison ===")
print(f"Postgres connectivity population (achievable side): {len(postgres_pop)}")
print(f"Neo4j BFS population (actual side, all clusters): {len(neo4j_pop)}")
print(f"Neo4j BFS population (actual side, reported/weighted): {len(neo4j_reported_pop)}")
intersection = postgres_pop & neo4j_pop
only_postgres = postgres_pop - neo4j_pop
only_neo4j = neo4j_pop - postgres_pop
print(f"intersection (postgres ∩ neo4j-all): {len(intersection)}")
print(f"only in Postgres connectivity, not in any BFS cluster: {len(only_postgres)}")
print(f"only in BFS clusters, not in Postgres connectivity (>=2): {len(only_neo4j)}")

TARGET_FAMILIES = ["unknown", "js.clearfake", "win.cobalt_strike", "win.vidar", "win.adaptix_c2"]
family_labels = {fam: {v: l for v, l in threatfox_labels.items() if l == fam} for fam in TARGET_FAMILIES}

def pairwise_recall(labels, clusters):
    universe = {v for c in clusters for v in c} | set(labels)
    pred = build_predicted_labels(clusters, universe)
    _, r = pairwise_precision_recall(labels, pred)
    return r

print(f"\n=== Per-family: full achievable/actual vs. intersection-restricted ===")
print(f"{'family':20s}{'achievable(full)':>18}{'actual(full)':>14}   |{'achievable(int)':>18}{'actual(int)':>14}")
for fam in TARGET_FAMILIES:
    labels = family_labels[fam]
    ach_full = pairwise_recall(labels, conn_clusters)
    act_full = pairwise_recall(labels, reported_w)

    # restrict both clusterings AND the label set to the intersection population
    labels_int = {v: l for v, l in labels.items() if v in intersection}
    conn_clusters_int = [[v for v in c if v in intersection] for c in conn_clusters]
    conn_clusters_int = [c for c in conn_clusters_int if len(c) >= 2]
    reported_w_int = [[v for v in c if v in intersection] for c in reported_w]
    reported_w_int = [c for c in reported_w_int if len(c) >= 2]

    ach_int = pairwise_recall(labels_int, conn_clusters_int) if labels_int else float("nan")
    act_int = pairwise_recall(labels_int, reported_w_int) if labels_int else float("nan")
    print(f"{fam:20s}{ach_full:18.4f}{act_full:14.4f}   |{ach_int:18.4f}{act_int:14.4f}   (n_int={len(labels_int)}/{len(labels)})")

db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
