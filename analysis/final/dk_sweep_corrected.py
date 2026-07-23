import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.evaluation.ground_truth import build_threatfox_labels
from app.evaluation.diagnostics import connectivity_components
from app.evaluation.metrics import build_predicted_labels, pairwise_precision_recall

TARGET_FAMILIES = ["unknown", "win.cobalt_strike", "js.clearfake", "win.vidar", "win.adaptix_c2"]

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()
threatfox_labels = build_threatfox_labels(db)
family_labels = {fam: {v: l for v, l in threatfox_labels.items() if l == fam} for fam in TARGET_FAMILIES}

fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)

# fixed reference populations, exactly matching §6i's construction
conn_clusters = connectivity_components(fp_weighted, degrees, max_degree=None)
conn_clusters = [c for c in conn_clusters if len(c) >= 2]
postgres_pop = {v for c in conn_clusters for v in c}

reference_bfs = CampaignDetector().find_connected_clusters()  # default d=2, k=3
neo4j_pop = {v for c in reference_bfs for v in c}

intersection = postgres_pop & neo4j_pop
print(f"intersection population: {len(intersection)} (postgres={len(postgres_pop)}, neo4j_default={len(neo4j_pop)})", flush=True)

def pairwise_recall_intersection(labels, clusters):
    labels_int = {v: l for v, l in labels.items() if v in intersection}
    clusters_int = [[v for v in c if v in intersection] for c in clusters]
    clusters_int = [c for c in clusters_int if len(c) >= 2]
    universe = {v for c in clusters_int for v in c} | set(labels_int)
    pred = build_predicted_labels(clusters_int, universe)
    _, r = pairwise_precision_recall(labels_int, pred)
    return r, len(labels_int)

# corrected achievable ceilings (§6i), recomputed here for self-containment
ceilings = {}
for fam in TARGET_FAMILIES:
    r, n = pairwise_recall_intersection(family_labels[fam], conn_clusters)
    ceilings[fam] = r
print("corrected achievable ceilings (intersection):", {k: round(v, 4) for k, v in ceilings.items()}, flush=True)

print("\n=== d/k sweep, intersection-restricted, recall as fraction of corrected ceiling ===")
sweep_results = []
for d in [1, 2, 3]:
    for k in [2, 3, 5]:
        t1 = time.time()
        det = CampaignDetector()
        det.MAX_DEPTH = d
        det.MIN_CLUSTER = k
        clusters = det.find_connected_clusters()
        elapsed = time.time() - t1
        row = {"d": d, "k": k, "n_clusters": len(clusters), "elapsed_s": round(elapsed, 1)}
        parts = []
        for fam in TARGET_FAMILIES:
            recall, n_int = pairwise_recall_intersection(family_labels[fam], clusters)
            pct_of_ceiling = 100 * recall / ceilings[fam] if ceilings[fam] else float("nan")
            row[fam] = {"recall": round(recall, 4), "pct_of_ceiling": round(pct_of_ceiling, 1)}
            parts.append(f"{fam.split('.')[-1]}={recall:.4f}({pct_of_ceiling:.1f}%)")
        sweep_results.append(row)
        print(f"d={d} k={k}  n={len(clusters):5d}  elapsed={elapsed:.1f}s  " + "  ".join(parts), flush=True)

json.dump({"ceilings": ceilings, "sweep": sweep_results, "intersection_size": len(intersection)},
           open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/dk_sweep_corrected_results.json", "w"))
db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
