import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from app.evaluation.ground_truth import build_threatfox_labels
from app.evaluation.diagnostics import connectivity_components
from app.evaluation.metrics import adjusted_rand_index, build_predicted_labels, pairwise_precision_recall

TARGET_FAMILIES = ["unknown", "win.cobalt_strike", "js.clearfake", "win.vidar", "win.adaptix_c2"]

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()
threatfox_labels = build_threatfox_labels(db)
family_labels = {fam: {v: l for v, l in threatfox_labels.items() if l == fam} for fam in TARGET_FAMILIES}

fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)
print(f"labels+fingerprints loaded in {time.time()-t0:.1f}s", flush=True)

# achievable ceilings on the (unchanged -- Postgres-only) connectivity graph
conn_clusters = connectivity_components(fp_weighted, degrees, max_degree=None)
conn_clusters = [c for c in conn_clusters if len(c) >= 2]

def pairwise_recall(labels, clusters):
    universe = {v for c in clusters for v in c} | set(labels)
    pred = build_predicted_labels(clusters, universe)
    _, r = pairwise_precision_recall(labels, pred)
    return r

ceilings = {fam: pairwise_recall(family_labels[fam], conn_clusters) for fam in TARGET_FAMILIES}
print("achievable ceilings (unchanged, Postgres-only):", {k: round(v,4) for k,v in ceilings.items()}, flush=True)

# === PART A: BFS ARI weighted vs unweighted, d=2 k=3 (production defaults) ===
bfs_clusters = CampaignDetector().find_connected_clusters()
fp_unweighted = ie.build_fingerprints(db)
print(f"BFS d=2,k=3 (rebuilt graph): {len(bfs_clusters)} clusters", flush=True)

def confidence_filtered(cl, fp, deg):
    raw = [{"campaign_id": f"c{i}", "indicators": c, "size": len(c)} for i, c in enumerate(cl)]
    scored = scorer.score_campaigns(raw, fingerprints=fp, degrees=deg)
    return scored

scored_u = confidence_filtered(bfs_clusters, fp_unweighted, None)
scored_w = confidence_filtered(bfs_clusters, fp_weighted, degrees)
reported_u = [c["indicators"] for c in scored_u if c["confidence"] >= 40]
reported_w = [c["indicators"] for c in scored_w if c["confidence"] >= 40]

def evaluate(name, clusters):
    universe = {v for c in clusters for v in c} | set(threatfox_labels)
    pred = build_predicted_labels(clusters, universe)
    ari = adjusted_rand_index(threatfox_labels, pred)
    p, r = pairwise_precision_recall(threatfox_labels, pred)
    print(f"  {name:32s} n={len(clusters):5d}  ARI={ari:.4f}  P={p:.4f}  R={r:.4f}", flush=True)
    return ari

print("\n=== PART A: ThreatFox ARI, rebuilt graph ===")
evaluate("bfs_all_clusters", bfs_clusters)
ari_u = evaluate("bfs_reported_unweighted", reported_u)
ari_w = evaluate("bfs_reported_weighted", reported_w)
print(f"  weighted-unweighted delta: {ari_w-ari_u:+.4f}")

# === PART B: achievable-vs-actual recall table, 5 families, on rebuilt graph ===
print("\n=== PART B: achievable vs actual (BFS reported, weighted), rebuilt graph ===")
for fam in TARGET_FAMILIES:
    achievable = ceilings[fam]
    actual = pairwise_recall(family_labels[fam], reported_w)
    print(f"  {fam:20s} n={len(family_labels[fam]):4d}  achievable={achievable:.4f}  actual={actual:.4f}  gap={achievable-actual:+.4f}")

# === PART C: d/k sweep, raw BFS, rebuilt graph ===
print("\n=== PART C: d/k sweep, raw BFS, rebuilt graph ===")
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
        for fam in TARGET_FAMILIES:
            row[fam] = round(pairwise_recall(family_labels[fam], clusters), 4)
        sweep_results.append(row)
        print(f"d={d} k={k}  n={len(clusters):5d}  elapsed={elapsed:.1f}s  " +
              "  ".join(f"{fam.split('.')[-1]}={row[fam]:.4f}" for fam in TARGET_FAMILIES), flush=True)

json.dump({"ceilings": ceilings, "sweep": sweep_results}, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/post_rebuild_results.json", "w"))
db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
