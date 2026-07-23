import sys, time, json
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.evaluation.ground_truth import build_threatfox_labels
from app.evaluation.metrics import adjusted_rand_index, build_predicted_labels, pairwise_precision_recall

TARGET_FAMILIES = {
    "unknown": 0.7822,
    "win.cobalt_strike": 0.6695,
    "js.clearfake": 0.7435,
    "win.vidar": 0.5973,
    "win.adaptix_c2": 0.4941,
}

t0 = time.time()
db = SessionLocal()
threatfox_labels = build_threatfox_labels(db)
family_labels = {fam: {v: l for v, l in threatfox_labels.items() if l == fam} for fam in TARGET_FAMILIES}
db.close()

results = []
for d in [1, 2, 3]:
    for k in [2, 3, 5]:
        t1 = time.time()
        det = CampaignDetector()
        det.MAX_DEPTH = d
        det.MIN_CLUSTER = k
        clusters = det.find_connected_clusters()
        elapsed = time.time() - t1

        row = {"d": d, "k": k, "n_clusters": len(clusters), "elapsed_s": round(elapsed, 1)}
        for fam, ceiling in TARGET_FAMILIES.items():
            fam_labels = family_labels[fam]
            universe = {v for c in clusters for v in c} | set(fam_labels)
            pred = build_predicted_labels(clusters, universe)
            _, recall = pairwise_precision_recall(fam_labels, pred)
            row[fam] = round(recall, 4)

        results.append(row)
        print(f"d={d} k={k}  n_clusters={len(clusters):5d}  elapsed={elapsed:.1f}s  " +
              "  ".join(f"{fam.split('.')[-1]}={row[fam]:.4f}" for fam in TARGET_FAMILIES), flush=True)

json.dump(results, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/dk_sweep_results.json", "w"))
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
