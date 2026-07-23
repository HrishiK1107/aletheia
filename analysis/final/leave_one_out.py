import sys, json, time
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.evaluation.ground_truth import build_threatfox_labels
from app.evaluation.diagnostics import connectivity_components
from app.evaluation.metrics import adjusted_rand_index, build_predicted_labels, pairwise_precision_recall
from collections import Counter

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()

threatfox_labels = build_threatfox_labels(db)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)
print(f"loaded in {time.time()-t0:.1f}s", flush=True)

# unrestricted connectivity components -- computed ONCE, doesn't depend on labels
clusters = connectivity_components(fp_weighted, degrees, max_degree=None)
clusters = [c for c in clusters if len(c) >= 2]
print(f"unrestricted components: {len(clusters)}, largest={max(len(c) for c in clusters)}", flush=True)

def ari_for_labels(labels):
    universe = {v for c in clusters for v in c} | set(labels)
    pred = build_predicted_labels(clusters, universe)
    ari = adjusted_rand_index(labels, pred)
    precision, recall = pairwise_precision_recall(labels, pred)
    return ari, precision, recall

baseline_ari, baseline_p, baseline_r = ari_for_labels(threatfox_labels)
print(f"\nbaseline (all {len(threatfox_labels)} labels): ARI={baseline_ari:.4f} P={baseline_p:.4f} R={baseline_r:.4f}")

counts = Counter(threatfox_labels.values())
top_families = [f for f, _ in counts.most_common(10)]

print("\n=== leave-one-family-out ===")
results = {"baseline": {"n": len(threatfox_labels), "ari": baseline_ari, "precision": baseline_p, "recall": baseline_r}, "leave_one_out": []}
for family in top_families:
    filtered = {v: l for v, l in threatfox_labels.items() if l != family}
    ari, p, r = ari_for_labels(filtered)
    delta = ari - baseline_ari
    print(f"  held out {family:20s} (n={counts[family]:4d})  ARI={ari:.4f}  delta={delta:+.4f}")
    results["leave_one_out"].append({
        "held_out": family, "n_held_out": counts[family],
        "n_remaining": len(filtered), "ari": ari, "precision": p, "recall": r, "delta": delta,
    })

# also: solo -- ARI computed using ONLY that family's own members (sanity check on cohesion)
print("\n=== solo (evaluated using only that family's members) ===")
for family in top_families:
    solo = {v: l for v, l in threatfox_labels.items() if l == family}
    if len(solo) < 2:
        continue
    ari, p, r = ari_for_labels(solo)
    print(f"  solo {family:20s} (n={counts[family]:4d})  ARI={ari:.4f}  P={p:.4f}  R={r:.4f}")

json.dump(results, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/leave_one_out_results.json", "w"))
db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
