import sys, json, time
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.evaluation.ground_truth import build_threatfox_labels, build_otx_labels, find_largest_otx_pulse
from app.evaluation.diagnostics import label_infra_cohesion, ceiling_sweep

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()

print("loading labels + fingerprints...", flush=True)
threatfox_labels = build_threatfox_labels(db)
outlier_pulse_id, outlier_count = find_largest_otx_pulse(db)
otx_labels = build_otx_labels(db)
otx_labels_no_outlier = build_otx_labels(db, exclude_pulse_id=outlier_pulse_id)

fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)
print(f"  done in {time.time()-t0:.1f}s", flush=True)

print("\n=== PART 1: ThreatFox top-10 families, in-family infra cohesion ===")
tf_cohesion = label_infra_cohesion(threatfox_labels, fp_weighted, top_n=10)
for r in tf_cohesion:
    print(f"  {r['label']:20s} n={r['n_total']:4d}  enriched={r['enriched_fraction']*100:5.1f}%  "
          f"cohesion_among_enriched={r['cohesion_among_enriched']*100:5.1f}%  cohesion_overall={r['cohesion_overall']*100:5.1f}%")

print("\n=== PART 2: OTX top-10 pulses (incl. outlier), in-pulse infra cohesion ===")
otx_cohesion = label_infra_cohesion(otx_labels, fp_weighted, top_n=10)
for r in otx_cohesion:
    flag = " <-- outlier pulse" if r["label"] == outlier_pulse_id else ""
    print(f"  {r['label']:28s} n={r['n_total']:5d}  enriched={r['enriched_fraction']*100:5.1f}%  "
          f"cohesion_among_enriched={r['cohesion_among_enriched']*100:5.1f}%  cohesion_overall={r['cohesion_overall']*100:5.1f}%{flag}")

print("\n=== PART 2b: OTX top-10 pulses EXCLUDING outlier ===")
otx_cohesion_no_out = label_infra_cohesion(otx_labels_no_outlier, fp_weighted, top_n=10)
for r in otx_cohesion_no_out:
    print(f"  {r['label']:28s} n={r['n_total']:5d}  enriched={r['enriched_fraction']*100:5.1f}%  "
          f"cohesion_among_enriched={r['cohesion_among_enriched']*100:5.1f}%  cohesion_overall={r['cohesion_overall']*100:5.1f}%")

print("\n=== PART 3: theoretical ceiling -- connectivity sweep by degree threshold ===")
thresholds = [1, 2, 3, 5, 10, 20, 50, 100, 500, None]

print("\n-- vs ThreatFox --")
tf_sweep = ceiling_sweep(fp_weighted, degrees, threatfox_labels, thresholds)
for r in tf_sweep:
    th = r["threshold"] if r["threshold"] is not None else "unrestricted"
    print(f"  threshold={str(th):14s} n_components={r['n_components']:6d}  largest={r['largest_component']:6d}  "
          f"ARI={r['ari']:.4f}  P={r['precision']:.4f}  R={r['recall']:.4f}")

print("\n-- vs OTX (with outlier) --")
otx_sweep = ceiling_sweep(fp_weighted, degrees, otx_labels, thresholds)
for r in otx_sweep:
    th = r["threshold"] if r["threshold"] is not None else "unrestricted"
    print(f"  threshold={str(th):14s} n_components={r['n_components']:6d}  largest={r['largest_component']:6d}  "
          f"ARI={r['ari']:.4f}  P={r['precision']:.4f}  R={r['recall']:.4f}")

print("\n-- vs OTX (without outlier) --")
otx_sweep_no_out = ceiling_sweep(fp_weighted, degrees, otx_labels_no_outlier, thresholds)
for r in otx_sweep_no_out:
    th = r["threshold"] if r["threshold"] is not None else "unrestricted"
    print(f"  threshold={str(th):14s} n_components={r['n_components']:6d}  largest={r['largest_component']:6d}  "
          f"ARI={r['ari']:.4f}  P={r['precision']:.4f}  R={r['recall']:.4f}")

json.dump({
    "threatfox_cohesion": tf_cohesion,
    "otx_cohesion_with_outlier": otx_cohesion,
    "otx_cohesion_without_outlier": otx_cohesion_no_out,
    "outlier_pulse_id": outlier_pulse_id,
    "threatfox_ceiling_sweep": tf_sweep,
    "otx_with_outlier_ceiling_sweep": otx_sweep,
    "otx_without_outlier_ceiling_sweep": otx_sweep_no_out,
}, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/ari_diagnosis_results.json", "w"))

db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
