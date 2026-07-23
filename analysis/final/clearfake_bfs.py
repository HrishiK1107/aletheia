import sys, json, time
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.correlation.confidence_scorer import CampaignConfidenceScorer
from app.evaluation.ground_truth import build_threatfox_labels
from app.evaluation.metrics import adjusted_rand_index, build_predicted_labels, pairwise_precision_recall

t0 = time.time()
db = SessionLocal()
ie = InfrastructureEngine()
scorer = CampaignConfidenceScorer()

threatfox_labels = build_threatfox_labels(db)
clearfake_labels = {v: l for v, l in threatfox_labels.items() if l == "js.clearfake"}
print(f"js.clearfake labelled members: {len(clearfake_labels)}", flush=True)

bfs_clusters = CampaignDetector().find_connected_clusters()
fp_unweighted = ie.build_fingerprints(db)
fp_weighted = ie.build_weighted_fingerprints(db)
degrees = ie.compute_feature_degrees(fp_weighted)
print(f"BFS: {len(bfs_clusters)} raw clusters, loaded in {time.time()-t0:.1f}s", flush=True)

def confidence_filtered(clusters, fingerprints, degrees_):
    raw = [{"campaign_id": f"c{i}", "indicators": c, "size": len(c)} for i, c in enumerate(clusters)]
    scored = scorer.score_campaigns(raw, fingerprints=fingerprints, degrees=degrees_)
    return [c["indicators"] for c in scored if c["confidence"] >= 40]

bfs_unweighted_reported = confidence_filtered(bfs_clusters, fp_unweighted, None)
bfs_weighted_reported = confidence_filtered(bfs_clusters, fp_weighted, degrees)

def clearfake_solo_stats(clusters, label="?"):
    # restrict to clusters that contain at least one clearfake member, for cluster-count reporting
    touching = [c for c in clusters if any(v in clearfake_labels for v in c)]
    n_members_in_touching = sum(1 for c in touching for v in c if v in clearfake_labels)

    universe = {v for c in clusters for v in c} | set(clearfake_labels)
    pred = build_predicted_labels(clusters, universe)
    ari = adjusted_rand_index(clearfake_labels, pred)
    precision, recall = pairwise_precision_recall(clearfake_labels, pred)

    sizes = sorted((len(c) for c in touching), reverse=True)
    print(f"\n-- {label} --")
    print(f"  clusters touching >=1 js.clearfake member: {len(touching)}")
    print(f"  js.clearfake members captured in those clusters: {n_members_in_touching} / {len(clearfake_labels)}")
    print(f"  cluster sizes (touching only), largest 10: {sizes[:10]}")
    print(f"  ARI={ari:.4f}  P={precision:.4f}  R={recall:.4f}")
    return {"label": label, "n_touching_clusters": len(touching), "n_captured": n_members_in_touching,
            "sizes_top10": sizes[:10], "ari": ari, "precision": precision, "recall": recall}

results = {}
results["raw_bfs"] = clearfake_solo_stats(bfs_clusters, "raw BFS, all 1,396 clusters (d=2,k=3, no confidence filter)")
results["unweighted_reported"] = clearfake_solo_stats(bfs_unweighted_reported, "BFS reported-only, UNWEIGHTED (confidence>=40)")
results["weighted_reported"] = clearfake_solo_stats(bfs_weighted_reported, "BFS reported-only, WEIGHTED (confidence>=40)")

json.dump(results, open("/home/itzhrixhi/.claude/jobs/4923b6c2/tmp/clearfake_bfs_results.json", "w"), default=str)
db.close()
print(f"\ntotal runtime: {time.time()-t0:.1f}s")
