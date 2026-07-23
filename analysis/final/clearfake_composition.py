import sys, time
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.correlation.campaign_detector import CampaignDetector
from app.evaluation.ground_truth import build_threatfox_labels

t0 = time.time()
db = SessionLocal()
threatfox_labels = build_threatfox_labels(db)
clearfake_set = {v for v, l in threatfox_labels.items() if l == "js.clearfake"}

bfs_clusters = CampaignDetector().find_connected_clusters()
print(f"loaded in {time.time()-t0:.1f}s", flush=True)

touching = [(c, sum(1 for v in c if v in clearfake_set)) for c in bfs_clusters]
touching = [(c, n) for c, n in touching if n > 0]
touching.sort(key=lambda x: len(x[0]), reverse=True)

print(f"\n{len(touching)} clusters touch >=1 js.clearfake member\n")
print(f"{'cluster size':>12}  {'clearfake members':>18}  {'clearfake %':>12}  {'non-clearfake members':>22}")
for c, n in touching:
    pct = 100 * n / len(c)
    print(f"{len(c):>12}  {n:>18}  {pct:>11.1f}%  {len(c)-n:>22}")
