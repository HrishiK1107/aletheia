import sys, csv
sys.path.insert(0, '.')
from app.correlation.campaign_detector import CampaignDetector

clusters = CampaignDetector().find_connected_clusters()

out_path = "../analysis/output/cluster_sizes.csv"
with open(out_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["cluster_index", "size"])
    for i, c in enumerate(clusters):
        w.writerow([i, len(c)])

sizes = [len(c) for c in clusters]
print(f"wrote {len(clusters)} rows to {out_path}")
print(f"min={min(sizes)}  max={max(sizes)}  mean={sum(sizes)/len(sizes):.2f}  total_members={sum(sizes)}")
