import sys, statistics
sys.path.insert(0, '.')
from collections import Counter
from app.correlation.campaign_detector import CampaignDetector
from app.correlation.confidence_scorer import CampaignConfidenceScorer


def classify(value: str) -> str:
    """Exact per-value classification `_type_diversity()` uses internally --
    lifted out here so the population-level distribution and the per-cluster
    D(C) figures are guaranteed to be measuring the same thing."""
    if value.startswith("http"):
        return "url"
    if value.count(".") == 3 and all(part.isdigit() for part in value.split(".")):
        return "ip"
    if "." in value:
        return "domain"
    return "hash"


clusters = CampaignDetector().find_connected_clusters()
scorer = CampaignConfidenceScorer()

print(f"clusters: {len(clusters)}")

# --- 1. Population-level type distribution over cluster members ---
all_members = [v for c in clusters for v in c]
type_counts = Counter(classify(v) for v in all_members)
total = len(all_members)

print(f"\n--- indicator type distribution, cluster members only (n={total}) ---")
for t, n in type_counts.most_common():
    print(f"  {t:<8} {n:>7,}  ({100*n/total:.1f}%)")

# --- 2. D(C) measured directly across all 1,334 clusters ---
dc_values = [scorer._type_diversity(c) for c in clusters]
dc_counter = Counter(round(v, 4) for v in dc_values)

print(f"\n--- D(C) distribution across {len(clusters)} clusters ---")
for v, n in sorted(dc_counter.items()):
    print(f"  D(C)={v:.4f}  {n:>5} clusters  ({100*n/len(clusters):.1f}%)")

print(f"\ndistinct D(C) values: {len(dc_counter)}")
print(f"mean:     {statistics.mean(dc_values):.4f}")
print(f"variance: {statistics.pvariance(dc_values):.6f}  (population variance)")
print(f"stdev:    {statistics.pstdev(dc_values):.4f}")
print(f"min/max:  {min(dc_values):.4f} / {max(dc_values):.4f}")

# --- 3. Per-cluster type-set breakdown (which combinations actually occur) ---
type_set_counter = Counter()
for c in clusters:
    types = frozenset(classify(v) for v in c)
    type_set_counter[types] += 1

print("\n--- per-cluster distinct-type-set breakdown ---")
for types, n in type_set_counter.most_common():
    label = "+".join(sorted(types)) if types else "(empty)"
    print(f"  {{{label}}}: {n} clusters ({100*n/len(clusters):.1f}%)")
