"""
CONTEXT.md §6p / Task 2: bootstrap CIs for exactly the three cells
pre-registered for window 2 -- ThreatFox, scoped,
bfs_unweighted_reported_only / bfs_weighted_reported_only /
jaccard_v1__reported -- not the full 42-cell grid app.evaluation.run_bootstrap
computes for window 1 (§6p explicitly scopes this down, since only these
three feed quantities 2 and 3 of the pre-registration).

Reuses app.evaluation.run_bootstrap's own build_methods_and_ground_truth()
unmodified, and app.evaluation.bootstrap.bootstrap_ari() unmodified --
just narrows which cells get bootstrapped and how many iterations, driven
by window-2 environment variables (must already be set before this
process starts).
"""

import json
import sys
import time
from datetime import UTC, datetime

sys.path.insert(0, ".")

from app.core.config import settings  # noqa: E402

assert "window2" in settings.postgres_dsn, "REFUSING: postgres_dsn does not look like window2"
assert ":7688" in settings.neo4j_uri, "REFUSING: neo4j_uri does not look like window2"

from app.evaluation.bootstrap import bootstrap_ari  # noqa: E402
from app.evaluation.metrics import build_predicted_labels  # noqa: E402
from app.evaluation.run_bootstrap import N_ITERATIONS, SEED, build_methods_and_ground_truth  # noqa: E402
from app.evaluation.run_evaluation import restrict_to_scope  # noqa: E402

t0 = time.time()
methods, ground_truths, fp_weighted = build_methods_and_ground_truth()

threatfox = ground_truths["threatfox"]
scoped_labels = restrict_to_scope(threatfox, fp_weighted)
print(f"ThreatFox scoped: {len(scoped_labels)}/{len(threatfox)}", flush=True)

results = {
    "generated_at": datetime.now(UTC).isoformat(),
    "n_iterations": N_ITERATIONS,
    "seed": SEED,
    "ci_level": 0.95,
    "reported_ci": "pivotal",
    "scope": "ThreatFox scoped only -- pre-registered subset, §6p",
    "cells": {},
}

for method_name in ["bfs_unweighted_reported_only", "bfs_weighted_reported_only", "jaccard_v1__reported"]:
    clusters = methods[method_name]
    universe = {v for c in clusters for v in c} | set(scoped_labels)
    pred = build_predicted_labels(clusters, universe)

    t_m = time.time()
    ci = bootstrap_ari(scoped_labels, pred, n_iterations=N_ITERATIONS, seed=SEED)
    results["cells"][method_name] = ci
    print(
        f"  {method_name:32s} ARI={ci['point_estimate']:.4f} "
        f"pivotal=[{ci['pivotal_ci_lower']:.4f}, {ci['pivotal_ci_upper']:.4f}] "
        f"pctile=[{ci['percentile_ci_lower']:.4f}, {ci['percentile_ci_upper']:.4f}] "
        f"({time.time() - t_m:.1f}s)",
        flush=True,
    )

out_path = "../evaluation_runs/window2_dumps/bootstrap_targeted_window2.json"
json.dump(results, open(out_path, "w"), indent=2, default=str)
print(f"\nWrote {out_path}")
print(f"Total runtime: {time.time() - t0:.1f}s")
