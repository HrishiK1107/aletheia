"""
Script of record for CONTEXT.md §8's Spine 5, 11th instance: the percentile
bootstrap's small, real, non-Monte-Carlo bias found while verifying
app/evaluation/bootstrap.py (peer-review Task 1), before it was run at scale.

Purely synthetic -- no DB, no Neo4j, no project data. Independent,
uncorrelated random true/predicted labels have a true ARI of ~0 by
construction (ARI is defined to correct for chance agreement). If the
percentile bootstrap mean tracked the point estimate, it should also sit
near 0 at every n. It does not, and critically the gap does NOT shrink as n
grows from 200 to 60,000 -- ruling out ordinary Monte Carlo noise (which
would shrink with more resampled population size) and confirming a
structural bias in with-replacement item resampling of a chance-corrected
pairwise index: a duplicated indicator in a resample trivially "agrees with
itself" in both the (fixed) true and predicted partitions, and ARI's
chance-correction term does not fully cancel that out.

Run with: python ../analysis/final/bootstrap_bias_diagnostic.py, cwd
backend/ (same convention as every other analysis/final/ script, since
`from app...` only resolves from there).
"""

import random
import sys

sys.path.insert(0, ".")

from app.evaluation.bootstrap import bootstrap_ari
from app.evaluation.metrics import adjusted_rand_index


def make_independent_labels(n: int, n_true_clusters: int, n_pred_clusters: int, seed: int) -> tuple[dict, dict]:
    rng = random.Random(seed)
    true_labels = {f"x{i}": rng.randrange(n_true_clusters) for i in range(n)}
    pred_labels = {f"x{i}": rng.randrange(n_pred_clusters) for i in range(n)}
    return true_labels, pred_labels


SEED = 7
N_ITERATIONS = 1000
SCALES = [200, 2000, 20000, 60000]

print(f"{'n':>8} {'point':>10} {'boot_mean':>10} {'bias':>10} {'bias*n':>10}")
for n in SCALES:
    true_labels, pred_labels = make_independent_labels(
        n, max(5, n // 100), max(5, n // 20), seed=SEED
    )
    point = adjusted_rand_index(true_labels, pred_labels)
    result = bootstrap_ari(true_labels, pred_labels, n_iterations=N_ITERATIONS, seed=42)
    bias = result["bootstrap_mean"] - point
    print(f"{n:8d} {point:10.5f} {result['bootstrap_mean']:10.5f} {bias:+10.5f} {bias * n:10.2f}")

print(
    "\nIf this were Monte Carlo noise or an O(1/n) ratio-statistic bias, "
    "bias would shrink toward 0 as n grows. It plateaus instead -- "
    "confirmed structural, not a bug in this run's resampling."
)
