# Analysis scripts — item 6/7 correction cycle, 2026-07-23

These are the ad hoc scripts run directly against the live Postgres/Neo4j
state during the item 6/7 correction cycle documented in `CONTEXT.md`
§6a–§6i and §8. They were originally written to a job-local temp
directory (not part of the repo) and moved here because most of the
specific numbers in CONTEXT.md have no other source — without these
scripts, those numbers are not reproducible, which contradicts §7's
persist-every-run rule and one of the paper's own methodological
findings (Spine 5) about the discipline of re-running rather than
assuming.

**Nothing has been curated, deleted, or rewritten.** Every script that
existed in the job's temp directory is here, including ones that turned
out to be wrong. `analysis/superseded/` in particular is evidence, not
dead weight: `degree_weighting_rc.py` → `rc2.py` → `rc3.py` is the
record of a formula iteration where an earlier attempt was tried and
rejected before the version that shipped in
`app/correlation/confidence_scorer.py`.

None of these scripts are tested, imported by the application, or run in
CI. They talk to a live Postgres/Neo4j instance directly and assume the
schema/data state at the time they were run. Treat them as a lab
notebook, not as library code.

## `analysis/final/` → CONTEXT.md mapping

| Script | CONTEXT.md section(s) | What it produced |
|---|---|---|
| `degree_bucket_final.py` | §6 (item 6) | The original degree-exposure-band `R(C)` gradient (56.4% / 72.4% / 77.2%) — correct methodology at the time; re-run on updated data by `final_spine1_spine3.py` (below), not methodologically superseded, just superseded by a later graph/join state. Both the original and re-run numbers are cited in §8's Spine 3 entry as "old" vs "new". |
| `diagnose_ari.py` | §6d | The ARI diagnosis: per-family cohesion tables, the connectivity-degree-threshold sweep (the `0.2194` figure and its full sweep table), before the join-key fix. |
| `leave_one_out.py` | §6d | The leave-one-family-out decomposition of the `0.2194` connectivity-sweep ARI, isolating `js.clearfake`'s dominance. |
| `clearfake_bfs.py` | §6d/§6e | `js.clearfake`'s composition/solo-under-actual-BFS check (raw, unweighted-reported, weighted-reported) — the numbers that reproduced bit-for-bit three times over the rest of the session. |
| `clearfake_composition.py` | §6d/§6e | The per-cluster composition table (size vs. `js.clearfake` share) for the four largest commodity-hub clusters. |
| `backfill_ip_port.py` | §6b (item 2.4 follow-up) | The live migration of 977 `ip:port`-typed indicators (498 distinct new IPs) and their re-enrichment — 498/498 gained a real ASN. Only version; not superseded. |
| `spine1_neo4j_correct.py` | §6i, task 1 | The corrected (Neo4j-graph-traversal) Spine 1 commodity-hub bridging measurement on the final graph — 838/1,334 touching, Cloudflare 223, `AS13335` 255, 0 collinearity violations. **Final, current §8 numbers.** |
| `big_cluster_recheck.py` | §6i, task 3 | Re-verification of the 1,849-member cluster's size and `AS13335` coverage on the final graph (both unchanged: 1,849, 100.0%). |
| `population_check.py` | §6i, task 5 | The achievable-vs-actual population-equivalence check and the intersection-corrected five-family gap table — the numbers currently in §8's Spine 4 table. |
| `dk_sweep_corrected.py` | §6i, subsection 6 | The `d`/`k` traversal sweep re-run against the population-corrected achievable ceilings — the percentages currently cited in §8's Spine 4 sweep entry. |
| `otx_final.py` | §6h | The OTX (with/without outlier pulse) re-run through the corrected pipeline — the numbers behind Spine 3's 6-confirmation count and Spine 4's "does not universally generalize" finding. |
| `final_table.py` | §6g | The scope-condition table and confidence-filtered baseline comparison (all-clusters and reported, full vs. scoped ARI). |
| `scoped_pr.py` | §6g | The follow-up precision/recall-by-scope correction to `final_table.py`'s output (adds scoped recall alongside full-population recall for every method). |
| `post_rebuild_full.py` | §6f | The first full re-run after the GraphBuilder fix + graph rebuild: BFS ARI weighted vs. unweighted (confirmation #3 in §8's Spine 3 count), the achievable-vs-actual table (later superseded by `population_check.py`'s population-corrected version), and a `d`/`k` sweep (later superseded by `dk_sweep_corrected.py`). Kept in `final/` because its weighted-vs-unweighted confirmation is still cited; its other two sub-results are not the current numbers — see `population_check.py`/`dk_sweep_corrected.py` instead. |
| `final_spine1_spine3.py` | §6i, tasks 1–3 (mixed — see below) | **Task 2 (Spine 3 gradient, final: 61.9%/72.6%/80.3%) is the current source for those §8 numbers.** Task 1 (Spine 1 bridging) used the wrong methodology (Postgres fingerprints instead of Neo4j graph traversal) and was corrected by `spine1_neo4j_correct.py`. Task 3 (1,849-cluster `AS13335` coverage, reported 94.3%) used the same flawed methodology and was corrected by `big_cluster_recheck.py` (100.0%, matching the original). Kept whole, not split, per "do not curate" — this file is itself the record of the methodology-mismatch catch described in CONTEXT.md §6i and Spine 5. |

`analysis/output/item7_run.log` is the log of the *first* full item-7
harness run — produced by `python -m app.evaluation.run_evaluation`, the
actual committed, tested code in `backend/app/evaluation/`, not an ad hoc
script. No corresponding `.py` belongs in `final/`/`superseded/` for it.

## `analysis/superseded/`

| Script | What happened to it |
|---|---|
| `degree_weighting_eval.py` | First full item-6 pass, scored on the blended 0–100 confidence score. Superseded once it became clear `R(C)` is only 20% of that score and needed to be isolated directly. |
| `degree_weighting_rc.py` | First direct `R(C)`-only comparison (the flat-count-over-cluster-size formula) — this is the formula that ended up in `confidence_scorer.py`, but as a standalone check it was superseded by `degree_bucket_final.py`'s cleaner run. |
| `degree_weighting_rc2.py` | A "mean inverse-degree, no cluster-size normalization" formula variant — tried, and rejected in favor of the version in `rc.py`/the shipped code. Negative result, kept as such. |
| `degree_weighting_rc3.py` | Degree-threshold bucket classification exploration, superseded by `degree_bucket_final.py`. |
| `dk_sweep.py` | The original `d`/`k` traversal sweep, pre-graph-rebuild. Superseded first by `post_rebuild_full.py`'s sweep, then by `dk_sweep_corrected.py`'s population-corrected sweep. |

## `analysis/output/`

Every `.json`/`.txt`/`.log` produced by any script above (final or
superseded), plus the three environment-diff artifacts from §6a
(`venv_freeze.txt`, `system_freeze.txt`, `system_freeze_err.txt`,
`venv_diff_report.txt`) and `metastealer_hashes.json` (an empty-result
artifact from the abandoned first attempt at the item-2.4 hash probe,
before discovering `win.metastealer` has zero hash-type indicators —
see CONTEXT.md's correction on that point).

## A known issue in these files, left as-is

Several scripts and logs contain absolute filesystem paths of the form
`/home/<local-username>/...` — these are the paths the job's own temp
directory and this repo's checkout happened to live at when the scripts
were run. They are not secrets, but they are local-machine-specific and
will not resolve on any other machine. Not rewritten, per the instruction
that produced this directory: report, don't silently edit.
