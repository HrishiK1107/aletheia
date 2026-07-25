# Aletheia

### A Measurement Study of Infrastructure-Based Threat Correlation

---

## What this is

**Aletheia is a measurement study, not a working attribution engine.**

It started as an attempt to build a deterministic pipeline that turns open-source
threat indicators (domains, IPs, URLs, hashes) into attributed adversary
campaigns, using shared infrastructure — ASN, hosting provider, nameserver,
registrar — as the correlation signal. Building it exposed a systematic failure
mode in that entire approach, and the project became about quantifying that
failure mode rather than shipping around it.

**The finding:** infrastructure-based correlation systematically over-clusters
on commodity infrastructure. Shared CDNs, bulk registrars, and free-hosting
platforms get counted as evidence of a shared campaign with exactly the same
weight as a genuinely rare, attacker-specific signal — whether the shared
feature is used by 3 domains or 2,048.

Full methodology, every retraction, and every re-verified number are in
[`CONTEXT.md`](./CONTEXT.md), which is the project's working log and the
source of record for every figure below.

---

## Central result

- **62.8% of detected clusters (838/1,334)** touch a `HostingProvider`/`ASN`
  value that also recurs in other, otherwise-unrelated clusters.
  `Cloudflare, Inc.` alone bridges **223** of them; `AS13335` (Cloudflare's
  ASN) bridges 255. (This is a feature-level fact, not a cluster-level
  verdict — most of those clusters also carry additional, more specific
  shared evidence. Only 2.6% of clusters are strictly commodity-only.)
- **Degree-weighting (scaling each shared feature's evidence weight by its
  inverse global degree) suppresses that contribution mechanically and as
  designed** — a hub feature's score contribution collapses toward zero
  without a blocklist, confirmed across a monotonic exposure-band gradient
  and multiple independent re-runs.
- **It produces no measurable accuracy gain.** Weighted vs. unweighted BFS
  clustering is the *same partition* by construction (weighting changes the
  confidence score, not cluster membership). ARI against ThreatFox ground
  truth is statistically indistinguishable between the two — 0.1525
  (weighted) vs. 0.1540 (unweighted), Δ −0.0015, scoped/confidence-filtered
  identically — confirmed across six independent re-runs on two
  ground-truth datasets, with bootstrapped confidence intervals that
  overlap almost entirely.
- **The recoverable loss is in the traversal, not the weighting.** Measuring
  achievable-vs-actual pairwise recall against five labelled malware
  families, population-matched, shows gaps of 0.64–0.91 that a `d`/`k` BFS
  depth/breadth sweep does not close for any family (best case anywhere in
  the sweep: `js.clearfake` reaches 21.6% of its own achievable ceiling,
  which is itself effectively saturated at 0.9974). Whatever headroom
  exists in this method, it isn't unlocked by fixing the confidence
  formula.
- **BFS still beats naive baselines, independent of the weighting
  question — but not unconditionally.** ~1.7× the next-best baseline on
  ThreatFox (0.1525–0.1540 vs. Jaccard v1's 0.0891) and on OTX-with-outlier
  (0.0386–0.0390 vs. `group_by_hosting_provider`'s 0.0225) — but not on
  OTX-without-outlier, where two naive baselines beat it. 2 of 3 tested
  ground-truth configurations confirm; scoped accordingly, not claimed as
  general.

The confidence score itself is **not discarded but frozen**: its known
formula defects (`R(C)`'s cluster-size normalization, a near-constant
`D(C)` term, a circular `E(C)` term) are documented as limitations rather
than patched, because patching them would invalidate the six-way
weighted/unweighted comparison above. This is a documented, deliberate
scoping decision, not an oversight — the score should not be read as a
reliable discriminator of true positive campaigns.

---

## Ground truth

A common assumption in this space is that indicator-level ground truth
for evaluating correlation/clustering methods doesn't exist in open-source
threat intelligence. It does, for a meaningful subset: ThreatFox tags a
portion of its indicators with a malware family, and OTX pulses are
themselves pre-grouped by campaign — both usable directly as
indicator-level labels without building a synthetic dataset. This is
**not** a claim that every collected indicator is labelled — ThreatFox
and OTX supply labels only for the indicators each of them tags, and
sourcing/validating that subset (including the decision to exclude
ThreatFox's `'Unknown malware'` bucket, and reporting OTX both with and
without its one outsized pulse) is itself part of this project's
contribution: showing this narrower, indicator-level ground truth is
usable at all, not asserting universal coverage.

---

## Reproducibility

- **Every figure cited above and in the paper maps to a specific,
  documented command** — see `CONTEXT.md` §6m for the full figure-to-command
  table (graph composition, Spine 1–5 measurements, bootstrap CIs, the
  window-2 replication run, all of it).
- **155/155 tests pass.** The suite (`backend/tests/`) covers ingestion,
  enrichment, graph construction, clustering, confidence scoring, and the
  evaluation harness itself (determinism, bootstrap bias diagnostics,
  ground-truth loading).
- **Reproducibility scripts are public**: `analysis/final/` contains every
  script of record behind a paper figure; `analysis/output/` has their
  output. `analysis/superseded/` keeps earlier, since-corrected versions for
  provenance.
- Raw evaluation run artifacts (baseline runs, item-7 evaluation output,
  bootstrap CI results) are committed under `evaluation_runs/`.
- **Two figures are dated snapshots, not reproducible constants**:
  collection volume (23,427 indicators/run across five feeds, 2026-07-23
  snapshot) and pipeline timings (enrichment 18.3 min for 22,642
  indicators; full graph build 20.5 min for 23,135 indicators) are
  wall-clock measurements against live, rate-limited third-party feeds and
  the then-current database state. The documented commands reproduce the
  *procedure* exactly — re-running them will not reproduce these exact
  counts or durations, which vary with feed activity and network
  conditions. Cite them as measured, not as guaranteed constants.

---

## Honest limitations

- **Effectively one collection window, not two independent ones.** A
  second collection window was run to test temporal stability, but
  ThreatFox's 7-day lookback and OTX's recency-ordered pulls mean the two
  windows share ~86% of their indicators regardless of pipeline behavior.
  This is a weak test of temporal stability, not a null one, and is
  reported as such rather than oversold.
- **The confidence formula (`R(C)`, `N(C)`, `D(C)`, `E(C)`) is frozen with
  documented defects**, not fixed, to keep the weighted/unweighted
  comparison valid. See `CONTEXT.md` §6g for the freeze decision and every
  known defect.
- **No confidence intervals on the traversal recall gaps** (Spine 4) — the
  achievable-vs-actual figures and the `d`/`k` sweep are point measurements,
  not bootstrapped, unlike the ARI figures in Spine 3.

---

## Data dependency: GeoLite2

ASN/hosting-provider enrichment uses MaxMind's GeoLite2-ASN database,
loaded from a local `.mmdb` file (`data/GeoLite2-ASN.mmdb`, gitignored).
**GeoLite2 is required to run the pipeline but is not redistributed in
this repository** — MaxMind's license does not permit that. Sign up for a
free MaxMind account and download your own `GeoLite2-ASN.mmdb` snapshot
from MaxMind's [GeoLite2 download page](https://www.maxmind.com/en/geolite2/signup)
(terms: [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula))
to reproduce enrichment or the ASN/hosting-provider figures above.

---

## Tech stack

* **Backend**: Python (FastAPI)
* **Database**: PostgreSQL
* **Graph Database**: Neo4j
* **Queue System**: Redis
* **Workers**: Async processing pipeline

---

## Paper

The full manuscript — methodology, complete results section, and
discussion — is maintained outside this repository. `CONTEXT.md` is the
working log behind it: every measurement, every correction, and the
reasoning behind every reported number.

---

## License

This project is intended for research and educational purposes.

---

## Author

Developed as part of a research-focused threat intelligence system.
