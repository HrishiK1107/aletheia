# Aletheia — Project Context

Read this at the start of every session. It defines what this project is, what is
wrong with it, and what "done" looks like.

---

## 1. What this is

Aletheia is a deterministic, label-free threat intelligence correlation pipeline.
It ingests open-source IOCs, enriches them with infrastructure data, builds a Neo4j
property graph, clusters indicators into candidate campaigns via shared
infrastructure, and assigns explainable confidence scores.

**Stack:** Python 3.13, FastAPI, PostgreSQL, Redis, Neo4j 5, Docker Compose.
**Hard constraint:** everything must be free. No paid APIs, no paid services, no GPU.
Single Linux machine with Docker.

**Pipeline:** ingestion → enrichment → graph build → clustering → scoring → REST API

Workers are standalone processes under `app.workers.*`. Campaign detection is
triggered by `POST /campaigns/run`.

**Run order:**
```bash
cd docker && docker compose up -d          # postgres, redis, neo4j
cd backend && uvicorn app.main:app --reload
curl http://localhost:8000/feeds/collect   # collect → Redis queue
python -m app.workers.ingestion_worker     # Redis → Postgres
python -m app.workers.enrichment_worker    # DNS/ASN/WHOIS
python -m app.workers.graph_worker         # Postgres → Neo4j
curl -X POST http://localhost:8000/campaigns/run
```

---

## 2. Why this rewrite is happening

This is being taken from a working prototype to a publishable research artifact.
Target: a Scopus-indexed security journal, ideally Q1/Q2.

The current version does not support a defensible research claim. The reasons are
specific and listed below. **The goal is not more features — it is a system whose
results can survive peer review.**

---

## 3. The research claim we are building toward

Not "we built a pipeline." That is unpublishable.

**The claim:**
> Infrastructure-based CTI correlation systematically over-clusters on commodity
> infrastructure (shared hosting, CDNs, common nameservers). We quantify this
> failure mode and present a degree-weighted correlation method that suppresses it
> without hardcoded blocklists, validated against labelled data.

This is defensible because it identifies a flaw in an entire class of systems —
including our own prior version — and fixes it with a principled, measurable method.

**The result that proves it:**

| Method | Clusters | ARI vs. labels | Precision | Recall | Commodity-infra FP rate |
|---|---|---|---|---|---|
| Random baseline | | ~0.00 | | | |
| GROUP BY ASN | | | | | high |
| GROUP BY resolved IP | | | | | high |
| Jaccard fingerprint (v1 method) | | | | | high |
| BFS d=2, unweighted | | | | | high |
| **BFS + inverse-degree weighting** | | | | | **low** |

If the last row wins on ARI *and* drops the commodity false-positive rate, the paper
is sound. If it does not, we report that honestly and rethink — do not massage
numbers to fit this table.

---

## 4. Known defects — ordered by severity

### TIER 1 — fatal, fix first

**1.1 The paper describes dead code.**
`app/correlation/campaign_detector.py` implements BFS clustering (d=2, k=3,
lexicographic seed ordering) and its docstring cites "paper, Section 3.5".
**It is never called by the pipeline.** Only tests reference it.
`CampaignEngine.detect_campaigns()` actually calls
`InfrastructureEngine.detect_clusters()` — Jaccard similarity, threshold 0.75,
`len(cluster) > 1`.
So the published algorithm and the executed algorithm are different.
**Fix:** wire `CampaignDetector` into `CampaignEngine`. Retire the Jaccard path or
keep it explicitly as a labelled baseline for comparison.

**1.2 Ground truth is discarded at ingestion.**
ThreatFox returns `malware`, `malware_printable`, `threat_type`, `tags`,
`confidence_level`, `first_seen`, `reporter`. The parser keeps only `ioc` and
`ioc_type`. **The malware family field is a campaign label.**
Same problem: MalwareBazaar returns `signature`; OTX pulse IDs are campaign groupings.
Without these there is no evaluation and no paper.
**Fix:** carry a `labels: dict` through the schema, persist into
`raw_indicators.raw_payload` (already a JSON column), build the evaluation set from it.

**1.3 Clustering is not connected components.**
`InfrastructureEngine.detect_clusters` compares every candidate against the seed
only — not transitive, order-dependent. Determinism comes from dict insertion order,
not from the algorithm.
**Fix:** superseded by 1.1; the BFS traverses properly.

**1.4 No cross-run deduplication.**
`raw_indicators` accumulated 1344 rows from two collections of ~670. Nothing
deduplicates on `value` across runs. `dedupe_engine.py` exists but is not called
from the ingestion path.
**Fix:** unique constraint on `raw_indicators.value` + `ON CONFLICT DO NOTHING`,
or wire `dedupe_engine` in properly.

### TIER 2 — method quality

**2.1 Commodity infrastructure destroys precision. THIS IS THE CONTRIBUTION.**
`hosting_provider` is derived from an 8-entry hardcoded suffix map in
`enrichment_worker.py` — `pages.dev`, `vercel.app`, `blogspot.com`, etc. Those are
exactly the free platforms every unrelated phishing kit uses.
Observed failure: four unrelated Vercel URLs scored 70/100 as a "medium confidence
campaign" sharing nothing but a hosting provider used by millions.
**Fix:** weight each infrastructure feature by inverse node degree, computed from
the graph. A nameserver shared by 3 domains carries weight; one shared by 3,000
carries ~0. No blocklist — it self-suppresses. This is the novel method.

**2.2 The scoring function is broken in four ways.**
`score(C) = 0.30·N + 0.30·D + 0.20·R + 0.20·E`
- `D(C)` type diversity — 30% of the score, but ~90% of input is URLs, so it is a
  near-constant offset, not a signal
- `N(C)` normalised against the largest cluster *in the same run*, so scores are not
  comparable across runs — this invalidates any aggregate claim over multiple runs
- `R(C)` counts shared features but ignores how strongly they are shared: a feature
  in 2 of 50 members counts the same as one in 50 of 50
- `E(C)` enrichment completeness — 20% of the score measures whether our own
  pipeline succeeded, not whether the campaign is real. Circular.

**Fix:** `D` becomes meaningful once feeds are fixed and hashes/IPs arrive.
`N` → absolute, log-scaled. `R` → mean inverse-degree of shared infrastructure.
`E` → remove from confidence entirely; report separately as a data-quality metric.

**2.3 Enrichment uses only the first resolved IP.**
`asn_data = safe_lookup(lookup_asn, ips[0])`. A domain resolving to 5 IPs across
3 ASNs records one ASN. Load-balanced infrastructure is exactly what campaigns use.
**Fix:** iterate all IPs, store all ASNs.

**2.4 Hashes receive no enrichment.**
`enrich_indicator` handles `ip`, `domain`, `url`. Hashes fall through with an empty
fingerprint and are unclusterable.
**Fix:** cluster hashes via shared C2 infrastructure and MalwareBazaar `signature`.

**2.5 Redundant graph layer inflates a reported metric.**
Every IOC creates both a typed node (`:URL`) and a generic `:Indicator` node joined
by `:INDICATES` — ~670 wasted nodes. Graph Expansion Factor is reported in the paper
and is partly counting our own duplication.
**Fix:** drop the generic layer, or exclude it from GEF.

**2.6 Enrichment is serial.**
~1–3s per indicator. At 30,000 indicators that is 10–25 hours.
**Fix:** thread pool (20–50 workers) + local DNS cache. Target: under an hour.

### TIER 3 — evaluation

**3.1 No baselines, no ground-truth comparison, no statistical test.**
All current metrics are structural (cluster coherence, infrastructure reuse rate).
Structural metrics cannot distinguish a real campaign from a shared CDN.
**Fix:** build the table in §3. Adjusted Rand Index against ThreatFox malware
families, plus pairwise precision/recall.
**Class skew note (2026-07-22):** ThreatFox family labels are heavily skewed —
top 2 of 81 families are ~47% of the labelled set (§5). Aggregate ARI over this
set will be dominated by MetaStealer/ClearFake and can look good while the
system fails on smaller families entirely. Report per-family precision/recall
alongside aggregate ARI, not instead of it.

**3.2 Parameters are asserted, not derived.**
`d=2`, `k=3`, Jaccard `0.75` have no empirical justification.
**Fix:** sweep each, plot ARI against the parameter, select the peak. Report the sweep.

---

## 5. Ingestion volume — currently ~670/run, ceiling is 30,000–60,000

This is the bottleneck on everything downstream. Bigger N means tighter confidence
intervals, more infrastructure overlap, and a dataset a reviewer takes seriously.

| Feed | Now | Cause | Fix | After |
|---|---|---|---|---|
| ThreatFox | 373 | `{"query": "get_iocs"}` with no `days` param defaults to 1 day | ~~add `"days": 90` (API max)~~ **corrected 2026-07-22:** the live API rejects anything outside 1–7 (`"illegal_days"`); 90 was never valid. `days: 7` verified live → 4,019 IOCs. There is no larger single-call window — higher volume needs the same accumulate-over-time strategy as OpenPhish below. | 4,019/week (verified), not 20,000–40,000 |
| OTX | 0 | hits `/indicators/export`, a bulk endpoint that times out at 20s | use `/api/v1/pulses/subscribed?limit=50&page=N` with pagination — **pulses are pre-grouped by campaign = free ground truth** | 5,000–15,000 |
| MalwareBazaar | 0 | `get_recent` + `selector: "time"` returns the last hour, often empty | `selector: "100"`, or query by signature for family-labelled batches | 1,000+ |
| OpenPhish | 300 | free feed is capped at ~500 most recent, refreshes every 12h — hard ceiling | accumulate: poll every 12h over several days | 4,000+ over a week |

**Done: ThreatFox `days: 7` (verified max) + labels captured.** Live `days=7` pull
returned 4,019 IOCs, 100% with non-null `malware`, 81 distinct families. Top families:
MetaStealer 997, ClearFake 893, Unknown malware 603, Cobalt Strike 265, Vidar 252.

Two decisions locked in for the evaluation harness (item 7):
- **Exclude `'Unknown malware'` from ground truth.** It is ThreatFox's explicit
  "not attributed" label, not a family — clustering those IOCs together would
  reward grouping unrelated indicators. Filter it out of the labelled eval set.
- **Class skew is real and must be handled in reporting.** Top 2 families
  (MetaStealer + ClearFake) are ~47% of the labelled set. Aggregate ARI alone
  will be dominated by those two families — see item 3.1.

`ioc_type` values outside the normalized `{ip, domain, url, hash}` set are common
in practice: `ip:port` (980), `sha256_hash` (123), `sha1_hash`/`md5_hash` (76 each).
These pass through unvalidated/unnormalized today — logged at runtime by the
collector, tracked as item 2.4.

---

## 6. Work order — target one week

1. ~~ThreatFox `days: 90`~~ ThreatFox `days: 7` (verified max) + capture labels —
   **done 2026-07-22**, see §5
2. Fix OTX and MalwareBazaar endpoints — half day — **in progress**
3. Wire `CampaignDetector` in, retire Jaccard as a baseline — half day
4. Dedup constraint — 1 hour
5. Parallel enrichment + DNS cache — 1 day
6. Inverse-degree weighting — 2 days — **the contribution**
7. Evaluation harness + ARI + baselines — 2 days
8. Parameter sweeps — 1 day

Then rewrite the paper around whatever the results actually show.

---

## 7. Rules for this work

- **Persist every run.** The previous evaluation was lost because nothing was saved
  outside the containers. Dump Neo4j, dump Postgres, export clusters to CSV after
  every run, into a timestamped directory. `docker compose down -v` wipes everything.
- **Keep the test suite green.** 44 test files and CI already exist. New code needs tests.
- **Report honest numbers.** If degree weighting does not beat the baselines, that is
  the finding. Do not tune until the table looks good.
- **Determinism is a claimed property.** Same graph state must produce the same
  partition. Test it explicitly.
- **Every model must be imported in `app/db/model_registry.py`** or SQLAlchemy will
  not create its table. This has already caused one silent failure where
  `raw_indicators` did not exist and every ingestion write failed quietly.
