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

**Filled in 2026-07-23 (item 7, first run) — ThreatFox ground truth (4,108
labelled indicators, cleaner than OTX per §5's pulse-skew caveat). Full
numbers, all three ground truths, and per-size-band breakdowns are in the
item 7 write-up below and in `evaluation_runs/item7_eval_*.json` — this
table is the summary, not the full result, and the honest headline is
mixed: read the write-up before citing any single cell.**

| Method | Clusters | ARI vs. labels | Precision | Recall | Commodity-infra FP rate |
|---|---|---|---|---|---|
| Random baseline | 1,396 | 0.0000 | 0.1481 | 0.0006 | 19.77% |
| GROUP BY ASN | 256 | 0.0530 | 0.3480 | 0.0499 | 9.77% |
| GROUP BY resolved IP | 579 | 0.0062 | 0.9982 | 0.0036 | 0.00%¹ |
| GROUP BY hosting_provider | 245 | 0.0530 | 0.3479 | 0.0499 | 8.16% |
| Jaccard fingerprint (v1 method) | 1,274 | 0.0432 | 0.9842 | 0.0258 | 3.22% |
| BFS d=2, unweighted (reported, confidence≥40) | 711 | 0.0716 | 0.5375 | 0.0523 | 3.94% |
| **BFS + inverse-degree weighting (reported, confidence≥40)** | 367 | 0.0712 | 0.5364 | 0.0521 | **0.27%** |

¹ Structural zero, not evidence of quality — see item 7 write-up: the
commodity-only classifier only recognizes `org` (merged ASN/hosting) as
"commodity," so an IP-only-grouped cluster can never score positive on it
by construction, regardless of whether that shared IP is itself a hub.

**`GROUP BY hosting_provider` added 2026-07-23** as its own baseline row,
separate from `GROUP BY ASN`, even though item 2.1 established the two are
1:1 collinear in this dataset. The point of this row isn't to test a
different signal — it's that `Cloudflare, Inc.` alone bridges 223 of
1,396 clusters (item 2.1), so grouping directly on hosting_provider should
produce a small number of enormous, mostly-unrelated groups. Showing that
baseline fail on ARI/precision is direct, legible evidence for the central
claim (§3): the naive thing every unweighted infrastructure-correlation
tool effectively does — group by a shared hosting signal — collapses
exactly where this paper says it will.

If the last row wins on ARI *and* drops the commodity false-positive rate, the paper
is sound. If it does not, we report that honestly and rethink — do not massage
numbers to fit this table.

**Item 7 methodology requirements, locked in 2026-07-23, before the harness
is built:**
- **Stratify precision/recall and ARI by cluster size band** (3–5, 6–10,
  11–50, 50+), for every method in the table, not just the two BFS rows.
  Required because item 2.2 found `R(C)` before/after comparisons are
  confounded with cluster size — the same confound could hide in ARI/
  precision if degree-weighting's apparent advantage only shows up in one
  size band. If it only helps small clusters, that is a limitation to
  disclose, not a result to average away.
- **`BFS d=2, unweighted` and `BFS + inverse-degree weighting` produce the
  identical cluster partition** — degree-weighting changes `R(C)`
  (confidence), not BFS traversal or cluster membership. Their raw ARI
  will therefore be identical by construction, and that must be reported
  as identical, not worked around. Precision/recall for these two rows are
  computed over *reported* campaigns — clusters whose confidence score
  clears the existing medium-confidence threshold (`>=40`,
  `CampaignConfidenceScorer.classify_confidence`) — using each row's own
  confidence numbers (old formula for the unweighted row, degree-weighted
  formula for the weighted row). This is where the two rows can actually
  differ: weighting can push commodity-only clusters below the threshold
  (excluded from "reported campaigns", raising precision) while
  potentially also pushing some genuine clusters below it too (lowering
  recall) — which is exactly the open question item 6 left unresolved and
  is what this measurement settles.
- **OTX ARI reported both including and excluding the 4,499-indicator
  outlier pulse** (§5's open decision — "The Evolution of ClickFix..."),
  not just one or the other.

**Framing lock, 2026-07-23 — read before touching item 6, and before writing
any results section that cites the 68% number.** The full-volume
re-measurement (item 2.1) found that 953/1,396 clusters (68.3%) touch a
commodity `HostingProvider`/`ASN` hub value that also appears in other,
otherwise-disjoint clusters. It is tempting to summarize this as "68% of
detected campaigns are false positives." **That claim is not defensible and
must not appear in the paper.** Only 36/1,396 (2.6%) are *strictly*
commodity-only — their entire shared-evidence set is the commodity
ASN/HostingProvider pair and nothing else. The other 980/1,396 (70%) that
touch a hub value also have at least one more specific attribute
(`Nameserver`, `Registrar`, `ResolvedIP`) as additional, real corroboration.
Touching a hub is a *feature-level* fact; it is not a *cluster-level*
verdict.

**The defensible claim:** commodity infrastructure features (a shared CDN,
a shared bulk registrar, a shared free-hosting platform) contribute *full
weight* to the existing confidence score despite carrying almost no
discriminative value — the same one-bit "shared/not-shared" credit whether
the feature is used by 3 domains or 2,048. Degree-weighting corrects that
contribution by scaling each feature's evidence weight by its inverse
global degree, so a hub feature's contribution collapses toward zero
without needing a blocklist, while a feature that is actually rare keeps
most of its weight.

**Item 6's success metric follows directly from this and must be reported
as such:** *the score contribution of commodity features drops to
near-zero, while clusters with genuine, specific shared evidence largely
retain their score.* Not: *"false-positive clusters get removed."*
Concretely, the test is a two-sided one on `R(C)`, run over the same
1,396-cluster baseline:
- The 36 strictly commodity-only clusters (2.6%) should lose most of their
  `R(C)` contribution after weighting.
- The 980 clusters with genuine additional evidence (70%) should largely
  retain theirs.
- **If the second bucket also collapses, the weighting is too aggressive**
  — that is a failure of the method, not a stronger result, and must be
  reported as such, not tuned away.

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
**Done 2026-07-23:** `CampaignEngine.detect_campaigns()` now calls
`CampaignDetector.find_connected_clusters()` (the BFS/d=2/k=3 method the paper
actually describes). `InfrastructureEngine.detect_clusters()` (Jaccard, 0.75)
is kept, unchanged, as an explicitly-documented, separately-callable baseline
for the §3 results table — deliberately not deleted and deliberately not
wired back into `CampaignEngine`. `InfrastructureEngine.build_fingerprints()`
(Postgres enrichment) still feeds the R(C)/E(C) scoring inputs regardless of
which algorithm produced the clusters — clustering and scoring are
independent concerns. Verified live against the real Neo4j graph (670 nodes
from a prior collection run): BFS found 32 clusters, sizes 3–10+, all
persisted to `campaigns`. The Jaccard baseline returned 0 in the same
verification run, but only because Postgres `indicator_enrichment`/
`indicators` were empty at the time (see the test-DB-wipe finding below) —
not a regression in Jaccard itself.

**Related finding, hit while verifying this, fixed 2026-07-23:**
`conftest.py`'s session-scoped fixture ran `Base.metadata.drop_all()` /
`create_all()` against `app.db.postgres.engine` — the same DSN as the live
dev database, not an isolated test database. Running `pytest` at any point
wiped every Postgres table in the dev DB (both at session start and again at
teardown), including `raw_indicators`/`campaigns`/`feed_runs` from real
collection or detection runs — directly contradicting §7's "persist every
run" rule. **Fixed:** a real `aletheia_test` database now exists (same
Postgres container, separate database), `test_database_url` is a config
setting pointing at it, `conftest.py` builds its own engine/session bound to
that DSN, and `app/core/db_safety.py::ensure_distinct_databases()` runs at
conftest import time — before any fixture or test executes — and raises
`RuntimeError` immediately if `test_database_url` and `postgres_dsn` ever
resolve to the same `(host, port, database)`, regardless of matching
credentials. Verified: the guard fires and refuses to collect tests when
misconfigured to match; the dev DB's tables were confirmed unchanged (via
direct inspection) both before and after a full test run once the fix was
in place. Covered by `tests/test_db_safety.py` (6 cases: distinct DBs
allowed, same DB blocked, credentials don't mask identity, default-port
normalization, different host allowed).

**Concrete proof this was a real risk, not theoretical:** the 23,447-indicator
live collection pushed to Redis while verifying the FeedRun wiring (previous
commit) was drained into the dev DB's `raw_indicators`/`indicators` tables by
a subsequent `pytest` run's `process_indicator_queue()` call, then destroyed
moments later by that same test session's teardown `drop_all()` — before this
fix existed. The data itself was disposable (a live-collector re-run
reproduces it), but the mechanism is exactly what this fix closes off.

**Related finding, fixed 2026-07-23: the same class of risk existed for
Redis.** `test_ingestion_pipeline.py` calls `process_indicator_queue()`,
which drains `indicator_queue.py`'s real Redis queue via a
`while True: dequeue... until empty` loop — there was no test-specific
Redis database. **Fixed:** `test_redis_url` setting, defaulting to
`redis://localhost:6379/1` — Redis's logical-database feature (16 per
server, `SELECT`ed via the URL path) gives the same same-container
isolation as `aletheia_test` did for Postgres, no second Redis instance
needed. `ensure_distinct_redis_targets()` (`app/core/db_safety.py`) runs
at conftest import time and raises if `test_redis_url`/`redis_url` ever
resolve to the same `(host, port, db index)`.

Implementation differs from the Postgres fix in one way worth noting:
`redis_client` (`app/db/redis.py`) is a single module-level singleton
imported *by reference* everywhere (`indicator_queue.py`, etc.), not a
factory like `SessionLocal` — so instead of monkeypatching every import
site, `conftest.py` redirects the shared object once, by swapping its
`.connection_pool` to one built from `test_redis_url`. Every module that
already imported `redis_client` transparently starts talking to the test
database, verified directly: writes before the swap land in db 0, writes
after land in db 1, and a value written to db 0 before a full `pytest` run
was confirmed still present after. The guard rail was also verified to
fire and block test collection when deliberately misconfigured to match.
Covered by 5 cases in `tests/test_db_safety.py` (mirroring the Postgres
guard's test shape: distinct index allowed, same target blocked, explicit
`/0` vs. default treated as identical, default-port normalization,
different host allowed).

**1.2 Ground truth is discarded at ingestion.**
ThreatFox returns `malware`, `malware_printable`, `threat_type`, `tags`,
`confidence_level`, `first_seen`, `reporter`. The parser keeps only `ioc` and
`ioc_type`. **The malware family field is a campaign label.**
Same problem: MalwareBazaar returns `signature`; OTX pulse IDs are campaign groupings.
Without these there is no evaluation and no paper.
**Fix:** carry a `labels: dict` through the schema, persist into
`raw_indicators.raw_payload` (already a JSON column), build the evaluation set from it.
**Update 2026-07-23:** done for ThreatFox, OTX, MalwareBazaar. Added URLhaus as a
fifth source specifically to label OpenPhish's URL population (OpenPhish itself
carries no labels at all — 0% usable, see §5). URLhaus's label quality is weaker
than the other three: its bulk endpoint has no clean, separate malware-family
field — family names, when present, are unstructured strings mixed into `tags`
alongside architecture/format noise (`ua-wget`, `opendir`, `censys`, `ascii` are
not families). A clean per-payload `signature` exists only via the single-URL
lookup endpoint, at a cost of one API call per URL (~900+/run) — not implemented.

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
**Done 2026-07-23:** unique constraint on `(value, source)` — deliberately
not `value` alone. The same value from a *different* feed is cross-feed
corroboration (relevant to the §5 overlap analysis), not a duplicate; what
actually accumulated unbounded was the same feed re-reporting the same value
every run. `ingestion_worker.process_indicator()` now does a Postgres
`INSERT ... ON CONFLICT (value, source) DO NOTHING` (atomic, safe under
concurrent workers — not a check-then-insert race). Applied to the live dev
DB too: 8 pre-existing rows were 2 real values duplicated 4x each from
today's own test runs, deduped down to 2 before adding the constraint.
`dedupe_engine.find_duplicate()` is unrelated to this — it already ran
inside `indicator_service.create_indicator()`, deduplicating the separate,
normalized `indicators` table, not `raw_indicators`.

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

**Baseline measurement, 2026-07-23, before building the weighting (item 6).**
Taken on the BFS clustering from item 1.1 (32 clusters, 122 members, from the
670-node graph populated before today's collector fixes — small N, will
change once the newly-collected volume is enriched and graph-built; treat
as an early signal, not the final number). For each cluster, checked which
infrastructure attribute(s) (ASN, HostingProvider, Registrar, Nameserver,
resolved IP) are actually shared by ≥2 of its members, using the same
relationship types/depth the detector itself traverses:

| Grouping basis | Clusters | Note |
|---|---|---|
| No shared infra attribute at all | 18 / 32 (56%) | Not commodity over-clustering — these are the *same literal domain* represented as multiple URL paths (structural `HOSTS`, not shared infra), on domains that haven't been enrichment-crawled yet (item 2.6). |
| Shared infra attribute, some combination | 14 / 32 (44%) | 13 involve `HostingProvider`; 1 (`cluster 32`) involves `Registrar` alone. |
| `ASN` + `HostingProvider` and **nothing else shared** | 5 / 32 (16%) | Clusters 1, 6, 7, 8, 9. Functionally "commodity-infra-only": `ASN` and `HostingProvider` are not independent signals in this graph — every `HostingProvider` node co-occurs with exactly one `ASN` (same underlying company, two fields), so this is one fact reported twice, not two corroborating facts. |
| Literally *only* `HostingProvider`, no `ASN` either | 0 / 32 | `ASN` always rides along with `HostingProvider` here — the strict "purely hosting_provider" framing undercounts the real risk because of that correlation. |

**The concrete "used by millions" evidence:** of the 5 ASN+HostingProvider-only
clusters, 4 (clusters 6, 7, 8, 9 — the exact `n=4` "unrelated Vercel URLs"
anecdote already in this section) key off the identical `HostingProvider`
value `'Vercel'`, and 2 more (clusters 2, 3, which also share a `Nameserver`)
key off `'Cloudflare Pages'`. Both are named in this item's own `pages.dev`/
`vercel.app` list. So **6 of 32 clusters (19%) sit on a `HostingProvider` value
that recurs across multiple otherwise-disjoint clusters in the same run** —
the same commodity node bridging unrelated indicator sets, which is exactly
the failure mode this item describes, measured rather than anecdotal.

**Design decision, 2026-07-23: merge ASN and HostingProvider into one feature
for clustering/weighting, rather than dropping HostingProvider or applying a
correlation penalty.** This is a design decision for item 6, not a note —
treating two names for the same company as two pieces of evidence inflates
`R(C)` and would corrupt the weighting results. Worked out as follows.

*Mechanism, from `enrichment_worker.py`/`asn_lookup.py`.* `hosting_provider`
is populated by one of two independent code paths, in priority order:
1. `detect_hosting_platform()` — an 8-entry hardcoded suffix map
   (`vercel.app`→`"Vercel"`, `pages.dev`→`"Cloudflare Pages"`,
   `blogspot.com`→`"Google Blogger"`, etc., item 2.1). Pure string match on
   the domain; **has nothing to do with the ASN lookup.**
2. Fallback, only when (1) finds no match: `asn_data.get("hosting_provider")`
   — from the *same* `ip-api.com` response that also produces `asn`
   (`asn_lookup.py`: `asn` = the `as` field, `hosting_provider` = the `isp`
   field, one HTTP call, two keys of the same JSON object). This path is
   collinear with `asn` by construction — it's one measurement read twice.

So the two paths have different collinearity properties: (2) is guaranteed
collinear; (1) is not guaranteed collinear (a suffix-matched platform's IPs
could in principle sit on more than one ASN), only *empirically* correlated
if the platform happens to concentrate its edge presence on one ASN block.

**Checked empirically, current graph (small — see the N caveat above):**
every `HostingProvider` value present maps to exactly one `ASN` and every
`ASN` maps to exactly one `HostingProvider`, 9/9 pairs, both directions, no
divergence. All 9 observed values arose via path (1) (they're all
brand/product names, not raw ISP strings), so this is the *not-guaranteed*
path showing 1:1 anyway at this scale — consistent with, but not proof of,
permanent collinearity. **Re-check this at the 23,000+-indicator
re-measurement below** — a platform spanning multiple ASNs would only show
up once volume increases past what 9 small clusters can reveal.

**Why merge, not drop or penalize:**
- *Dropping `HostingProvider`* is not defensible: it is the literal feature
  item 2.1's own motivating anecdote is about (the "four unrelated Vercel
  URLs" case, now measured above as clusters 6–9). Removing it would strip
  the paper's central example of the exact evidence it needs, and
  `HostingProvider` is often more discriminating and more legible than `ASN`
  alone (a brand name vs. an opaque number).
- *A correlation penalty* (down-weight `R(C)` when features co-vary) requires
  estimating a correlation from data, re-estimating as the graph grows, and
  is harder to justify to a reviewer than removing the redundancy at the
  source — it dampens double-counting instead of eliminating it.
- *Merging* removes the redundancy structurally, not statistically: define a
  single canonical `org` feature — `hosting_provider` when set (the more
  legible identity, from either path), else `asn` (the only identity signal
  available when neither path resolved a name). A cluster sharing "Vercel"
  then contributes exactly one unit of shared-infrastructure evidence to
  `R(C)`, not two, regardless of which code path populated the value. One
  paragraph explains it in a methods/limitations section: *we observed
  self-reported hosting-provider name and ASN to be collinear in our data
  (verified 1:1 at N=9); we treat them as one organizational-identity
  feature to avoid counting one fact as two pieces of corroborating
  evidence.*
- `Registrar` and `Nameserver` are not merged in — registration and hosting
  are genuinely independent facts (a domain can be registered at GoDaddy and
  hosted at Cloudflare), and nothing in the enrichment code ties them
  together the way `asn`/`hosting_provider` are tied in path (2) above. Not
  independently re-verified beyond that reasoning; worth a similar empirical
  check if item 6's results look off in a way this doesn't explain.

**Action for item 6:** build the weighted fingerprint's feature set from
`{org (merged asn/hosting_provider), registrar, nameserver, resolved_ip}` —
four feature classes, not five — rather than weighting `asn` and
`hosting_provider` as separate dictionary entries the way
`InfrastructureEngine.fingerprint()` (the retained Jaccard baseline) does.
That baseline is deliberately left as-is per item 1.1's reasoning (a
faithful "v1 method" comparison point), so this merge applies only to the
new degree-weighted feature construction in item 6, not to the baseline.

**Full-volume re-measurement, 2026-07-23 — supersedes the 32-cluster/670-node
baseline above as the number degree weighting (item 6) has to beat.** Run
after item 2.7's GeoLite2 fix (ASN coverage 5.6%→38.0% overall, 14.8%→99.3%
conditional on a resolved IP) and the corresponding enrichment/graph
rebuild: 22,642 indicators enriched (18.3 min), graph rebuilt (11.4 min,
22,637 indicator nodes + 619 ASN / 582 HostingProvider / 490 Registrar /
4,122 Nameserver nodes), BFS clustering run (20.2s) →
**1,396 clusters, 13,496 members.**

Same methodology as the small-scale baseline (per cluster, which
attribute(s) are shared by ≥2 members, same relationship types/depth the
detector traverses), but computed via 5 bulk queries (all members at
once, results grouped per-cluster in Python) rather than one query per
cluster — 1,396 clusters made the small-scale approach impractical
(the Nameserver bulk query alone took 544s against this graph size).

| Grouping basis | Clusters | % |
|---|---|---|
| No shared infra attribute at all (same-domain/unenriched) | 182 / 1,396 | 13.0% |
| `ASN`+`HostingProvider`+`Nameserver`+`Registrar` | 504 / 1,396 | 36.1% |
| `ASN`+`HostingProvider`+`Nameserver`+`Registrar`+`ResolvedIP` | 230 / 1,396 | 16.5% |
| `ASN`+`HostingProvider`+`Nameserver` | 168 / 1,396 | 12.0% |
| `ASN`+`HostingProvider`+`Registrar` | 122 / 1,396 | 8.7% |
| `Registrar` alone | 61 / 1,396 | 4.4% |
| `ASN`+`HostingProvider`+`Nameserver`+`ResolvedIP` | 39 / 1,396 | 2.8% |
| `ASN`+`HostingProvider` **only** (functionally commodity-only) | 36 / 1,396 | 2.6% |
| `ASN`+`HostingProvider`+`Registrar`+`ResolvedIP` | 24 / 1,396 | 1.7% |
| `ASN`+`HostingProvider`+`ResolvedIP` | 15 / 1,396 | 1.1% |
| All other combinations (6 types, ≤6 clusters each) | 15 / 1,396 | 1.1% |
| **`HostingProvider` alone, no `ASN`** | **0 / 1,396** | **0%** |

The `ASN`/`HostingProvider` 1:1 pairing from the small-N check holds
exactly at full volume too (0 clusters with one but not the other,
across 1,396) — the merge decision above is on solid empirical ground,
not just a 9-pair coincidence.

**The concrete "used by millions" evidence, now at scale — and it's worse,
not better, than the small-scale signal suggested:**

| Value | Type | Clusters it bridges |
|---|---|---|
| `Cloudflare, Inc.` | HostingProvider | 223 |
| `AS13335` (Cloudflare) | ASN | 255 |
| `Hostinger International Limited` | HostingProvider | 138 |
| `AS47583` (Hostinger) | ASN | 138 |
| `Amazon.com, Inc.` | HostingProvider | 73 |
| `AS16509` (Amazon) | ASN | 61 |
| `Oracle Corporation` / `AS31898` | Hosting/ASN | 38 |
| `IONOS SE` / `AS8560` | Hosting/ASN | 33 |
| `Cloudflare Pages` | HostingProvider | 32 |
| `OVH SAS` / `AS16276` | Hosting/ASN | 31 |

**953 / 1,396 clusters (68.3%) touch a `HostingProvider` value that also
appears in at least one other, otherwise-disjoint cluster in the same
run; 952 / 1,396 (68.2%) touch a recurring `ASN` value** (nearly the same
set of clusters, consistent with the 1:1 pairing). This is the single
biggest finding of this re-measurement: at the small 32-cluster scale
the equivalent number was 6/32 (19%); at full volume it's over two-thirds
of all detected clusters. More clusters means more chances to collide on
the same handful of big commodity hosts — the problem gets *worse* with
scale, not better, which is exactly what the research claim (§3) predicts
and exactly the case degree-weighting has to make.

**Important nuance — this is not the same as "68% of clusters are pure
false positives."** Touching a hub value doesn't mean a cluster's *only*
evidence is that hub: 980 of the 1,396 clusters (70%) have `ASN`+
`HostingProvider` *plus* at least one more specific attribute
(`Nameserver`, `Registrar`, or `ResolvedIP`) — real additional
corroboration, not just the commodity pair. The strict "commodity-only,
nothing else shared" count is 36/1,396 (2.6%) — smaller as a share of
the total than the small-scale run's 16% (5/32), because full-volume
enrichment coverage is far better (38% ASN vs. near-zero), so more
clusters have real additional evidence available to attach. The 68%
hub-touching number is a *feature-level* finding, not a *cluster-level
verdict*: even a cluster with genuine additional evidence still has one
input (its `ASN`/`HostingProvider` feature) that is globally
uninformative and should contribute ~0 after inverse-degree weighting —
which is exactly what item 6 needs to get right, and exactly the effect
size (68% of clusters carry at least one such feature) that would make
degree-weighting's before/after comparison meaningful rather than noise.

**Cluster size is heavily skewed and the top end is extreme:** min 3,
median 3, mean 9.7, max **1,849**. Top 5: 258, 485, 1,054, 1,073, 1,849.
A dedicated attribute-breakdown query against just the single 1,849-member
cluster timed out after 280s (all four other top-5 clusters would have
been queried in the same run, so this is specific to that one cluster) —
itself suggestive of an extremely high-fanout hub node dominating it,
consistent with the over-clustering hypothesis, but **not confirmed in
detail**. Worth a dedicated, more efficient investigation (e.g., degree
of every node reachable from that cluster's seed, computed as a single
aggregate rather than per-attribute-type) before or during item 6, since
if one cluster this large is genuinely commodity-hub-dominated, it alone
would swing aggregate metrics (mean cluster size, mean confidence)
disproportionately.

**1,849-cluster resolved, 2026-07-23 — one hub, confirmed, not a BFS bug.**
The 280s timeout above was from a query scanning attribute types
one-at-a-time across the cluster; the cheap fix is a single scoped query:
re-ran `CampaignDetector.find_connected_clusters()` directly (25s for all
1,396 clusters — cheap, this is the whole detector, not a per-cluster
probe), isolated the 1,849-member cluster's member list (seed
`04qq.digitalcompetitiveedge.de`), then ran one `UNWIND`-based query
against just those 1,849 values asking which infrastructure attribute
nodes they touch and how many members touch each — no per-member
analysis, no full traversal replay:

| Attribute | Value | Members touching it (of 1,849) |
|---|---|---|
| ASN | `AS13335` (Cloudflare) | **1,849 / 1,849 (100%)** |
| HostingProvider | `Cloudflare, Inc.` | 1,808 / 1,849 (97.8%) |
| Registrar | `GoDaddy.com, LLC` | 196 / 1,849 (10.6%) |
| Nameserver | `harlee.ns.cloudflare.com` | 161 / 1,849 (8.7%) |
| Nameserver | `tosana.ns.cloudflare.com` | 160 / 1,849 (8.7%) |
| (1,020 more attribute values) | — | each ≤135 / 1,849 |

**Every single member of this cluster touches `AS13335`.** Checked
`AS13335`'s degree against the *whole graph*, not just this cluster: 2,048
domains, out of 7,439 domains with any ASN edge at all — **27.5% of every
domain in the graph with ASN data resolves through one node.** That one
node is why the BFS (undirected, depth 2) welds 1,849 otherwise-unrelated
domains into a single component: `domain₁ → AS13335 → domain₂` is two hops,
and with 2,048 domains hanging off `AS13335`, most pairs of them are
mutually reachable that way regardless of anything else about them. The
next-most-shared attributes (GoDaddy registrar, Cloudflare's own nameserver
pool) only bridge 8–11% of the cluster's members each — nowhere near enough
to hold 1,849 together on their own. Remove `AS13335` and this cluster
almost certainly fragments into many disconnected, much smaller pieces.

**Verdict: not a BFS bug — the clearest single illustration of the
commodity problem, at maximum expression.** The algorithm did exactly what
depth-2 shared-infrastructure traversal is defined to do; the defect is
that "shared infrastructure" includes a node with 27.5% global fan-out.
This single cluster holds 1,849 of 13,496 total clustered members (13.7%)
and will dominate any *mean*-based aggregate metric (mean cluster size,
mean confidence) in item 6's before/after comparison unless reported
alongside the median or called out individually — mean cluster size before
any trimming is 9.7, but excluding just this one cluster drops it to 8.4.

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

**`R(C)`'s `/cluster_size` normalization systematically under-measures
commodity exposure in exactly the clusters where hub bridging does the
most damage — found while validating item 6, 2026-07-23, concrete instance
recorded here because it's a defect in this metric's *design*, not a
one-off.** The 1,849-member cluster (item 2.1's fully-resolved Cloudflare
hub case) is bridged end-to-end by one node — `AS13335` touches 100% of
its members — yet its unweighted `R(C)` was only 0.34, because dividing by
1,849 caps it there regardless of how total the hub's dominance is. Small
clusters (3–5 members) that are *equally* commodity-only reach `R(C)=1.0`,
the formula's ceiling, because their denominator is tiny. So the metric
that is supposed to measure "how much of this cluster's cohesion is
commodity infrastructure" reads *lower* for the single most extreme
real-world case in the dataset than for small clusters showing the exact
same failure mode. This isn't hypothetical: after degree-weighting
(item 6), the five clusters with the largest *absolute* `R(C)` drop were
all size 3–5 (dropping from `R=1.0` to `R≈0.05–0.09`); the 1,849-cluster
ranked #658 of 1,396 by the same measure, despite being the clearest single
illustration of the problem by every measure that isn't divided by its own
size (100% ASN coverage, 2,048 global degree, 13.7% of all clustered
members). **Practical consequence:** any before/after `R(C)` comparison is
confounded with cluster size — a large commodity-dominated cluster and a
small genuine one can show similar `R(C)` values for entirely different
reasons. Item 7's precision/recall and ARI results must be stratified by
cluster size band (see below) specifically because of this, not just as a
general good practice.

**2.3 Enrichment uses only the first resolved IP.**
`asn_data = safe_lookup(lookup_asn, ips[0])`. A domain resolving to 5 IPs across
3 ASNs records one ASN. Load-balanced infrastructure is exactly what campaigns use.
**Fix:** iterate all IPs, store all ASNs.
**Done 2026-07-23:** `build_enrichment_data()` now loops every IP in
`dns_data["ips"]`, collecting every distinct ASN into a comma-separated
`IndicatorEnrichment.asn` (same storage pattern as `nameservers`/
`resolved_ips`) — deduped, original casing preserved (`normalize_list(...,
lowercase=False)`; ASN codes like `AS13335` aren't case-insensitive by
convention the way domains are, so folding them would just be noise).
`hosting_provider` stays single-valued (first found) — only ASN handling
was requested here. `graph_builder.py`'s `create_domain_infrastructure_relationship`
updated to match: splits `enrichment.asn` on commas and creates one
`RESOLVES_TO_ASN` edge per ASN, same split-and-loop pattern already used
for nameservers, instead of merging one node with a literal comma-joined
value. A failed lookup for one IP no longer blocks ASNs from the others.

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
**Done 2026-07-23:** `run_enrichment_batch()` now filters to unenriched
indicators up front (one query, `NOT EXISTS` join) and submits them to a
`ThreadPoolExecutor` (`enrichment_worker_threads`, config, default 30 — the
middle of the suggested 20–50). Enrichment is I/O-bound (DNS/WHOIS/HTTP),
so threads, not processes. Each worker task runs the lookups against a
shared `functools.lru_cache` per lookup type (`cached_lookup_dns`,
`cached_lookup_registrar`, `cached_lookup_asn`) — the "local DNS cache" —
so indicators sharing a domain (common: see the same-domain-different-path
finding in item 2.1's baseline) only trigger one real network round-trip
per domain, not one per indicator. DB writes happen per-task with their
own `SessionLocal()`, since SQLAlchemy sessions aren't safe to share across
threads. `enrich_indicator()` (serial, single-session) is kept for callers
that already hold a session; both paths share the same
`build_enrichment_data()` lookup logic so there's one implementation of
the actual enrichment rules, not two.

**Run at full volume 2026-07-23: 22,642 indicators enriched in 40.9
minutes** (under the "under an hour" target) — but this run surfaced a new,
severe defect, item 2.7 below, that must be fixed and the run redone
before this data is trustworthy for anything downstream.

**2.7 Parallelizing enrichment (item 2.6) broke ASN lookups by exceeding
the lookup API's rate limit — discovered at full volume, not a design
flaw in item 2.6 itself.**
The full-volume run showed ASN coverage collapsing to 5.6% overall (1,267
of 22,642) and just 14.8% even among indicators that had a resolved IP to
look up (1,233 of 8,340) — an order of magnitude below DNS (36.8%), WHOIS
(42.0%), and nameserver (31.3%) coverage on the *same* run, which is the
signature of a systemic failure, not sparse/aged data. ASN is a core
clustering feature (item 2.1, item 6), so this had to be root-caused
before any further work, not patched around.

**Instrumented and confirmed, not guessed:** `asn_lookup.py` calls
`ip-api.com`'s free JSON API, which allows ~45 requests/minute per client
IP (confirmed via the `X-Rl`/`X-Ttl` response headers, which count down
with each request). The same 9 real "failed" IPs from the actual run
succeeded 100% of the time when queried serially, 1.5s apart — the IPs
are perfectly resolvable; nothing wrong with the data. Reproducing the
real load (a `ThreadPoolExecutor` burst matching `enrichment_worker_threads`)
exhausts the budget within seconds and produces, depending on exactly how
depleted the budget is: **HTTP 429 with an empty body** (`Content-Length:
0`, `X-Rl: 0`, `X-Ttl: 0`), or **HTTP 200 with an empty body** right at
the boundary, which crashes `response.json()` with `JSONDecodeError`.
`asn_lookup.py`'s `if response.status_code != 200: return None` catches
the first case but not the second, and the whole function is wrapped in a
bare `except Exception: return None` with **zero logging** — every
rate-limited lookup was silently indistinguishable from "this IP
genuinely has no ASN." Root cause: item 2.6's thread pool gave every one
of `enrichment_worker_threads` (30) workers access to a single shared
external rate-limit budget that was never going to survive concurrent use
— a case where fixing one defect (serial enrichment) exposed another
(an ASN source with no headroom for the concurrency the fix introduced).

**Fix decision, 2026-07-23: migrate to MaxMind GeoLite2 (offline .mmdb
database), not Team Cymru's bulk DNS service and not independent
rate-limiting of the existing HTTP calls.** All three were evaluated:
- *Rate-limit the existing calls* (token bucket / semaphore, ~45/min) —
  smallest change, but reintroduces the exact throughput bottleneck item
  2.6 just removed for this one feature (ASN lookups would serialize back
  to ~2,700/hour regardless of thread count), and leaves ASN coverage
  permanently hostage to a third-party free-tier policy that isn't ours to
  guarantee and could change without notice.
- *Team Cymru's IP-to-ASN DNS service* — free, no signup, no comparable
  rate ceiling, reuses the existing `dnspython` dependency. Real
  contender, ruled out only in favor of the stronger option below.
- **MaxMind GeoLite2 — chosen.** Downloaded `.mmdb` snapshot, queried
  locally with no network call and no rate limit of any kind. The
  deciding factor is reproducibility for the paper: a dated snapshot
  ("GeoLite2-ASN, downloaded YYYY-MM-DD") gives the exact same answer for
  a given IP no matter when the pipeline is re-run, which a live lookup
  service — Team Cymru included — cannot promise as network topology
  shifts over time. Requires a free MaxMind account + license key, which
  only the project owner can create (blocking dependency — not
  implemented yet, pending the key).

**Status: implemented 2026-07-23.** `asn_lookup.py` rewritten to query the
local `.mmdb` snapshot (`geoip2.database.Reader`) instead of `ip-api.com` —
no network call, no rate limit, `lookup_asn()`'s public signature/return
shape unchanged so nothing downstream needed to change. `data/GeoLite2-ASN.mmdb`
(12MB, MaxMind build date 2026-07-22, confirmed via the file's own
metadata) is a frozen snapshot the project owner downloaded and placed
directly — not fetched by any code, not gitignored-but-required at
runtime via a license key (`data/*.mmdb` stays gitignored; the file
itself is provisioned out of band). `geolite2_asn_db_path` (config,
default `data/GeoLite2-ASN.mmdb`) resolves relative to the repo root
regardless of process cwd (works the same under uvicorn, a worker
script, or pytest). **Fails loudly at import time, no silent network
fallback**, if the file is missing or is the wrong MaxMind database type
— verified via a test that reloads the module with a bad path and
asserts the `RuntimeError`. The snapshot's build date is exposed via
`get_database_build_date()` and logged at load — available for whichever
results-metadata mechanism item 7's evaluation harness ends up using, so
ASN-derived results can cite the exact snapshot by date.

**Also done 2026-07-23, the two follow-up items:**
- **Silent-failure audit, `dns_lookup.py` and `registrar_lookup.py`.**
  Both had the same shape as the old `asn_lookup.py`: bare
  `except Exception: return None`/`pass`, zero logging, every failure
  reason indistinguishable from every other. Neither gets the fix ASN
  got (they're not broken — the DNS/WHOIS coverage numbers above are
  accepted as plausible for aged OSINT data) — this is purely an
  observability fix: `logger.debug(...)` now records the exception
  type/domain wherever one of these previously vanished silently, so a
  *future* systemic failure in either (e.g. a resolver rate limit, a
  WHOIS server blocking us) would leave a diagnostic trail instead of
  requiring the same manual instrumentation effort item 2.7 needed.
  WHOIS lookups also print their own connection errors directly to
  stdout via the underlying `whois`/socket library (the wall of "Error
  trying to connect to socket" text seen during the full-volume run) —
  that's a separate, third-party channel this doesn't silence, but our
  own code's reasoning is no longer opaque on top of it.
- **Post-enrichment coverage sanity check.** `check_enrichment_coverage_sanity()`
  in `enrichment_worker.py`, called automatically at the end of every
  `run_enrichment_batch()`. Compares a dependent field's coverage against
  its prerequisite field's coverage (currently one pair: `asn` given
  `resolved_ips` — ASN can only be looked up once DNS resolves an IP) and
  logs a `WARNING` if the ratio falls below a threshold (default 50%).
  This is exactly the check that would have caught item 2.7 automatically
  — 14.8% is far below any plausible threshold for a working local
  lookup — without needing a human to notice the discrepancy across
  separately-reported per-field percentages. Extensible: add more
  `(dependent, prerequisite, reason)` tuples to `COVERAGE_DEPENDENCIES`
  as more such relationships are identified.

**Done 2026-07-23: re-ran enrichment, rebuilt the graph, redid the
full-volume cluster-attribution re-measurement.** Results in item 2.1
above (search "Full-volume re-measurement"). `check_enrichment_coverage_sanity()`
confirmed healthy (no warnings) against the corrected data. Enrichment
re-run took 18.3 min (down from 40.9 min pre-fix — removing the ASN
network calls' contention sped up the whole batch, not just ASN itself).
83 indicators now record more than one distinct ASN (item 2.3's multi-IP
fix confirmed working on real load-balanced infrastructure, not just in
tests).

**Honest enrichment coverage baseline, full volume (22,642 indicators),
replacing the paper draft's unmeasured "~80% ECR" claim
(`Documentation/Aletheia_Paper_Revised.md`, cited 5 times with a fabricated
60/25/15% failure breakdown that does not correspond to any real run):**

| Attribute | Coverage | Note |
|---|---|---|
| Resolved IP (DNS A record) | 37.3% (8,451/22,642) | re-measured post-fix; DNS itself untouched by item 2.7, small variance vs. the 36.8% pre-fix run is normal live-lookup noise |
| Nameservers (DNS NS record) | 31.9% (7,221/22,642) | |
| Registrar (WHOIS) | 42.1% (9,522/22,642) | |
| ASN | **38.0% (8,610/22,642) overall, 99.3% (8,390/8,451) of indicators with a resolved IP** — fixed, see item 2.7 | was 5.6%/14.8% pre-fix; 99.3% is what a working local lookup should give (only private/reserved/unallocated IPs genuinely lack an ASN) |
| HostingProvider | 38.0% (8,610/22,642) | now tracks ASN exactly — GeoLite2 returns both from the same record for the ASN-fallback path |
| ≥1 attribute resolved (paper's own ECR definition) | 49.8% (11,275/22,642) | vs. the paper's claimed ~80%; up from 48.8% pre-fix as the ASN fix pulled some previously-zero-attribute IP-type indicators into the count |

These numbers (DNS/WHOIS/nameserver) are plausible for aged, open-source
phishing/malware-URL OSINT — a meaningful fraction of collected indicators
reference infrastructure that's already down, sinkholed, or DNS-expired by
collection time, and coverage should be expected to degrade further with
indicator age (older IOCs are more likely to be dead infrastructure by the
time they're enriched). That degradation-with-age relationship is itself
worth checking empirically before the paper asserts it (feed `first_seen`/
`date_added` timestamps are already captured as labels — item 1.2 — and
could be correlated against enrichment success). The ECR figure (48.8%)
should be re-measured once ASN is fixed, since a working ASN source will
push some currently-zero-attribute indicators (IP-type ones especially,
which enrich via ASN only) into the "≥1 attribute" count.

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
| OTX | 0 | hits `/indicators/export`, a bulk endpoint that times out at 20s | use `/api/v1/pulses/subscribed?limit=50&page=N` with pagination — **pulses are pre-grouped by campaign = free ground truth**. **Corrected 2026-07-22:** page size caps at 50 server-side regardless of requested `limit`; the account had 8,821 subscribed pulses (~220k indicators) at verification time, so pulled bounded by `otx_max_pages` (config, default 10 → 500 pulses). Also fixed: collector was reading `os.getenv("OTX_API_KEY")` directly, which is never populated (the key only exists in `.env`, loaded by `settings`, not by the process environment) — silently sent `X-OTX-API-KEY: None` on every request. | 18,056 from 500 pulses (verified, default config) |
| MalwareBazaar | 0 | `get_recent` + `selector: "time"` returns the last hour, often empty | `selector: "100"`. **Corrected 2026-07-22:** the deeper bug was `json=payload` — the API requires form-encoded (`data=payload`); JSON body returned `"missing_query"` regardless of `selector`, which is what actually caused the empty results, not just the 1-hour window. | 100/call (verified), 61% with non-null `signature`, 19 families |
| OpenPhish | 300 | free feed is capped at ~500 most recent, refreshes every 12h — hard ceiling | accumulate: poll every 12h over several days. **No fix needed** — the cap is a provider limit, not a bug. OpenPhish carries no labels at all (0% usable); URLhaus (below) closes that gap for the URL population. | 4,000+ over a week |
| URLhaus | 0 (new) | didn't exist as a collector | added 2026-07-23: `GET /v1/urls/recent/`, labels = `threat_type`/`tags`/`reporter`/`date_added` | 935/pull (verified, ~3-day window per abuse.ch, cap 1,000) |

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

**Done: OTX pulse pagination + labels captured.** Live pull at default config
(10 pages, 500 pulses) returned 18,056 indicators across 489 pulses with >=1
indicator (11 pulses were empty). `type` breakdown: domain 8,954, hash 7,343,
url 1,202, ip 236, plus small counts of CVE/email/YARA/BitcoinAddress that
don't map onto `{ip, domain, url, hash}` — same item-2.4 pattern as ThreatFox,
also logged at runtime.

**Open decision needed for item 7 (OTX pulse-size skew is worse than ThreatFox's
family skew):** pulse sizes range 1–4,499, median 13, mean 36.9. One pulse
("The Evolution of ClickFix...") alone accounts for 4,499 of 18,056 indicators
(~25% of the set). Unlike the ThreatFox `'Unknown malware'` case this isn't a
mislabelled bucket — it's a real human-curated pulse that happens to be huge —
so excluding it isn't obviously right. Decide before building the eval harness
whether to: use it as-is (aggregate ARI will be dominated by this one pulse,
worse than the ThreatFox skew), cap/exclude outlier pulses above some size
threshold, or report OTX pulse-membership and ThreatFox family-membership as
two separate ARI numbers rather than combining them.

**Done: MalwareBazaar `get_recent`/`selector: "100"` fixed (form-encoded body)
+ `signature`/`tags`/`file_type`/`reporter`/`first_seen` captured as labels.**
Live pull returned 100 samples, 61% with non-null `signature`, 19 distinct
families. `get_recent` selector only accepts `"time"` or `"100"` (other values
tested returned `"unknown_selector"`) — 100/call is the practical per-run max;
volume beyond that needs the same accumulate-over-time strategy as OpenPhish,
or `get_siginfo` queried per known family name (not implemented — CONTEXT.md's
original "query by signature for family-labelled batches" suggestion assumes
a list of target families, which we don't have yet).

**Done: URLhaus collector added** (`app/ingestion/collectors/urlhaus_collector.py`),
registered in `feed_registry.py`. Live pull: 935 URLs, `threat` is uniformly
`"malware_download"` (not a useful discriminator on its own), 95.9% have
non-null `tags`. Sampling the non-arch tag values shows both real malware
families (`Mozi` 280, `mirai` 199, `Tsunami` 62, `ClearFake` 26) and clearly
non-family infrastructure/scanner tags (`ua-wget` 282, `opendir` 115, `censys`
70, `ascii` 83, `botnetdomain` 23) mixed in the same list with no field
separating them — see the 1.2 update above. **Not attempting to heuristically
split family-vs-noise tags here** — that's exactly the kind of ad-hoc
classifier this project is trying to avoid; raw `tags` is stored as-is and
family extraction (if wanted) belongs in the eval harness (item 7), done
transparently and reported as a method, not hidden in the collector.

**Collector-layer audit (2026-07-23), all five collectors, three checks:**
auth read from `settings` not `os.getenv`; request encoding matches what
each API expects; no collector silently swallows an error that looks like
an empty result.

- **OTX** (already fixed in this session): was `os.getenv("OTX_API_KEY")`,
  never populated since the key only lives in `.env` (loaded by `settings`,
  not the process env) — now `settings.otx_api_key`. Encoding (GET + query
  params) was already correct. Error handling: `raise_for_status()` on each
  page surfaces HTTP failures clearly (e.g. 401) — no query_status-style
  hidden-error convention on this API, so no further gap found.
- **ThreatFox / MalwareBazaar — real bug found and fixed:** both abuse.ch
  APIs return **HTTP 200 even on request errors**, signaling failure only
  via a `query_status` field in the JSON body. Neither collector checked
  it. ThreatFox's `data["data"]` becomes a *string* on error (confirmed:
  `{"query_status": "illegal_days", "data": "Invalid value for parameter
  days..."}`) — the old `if "data" not in data` guard didn't catch this
  (the key *is* present), so `for item in data["data"]` iterated the
  string's characters and crashed on the first `.get()` call. This is
  exactly how the `days: 90` mistake earlier in this session surfaced: as
  an opaque `AttributeError`, not a readable API error. MalwareBazaar's
  error shape omits `data` entirely (confirmed for `unknown_selector` and
  `missing_query`), so the old guard didn't crash, but it also logged
  nothing — a real API failure looked identical to a quiet collection
  cycle. Both now check `query_status == "ok"` before touching `data`, and
  log a clear warning with the actual status/detail otherwise.
- **URLhaus:** built with the same `query_status` check from the start.
- **OpenPhish:** no auth (public feed), plain-text response, no JSON
  encoding to get wrong, `raise_for_status()` covers the only failure mode.
  No issue found.

**Paper limitations note:** both abuse.ch APIs (ThreatFox, MalwareBazaar —
URLhaus too, by the same convention) return **HTTP 200 even when the request
itself is invalid**, and signal the real failure only through a
`query_status` field in the response body. A collector that only checks the
HTTP status code (the obvious, default thing to do) will record a
zero-indicator error run as a *successful* zero-indicator run — indistinguishable
from a genuinely quiet collection cycle. This is a real operational
finding about working with these feeds, not just an internal bug, and worth
a line in the paper's limitations/threats-to-validity section: silent
zero-yield failures are a plausible, easy-to-miss source of undercounted
volume in any pipeline built on these APIs, including prior work that
doesn't mention checking for it.

**Done 2026-07-23: `FeedRun`/`update_feed_status` wired into
`collector_runner.py`.** `BaseCollector.collect()` now sets
`self.last_error` (still returns `[]` on failure either way, so its public
contract is unchanged) instead of only logging and discarding the
exception. `collector_runner.py` reads `last_error` after each `collect()`
call to tell a real failure apart from a legitimate zero, and persists
both: `FeedRun` (new `error` column added) as an immutable per-run history
row (`feed_source_id`, `status`, `indicators_collected`, `error`,
`completed_at`) via `record_feed_run()`, and `Feed`/`update_feed_status` as
the latest-status snapshot, same as before. `FeedSource` rows are now
created on first sight of a feed name (`get_or_create_feed_source()`).
Verified live end-to-end via `run_collectors()` against all five real
feeds: all five recorded `status="success"` in both tables with correct
counts and `error=None`; a synthetic failing collector in tests correctly
persists `status="failed"` with the real error string, and one failing
collector no longer blocks the others from running or being recorded.
This is what makes "collection reliability per feed across runs" a
reportable result rather than something only visible in log lines —
`FeedRun` rows accumulate every run, so success rate / failure reasons
over time can be queried directly for the paper.

**Combined live stats across all five feeds** (2026-07-23, default config):

| Feed | Indicators | Usable-labelled | Distinct label classes |
|---|---|---|---|
| ThreatFox | 4,036 | 4,036 (100%) | 81 families (excl. `Unknown malware`) |
| OTX | 18,056 | 18,056 (100%) | 489 pulses |
| MalwareBazaar | 100 | 56 (56%) | 13 signatures (this pull) |
| OpenPhish | 300 | 0 (0%) | none — no labels at all |
| URLhaus | 935 | 897 (95.9% have tags; not pure family labels) | 105 distinct raw tag values |
| **Total** | **23,427** | **23,045 (98.4%)** | |

**Cross-feed value overlap:** only **4 distinct values** out of 22,618 total
distinct values appeared in more than one feed (2 shared OTX/ThreatFox, 1
MalwareBazaar/ThreatFox, 1 ThreatFox/URLhaus). Feeds are almost entirely
disjoint at this snapshot. **This number understates true overlap and needs
re-measuring in item 7, not now** — it was computed on raw string equality,
which misses: the same domain appearing as a bare domain in one feed and
embedded in a URL in another; the same host appearing as a plain IP in one
feed and as an `ip:port` entry in another (ThreatFox alone had 983 of these,
see item 2.4); and trivial formatting differences (scheme, trailing slash,
case) that normalization already exists to handle
(`normalization_service.py`) but that raw overlap counting bypassed. Redo
this after enrichment/normalization, not on raw values, before concluding
feeds are actually this disjoint.

---

## 6. Work order — target one week

1. ~~ThreatFox `days: 90`~~ ThreatFox `days: 7` (verified max) + capture labels —
   **done 2026-07-22**, see §5
2. ~~Fix OTX and MalwareBazaar endpoints~~ **done 2026-07-22**, see §5. Extended
   2026-07-23: added URLhaus as a fifth collector (labels OpenPhish's URL
   population), plus a collector-layer audit that found and fixed a real
   silent-failure bug shared by ThreatFox/MalwareBazaar (`query_status` never
   checked) — see §5. Also **done 2026-07-23**: wired `FeedRun`/
   `update_feed_status` into `collector_runner.py` — per-feed success,
   failure reason, and counts are now persisted per run, not just logged.
   Also fixed the same day: `model_registry.py`/`lifespan.py` were
   committed without the actual model imports, so a fresh clone would have
   hit the same silent table-registration failure CONTEXT.md already
   documented once (§7) — see git history.
3. ~~Wire `CampaignDetector` in, retire Jaccard as a baseline~~ **done
   2026-07-23**, see item 1.1. Found while verifying: `conftest.py` shared
   the live dev DB's DSN, so running the test suite wiped dev-DB state.
   ~~Not fixed~~ **fixed same day**, see item 1.1: separate `aletheia_test`
   database + `test_database_url` setting + `ensure_distinct_databases()`
   guard rail that fails loudly if they ever collide.
4. ~~Dedup constraint~~ **done 2026-07-23**, see item 1.4 — `(value, source)`
   unique, not `value` alone
5. ~~Parallel enrichment + DNS cache~~ **done 2026-07-23**, see item 2.6
6. Inverse-degree weighting — 2 days — **the contribution**. **Implemented
   2026-07-23**, see write-up immediately below — code done, tests green,
   but the success-metric test defined in the framing lock above only
   *partially* passes, and that needs a decision before item 7 builds the
   §3 table on top of it.
7. Evaluation harness + ARI + baselines — 2 days
8. Parameter sweeps — 1 day

**Item 6 write-up, 2026-07-23.**

*Implementation.* `InfrastructureEngine.weighted_fingerprint()` builds the
four-class merged feature set decided in item 2.1 (`org` = hosting_provider
else asn, `registrar`, `ns`, `ip`) — separate from `fingerprint()`, which
stays untouched because it feeds the retained Jaccard baseline.
`compute_feature_degrees()` counts, per feature, how many indicators
*globally* (not just in one cluster) carry it — computed as one pass over
fingerprints already loaded for scoring, no second Neo4j traversal.
`CampaignConfidenceScorer._infrastructure_reuse_ratio_weighted()` replaces
each shared feature's flat count of 1 with `1/degree(feature)`, keeping the
same `/cluster_size` normalization the original `R(C)` used. `compute_score`
/`score_campaign`/`score_campaigns` all take an optional `degrees` param —
omitted, they reproduce the exact original unweighted `R(C)` (the "BFS d=2,
unweighted" row); supplied, they use the weighted formula (the "BFS +
inverse-degree weighting" row). `CampaignEngine.detect_campaigns()` (the
live pipeline) now always builds weighted fingerprints and passes degrees
through, same precedent as item 1.1: the live system runs the paper's
actual proposed method, not a side experiment. 6 new tests
(`test_infrastructure_engine.py`, `test_confidence_scorer.py`), full suite
green (99 passed; 2 pre-existing unrelated collection errors from a missing
`geoip2` package in this venv, confirmed present on a clean stash too, not
caused by this change).

**Measured, live, full volume (same 1,396-cluster BFS baseline as item
2.1).** Reporting `R(C)` directly, not the blended 0–100 confidence score —
`R(C)` is only `γ=0.20` of the blend, so even a total collapse of `R(C)`
moves the blended score by at most 20 points; measuring the blend would
bury the effect item 6 is actually about under `N`/`D`/`E`, which are
separate, already-tracked defects (item 2.2), not something to silently
fix here.

| Bucket (by shared-feature *type*, item 2.1's method) | n | R̄ before | R̄ after | drop |
|---|---|---|---|---|
| Commodity-only (`org` shared, nothing else) | 29 (2.1%) | 0.5845 | 0.0705 | **87.9%** |
| Has ≥1 other shared type (`ns`/`registrar`/`ip`) | 748 (53.6%) | 0.7078 | 0.2099 | **70.3%** |
| No shared infra type at all | 619 (44.3%) | 0.0000 | 0.0000 | 0.0% |

(Bucket sizes differ slightly from item 2.1's Neo4j-derived 36/980 — this
run classifies off the merged Postgres `org` fingerprint rather than
separate Neo4j `ASN`/`HostingProvider` node types, and BFS cluster members
here are matched to enrichment rows by indicator value rather than domain
node. Same phenomenon, same order of magnitude, not a re-derivation of the
exact same 1,396-cluster attribute census.)

**Honest read against the framing lock's test.** Commodity-only clusters
lose the most (87.9%) and end up carrying almost no `R(C)` signal (0.0705).
That half of the test passes cleanly. But the "genuine evidence" bucket
*also* loses 70.3% — a real, substantial drop, not the "largely retained"
the success metric asked for. **Root cause, checked, not guessed:** the
type-level classification (does the cluster share *some* `Nameserver` or
`Registrar`, regardless of that specific value's own degree) is not the
same question as *is the shared value itself rare*. Re-bucketing by actual
degree instead of attribute type makes this explicit — clusters where at
least one shared feature has global degree ≤10 still lose 69.2% of `R(C)`
on average, barely different from the type-based genuine bucket. Spot
example: the 1,849-member cluster's second- and third-most-shared
attributes are `harlee.ns.cloudflare.com` and `tosana.ns.cloudflare.com` —
Cloudflare's *own* nameserver pool, shared by ~160 members each. Those are
`Nameserver`-type shared attributes, so item 2.1's type-level census counted
them as "real additional corroboration" distinct from the `ASN`/
`HostingProvider` commodity pair — but they are commodity by the same
argument, just a different vendor's commodity infrastructure, and
degree-weighting correctly suppresses them too.

**This is a real finding, not a bug to quietly patch:** the type-level
"has another shared attribute" check this project (and, plausibly, prior
work in this space) used to distinguish "commodity-only" from "has genuine
evidence" undercounts how much commodity exposure is actually present,
because a shared registrar or nameserver can itself be just as commodity
as a shared CDN. Degree-weighting is doing exactly what it is supposed to
do — the discovery is that the earlier item 2.1 baseline's 70%
"genuine-evidence" figure was measured too coarsely to be the right
comparison group for this test. A cleaner success-metric test would
classify clusters by the *actual* degree of their most-specific shared
feature (e.g., does the cluster share **anything** with global degree
≤10?), not by attribute type — worth doing before item 7 builds the §3
table, so ARI/precision get evaluated against a degree-weighted method
whose before/after story is measured correctly, not against a type-based
grouping already shown here to conflate two different things.

**Not yet decided, needs a call before item 7:** whether to (a) accept
`R(C)`'s drop for both buckets as reported and rely on item 7's
ARI/precision-recall numbers to show the weighting is not "too aggressive"
in the sense that actually matters (does it separate real campaigns from
noise better, not does its own intermediate ratio survive unchanged), or
(b) revisit the weighting formula itself (e.g., stop dividing by
cluster_size, which independently shrinks `R(C)` for any large cluster
regardless of degree — confounding cluster-size effects with commodity
suppression in this exact measurement) before locking it in. Leaning
towards (a) — item 7's ARI comparison against ThreatFox/OTX labels is the
metric that actually decides whether this method works, and `R(C)` alone
was never going to be that decision — but flagging (b) explicitly rather
than picking silently.

**Reclassification approved and applied, 2026-07-23.**

*Why this is a reclassification, not a re-tune of the weighting.* The
original bucket split (immediately above) grouped clusters by shared
*attribute type*: "shares some `Nameserver`/`Registrar`/`ResolvedIP`" was
treated as evidence of genuine, campaign-specific infrastructure, distinct
from the commodity `ASN`/`HostingProvider` pair. That assumption is
demonstrably false: the 1,849-member cluster's own second- and
third-ranked shared attributes are `harlee.ns.cloudflare.com` and
`tosana.ns.cloudflare.com` — Cloudflare's *own* nameserver pool, bridging
~160 members each — which is exactly as commodity as its `ASN`. A
`Nameserver` field being populated says nothing about whether the specific
value in it is rare or a hub; only its measured global degree does. **The
baseline classification was mis-specified, not the weighting
mis-calibrated** — so the fix is to reclassify by what was always the
actual variable of interest (measured degree of the shared feature), not
to adjust the scoring formula to fit the old, wrong grouping.

*Circularity risk — recorded, not hidden.* Bucketing clusters by measured
degree and then scoring those same buckets with a degree-weighted formula
uses the same signal (degree) on both sides. A gradient found this way is
consistent with the method working, but it is not independent proof: a
formula that weights by `1/degree` will *mechanically* show a bigger `R(C)`
drop in a bucket selected for having higher degree, almost by construction.
**This finding should not be presented in the paper as validation on its
own.** The independent check is item 7: Adjusted Rand Index and
pairwise precision/recall against ThreatFox malware-family and OTX
pulse labels are computed entirely from ground-truth labels and cluster
membership — degree never enters that computation. If degree-weighted BFS
beats unweighted BFS on ARI/precision against real labels, that is the
external evidence this method works; the bucketed `R(C)` gradient below is
internal diagnostic evidence that the mechanism behaves as designed, one
necessary check among several, not the headline result. The paper must
lead with the item 7 numbers and present this section as mechanism
validation, explicitly flagging the circularity so a reviewer does not
have to find it themselves.

**Measured: three buckets by max shared-feature degree (not attribute
type), same 1,396-cluster baseline.** Bucketed by the highest global degree
among each cluster's shared features — this is the single feature most
responsible for that cluster's BFS connectivity, since one high-degree hop
is enough to weld a component together regardless of what else is shared.
Thresholds (≤10 / 11–100 / >100) are the same ones already used earlier in
this item, chosen to separate "shared by a handful" from "shared by
dozens" from "shared by a genuine hub" (Cloudflare's `AS13335` alone is
degree 2,048 — two orders of magnitude past the top of the "high" band).

| Bucket | n | R̄ before | R̄ after | drop |
|---|---|---|---|---|
| Low commodity exposure (max degree ≤10) | 180 (12.9%) | 0.7250 | 0.3159 | 56.4% |
| Medium commodity exposure (10 < max degree ≤100) | 235 (16.8%) | 0.6547 | 0.1807 | 72.4% |
| High commodity exposure (max degree >100) | 362 (25.9%) | 0.7238 | 0.1650 | **77.2%** |
| No shared infra attribute at all (excluded — not a commodity question) | 619 (44.3%) | 0.0000 | 0.0000 | 0.0% |

**The gradient is monotonic: 56.4% → 72.4% → 77.2%.** Per the test defined
at the top of this item, that is the pass condition — low-exposure clusters
lose the least, high-exposure clusters lose the most, in the right order,
not a uniform drop across the board. The method is suppressing
commodity-dominated clusters more than low-exposure ones, in proportion to
how commodity-dominated they measurably are. (Caveat above still applies:
this is mechanism validation, not the paper's headline evidence.)

**The 1,849-cluster, specifically — reported honestly, contradicts the
naive expectation.** It is *not* the largest single `R(C)` drop in the
dataset: `R_before=0.3402 → R_after=0.1169` (abs. drop 0.2233), ranked
**#658 of 1,396** by absolute drop, not #1. The five largest absolute drops
are all *small* clusters (size 3–5) that were **entirely** defined by one
commodity feature before weighting (`R_before=1.0000` exactly — every
member shared every feature) and collapse to `R_after≈0.05–0.09` after.
**Root cause, not a contradiction of the earlier finding:** `R(C)`
normalizes by `1/cluster_size` (the original, unweighted formula's own
design, item 2.2's already-tracked N(C)/R(C) normalization issues). For a
1,849-member cluster, that denominator alone caps `R_before` at 0.34 no
matter how total the hub's dominance is — it was never going to reach
1.0, so it has less room to fall. A 3-member cluster glued together by
one shared commodity feature starts at the formula's ceiling (`R=1.0`)
and has the entire range available to drop through. **The 1,849-cluster
remains the single clearest illustration of hub-driven BFS collapse by
every measure that isn't divided by its own size** — 100% ASN coverage,
2,048 global degree, 13.7% of all clustered members — but "biggest `R(C)`
number moved" is a different question, answered by the formula's existing
size-normalization quirk, not by anything specific to degree weighting.
Worth surfacing in the paper's limitations section as one more reason
`R(C)` in isolation is not the right metric to lead with (consistent with
item 2.2's pre-existing critique of this exact normalization choice).

**Decision: stop tuning against these internally-defined buckets, proceed
to item 7.** The monotonic gradient is a real, positive mechanism check,
reported with its circularity caveat attached. Further iteration on bucket
definitions or the weighting formula against `R(C)` alone would be
optimizing an internal diagnostic that was never the paper's actual
evidence. ARI and precision/recall against ThreatFox/OTX ground truth
(ThreatFox families, excluding `'Unknown malware'` per §5; OTX pulses,
pending the item 7 open decision on the ClickFix outlier pulse) is the
external test that settles whether degree-weighted BFS is actually better
than unweighted BFS — that comparison has not been run yet and is item 7's
first job.

**Item 7 write-up, 2026-07-23.**

*Built:* `app/evaluation/ground_truth.py` (ThreatFox family labels excluding
`'Unknown malware'`; OTX pulse labels, with a `find_largest_otx_pulse()`
helper that looks up the outlier pulse dynamically rather than hardcoding
its ID), `app/evaluation/baselines.py` (deterministic random baseline;
`group_by_feature_prefix()`, which builds GROUP BY ASN/hosting_provider/
resolved-IP baselines directly from the fingerprint dicts item 6 already
computes, avoiding a third N+1 Postgres pass), `app/evaluation/metrics.py`
(Adjusted Rand Index and pairwise precision/recall implemented directly
from the contingency-table formula — cross-checked by hand against a known
worked example, not just run-and-hope — rather than adding
scikit-learn/numpy/scipy as a dependency for one function), and
`app/evaluation/run_evaluation.py`, the runnable harness
(`python -m app.evaluation.run_evaluation`) that ties it together and
persists results to `evaluation_runs/item7_eval_<timestamp>.json` (§7's
persist-every-run rule). 13 new tests across
`test_evaluation_metrics.py`/`test_evaluation_baselines.py`, all passing.

*Ground truth loaded, live:* ThreatFox 4,108 labelled indicators (family
labels, `'Unknown malware'` excluded). OTX 17,259 labelled (pulse
membership); largest single pulse `6a0d971608b49dfc89267777` at 4,497
members (§5's "Evolution of ClickFix" pulse — count drifted slightly from
§5's 4,499 due to live re-collection between runs, same pulse); excluding
it leaves 12,762 OTX-labelled indicators.

*Methodology note on the two BFS rows, applied as specified in the
methodology-requirements block above:* `bfs_unweighted_reported_only` and
`bfs_weighted_reported_only` are the 1,396 raw BFS clusters filtered to
those whose confidence score clears `>=40` (medium-confidence threshold),
scored with the old and new `R(C)` formulas respectively. Unweighted
reports 711 clusters; weighted reports 367 — degree-weighting roughly
halves how many clusters clear the bar.

**Result 1 — GROUP BY hosting_provider fails exactly as predicted, and
identically to GROUP BY ASN.** ARI 0.0530, precision 0.348 against
ThreatFox — both numbers match `GROUP BY ASN` to three decimal places
(0.0530 / 0.3480), which is item 2.1's collinearity finding surfacing
again from a completely different measurement: grouping on
`hosting_provider` versus `asn` produces almost the same partition because
they carry the same information in this dataset. This is exactly the
"naive single-attribute grouping fails" evidence this baseline was added
to show (§3).

**Commodity-only FP rate for every baseline, computed after the initial
run — correcting a wrong assumption rather than leaving it stand.** The
first draft of this write-up put "100%" in the GROUP BY ASN/
hosting_provider FP-rate cells on the reasoning that a method which only
ever looks at one attribute must produce 100%-commodity-only clusters.
That reasoning was wrong and the measured numbers correct it: GROUP BY
ASN 9.77%, GROUP BY hosting_provider 8.16%, Jaccard 3.22%, GROUP BY
resolved IP 0.00%, random baseline **19.77%**. The gap is explained, not a
bug: item 2.1's commodity-only classifier checks whether a cluster's *only*
shared attribute type is `org`, across *all* its members, not just the
grouping key — a GROUP BY ASN cluster can have dozens of members (avg.
~33/group here), and with that many members, some pair among them
incidentally shares a nameserver or registrar too just by chance, which is
enough to move a cluster out of the strict "commodity-only" bucket even
though the entire cluster exists *because of* the commodity attribute. The
**random baseline scoring highest of all (19.77%)** is the more legible
result: with no real signal at all, the only way two randomly-grouped
indicators are likely to coincide on *anything* is a common `org` value
(Cloudflare/Hostinger-class providers cover a large share of the
enrichment-bearing population), while coincidence on a specific
`Nameserver`/`Registrar`/IP is rare — so pure chance, filtered through this
same classifier, produces almost 20% "commodity-only" clusters on its own.
That is itself a data point for the central claim: commodity infrastructure
is prevalent enough in this dataset that even random co-membership trips
over it one time in five.

**Result 2 — the ARI/precision/recall half of the claim does not win, and
that is reported here honestly rather than reframed.** Comparing the two
BFS rows against ThreatFox: ARI 0.0716 (unweighted) vs. 0.0712 (weighted);
precision 0.5375 vs. 0.5364; recall 0.0523 vs. 0.0521. Against OTX
(with outlier): 0.0703 vs. 0.0698 / 0.3447 vs. 0.3440 / 0.0501 vs. 0.0497.
Against OTX (without outlier): 0.0587 vs. 0.0547 / 0.0800 vs. 0.0755 /
0.0556 vs. 0.0520. **In every case the weighted row is flat-to-marginally-
worse, never a clear win.** Per §3's own rule — "if it does not [win on
ARI], we report that honestly and rethink" — this is that report. Degree
weighting is not shown, by this measurement, to produce a better partition
against real labels than unweighted BFS. (It cannot, in fact, produce a
*different* partition at all — see the methodology note above — so this
result is really about which subset of the same 1,396 clusters survives
the confidence filter, not about clustering quality.)

**Result 3 — the commodity-FP-rate half of the claim wins, dramatically,
and is the one clean, defensible win in this run.** Commodity-only share
of *reported* clusters: 3.94% (unweighted, n=711) → **0.27%** (weighted,
n=367) — a 93% relative reduction. Note the unweighted number is *higher*
than the unfiltered baseline (2.08% across all 1,396 raw clusters,
item 6): the old confidence formula's `N(C)` component rewards cluster
size, and commodity-only clusters tend to be large (hub-driven, item 2.1),
so the unweighted formula was actively *promoting* commodity-only clusters
into the reported set, not just failing to suppress them. Degree
weighting reverses that.

**Reconciling results 2 and 3 — this is the honest, load-bearing finding
of item 7, and it is exactly what item 6's open question predicted.**
Reported-campaign volume drops from 711 to 367 (a loss of 344 clusters),
but only ~28 of the 711 unweighted-reported clusters were commodity-only
(3.94% × 711) and roughly 1 of the 367 weighted-reported clusters is
(0.27% × 367) — so at most ~27 of the 344 removed clusters were
commodity-only. **The other ~317 removed clusters had genuine additional
evidence** by item 2.1's type-based classification, and were filtered out
anyway. This is item 6's "genuine clusters also lose R(C) substantially
(70.3%)" finding, now confirmed downstream at the confidence-threshold
level against real ground truth: weighting doesn't selectively remove
commodity clusters from the reported set, it removes a much larger,
mostly-genuine population alongside them, which is exactly why precision/
recall on what remains doesn't improve — the surviving 367 aren't a purer
subset of the 711, they're a smaller, largely-overlapping subset that
happens to have almost no commodity-only clusters left in it because
almost nothing is left in it.

**Size-band stratification (required per item 2.2's confound) shows no
robust, sample-size-reliable pattern.** Full per-band numbers are in
`evaluation_runs/item7_eval_*.json`; several bands have small `n_labelled`
(single-to-low-double-digits) where ARI swings wildly and is not
trustworthy (e.g. ThreatFox 6–10 band, weighted: `n_labelled=2`,
`ARI=1.0000` but `precision=recall=0.0000` — a degenerate small-sample
artifact, not a signal, flagged here so it is never cited as one). The one
band with consistently large, trustworthy sample sizes across all three
ground truths is **50+ members** (ThreatFox `n_labelled` 932→931; OTX-with
4,504→4,343; OTX-without 1,974→1,844), and in that band ARI is essentially
unchanged by weighting in all three: 0.1003→0.0994, 0.0174→0.0049,
0.0869→0.0807. **This is the band that contains the 1,849-member cluster
and the rest of item 2.1's extreme-hub cases — the exact place the paper's
central claim says the effect should be largest — and it shows the
smallest, most negligible movement of any band with a reliable sample
size.** Smaller bands show larger swings in both directions across the
three ground truths (no consistent "small clusters benefit more" story
either), which is consistent with those swings being small-sample noise
rather than a real cluster-size interaction. **Conclusion: the data here
does not support a claim that degree weighting's effect concentrates in
any particular size band — the honest read is that it doesn't show up
robustly in ARI/precision/recall at any size, only in the FP-rate metric
(Result 3).**

**Absolute ARI is low across every method in this table**, baselines
included (mostly 0.00–0.09, outside a few small-sample bands). No method
tested here achieves strong agreement with either label set. Worth
flagging as a limitation independent of degree weighting — plausibly
addressed by item 3.2's parameter sweep (BFS `d`/`k`, Jaccard threshold
were never tuned, just asserted) rather than anything item 6/7 changed.

**What this means for the paper, stated plainly:** the defensible claim
from the framing lock — "commodity features contribute near-zero R(C)
after weighting, while the *fraction of reported campaigns* that are
commodity-only drops sharply" — is empirically supported (Result 1, 3).
The stronger claim — "degree-weighted BFS is a better campaign-detection
method than unweighted BFS, as measured by agreement with ground-truth
malware families/pulses" — is **not** supported by this run (Result 2).
These are different claims, and only the first is currently backed by
evidence strong enough to publish. The paper should lead with the FP-rate
result as the contribution, characterize it precisely as "a large fraction
of a naive confidence filter's false-positive volume is provably
commodity-driven and removable" rather than "campaigns are detected more
accurately," and report Result 2/the flat ARI honestly as a limitation —
per §7's rule, not massaged to imply otherwise.

**Not done, worth doing before finalizing the paper's evaluation section:**
Jaccard v1 and the GROUP BY baselines were not run through the same
confidence-filtered comparison the two BFS rows get (they use
`CampaignConfidenceScorer` and its threshold; the current run only
computes their raw ARI/precision/recall over all detected clusters). A
like-for-like comparison would apply the same reporting-threshold logic
to every method, not just the two BFS rows — currently the table compares
BFS's *filtered* output against other methods' *unfiltered* output, which
is not quite apples-to-apples and should be corrected before this table
goes in the paper.

**ARI diagnosis, 2026-07-23 — why every method, including baselines,
scored ~0.00–0.09.** Requested directly: is infrastructure near-orthogonal
to malware family/pulse, making ARI-against-label the wrong metric for
every method, not just ours? Built `app/evaluation/diagnostics.py`
(`label_infra_cohesion()`: per-label, in-label feature-sharing rate, split
into enrichment coverage vs. cohesion-among-enriched so the two causes
can't be conflated; `connectivity_components()` +
`connectivity_threshold_sweep()`: union-find over the same fingerprints at
varying degree thresholds). 4 new tests, all passing. Answer: **no,
infrastructure is not orthogonal to these labels — it is strongly
correlated wherever enrichment exists.** The low ARI has a different, more
specific cause, found below.

**1. ThreatFox top-10 families (85.6% of the 4,108 labelled set) — in-family
infrastructure cohesion:**

| Family | n | Enriched | Cohesion (of enriched) | Cohesion (overall) |
|---|---|---|---|---|
| `win.metastealer` | 997 | 0.2% | 100.0% | 0.2% |
| `js.clearfake` | 908 | 86.2% | 99.1% | 85.5% |
| `unknown` | 662 | 37.5% | 94.4% | 35.3% |
| `win.cobalt_strike` | 257 | 0.0% | — | 0.0% |
| `win.vidar` | 247 | 37.7% | 91.4% | 34.4% |
| `win.adaptix_c2` | 144 | 0.0% | — | 0.0% |
| `js.kongtuke` | 121 | 100.0% | 100.0% | 100.0% |
| `win.asyncrat` | 69 | 2.9% | 0.0% | 0.0% |
| `js.iclickfix` | 58 | 93.1% | 63.0% | 58.6% |
| `elf.aisuru` | 54 | 0.0% | — | 0.0% |

**The pattern is bimodal, not weak-everywhere.** Families reported via
domain/URL indicators (`js.clearfake`, `js.kongtuke`, `js.iclickfix`,
`win.vidar`, `unknown`) show 91–100% cohesion among their enriched
members — as strong a correlation between family and shared infrastructure
as this project could hope to find. Families reported almost entirely via
file hashes (`win.metastealer` — the single largest family in the whole
labelled set — `win.cobalt_strike`, `win.adaptix_c2`, `win.asyncrat`,
`elf.aisuru`) show 0–3% enrichment coverage, full stop, because **item
2.4 ("Hashes receive no enrichment") means these families are
structurally unclusterable by any infrastructure-based method,
independent of clustering quality.** `win.metastealer` alone is 997 of
4,108 labelled indicators (24.3%) and is essentially invisible to
infrastructure-based evaluation. Combined, the five near-zero-enrichment
families above account for 1,521 of 4,108 (37.0%) of the labelled set.

**CORRECTION, 2026-07-23, same day — the "hash-only, item 2.4" attribution
above is wrong, or at minimum unverified when written, and is left in
place with this note rather than silently fixed, same convention as the
earlier `js.clearfake` retraction.** The claim was inferred from malware
family *naming convention* (`win.*` reads as "Windows malware, probably
hash-reported"), not checked against actual `ioc_type` values — this
session's next entry checks it directly, and it does not hold.
`win.metastealer` (997, 24.3% of the labelled set, the single largest
family) has **zero** hash-type indicators — it is 996 `domain` + 1
`ip:port`. Three of the other four ("hash-only") families
(`win.cobalt_strike` 257, `win.adaptix_c2` 144, `elf.aisuru` 54) are 100%
`ip:port`, also zero hashes. Only `win.asyncrat` (69) has any real hash
content, and it's a minority (12 of 69, 17%). Across the *entire*
4,108-indicator ThreatFox labelled set, genuine hash-type IOCs
(`sha256_hash`/`sha1_hash`/`md5_hash`) total 263 (6.4%), not the ~37%
implied above. **"Hashes are categorically out of scope for
infrastructure clustering" was the load-bearing explanation for low
aggregate ARI in this write-up's synthesis (below) — that explanation is
unsupported as stated, since hashes are barely present in the population
being explained.** What is actually driving the near-zero-enrichment
figure is investigated next, report-only, before any scope-condition
table is built on top of it.

**2. OTX pulses — same question, same shape, reported separately as
requested.** Coverage and cohesion vary pulse-to-pulse (12–99% enriched,
75–100% cohesion-among-enriched where coverage exists), consistent with
pulses mixing indicator types just like ThreatFox families do. Notably,
the 4,497-member outlier pulse (§5's "Evolution of ClickFix...") is
*not* noise by this measure — 84.9% enriched, 98.0% cohesion among
enriched, 83.1% overall — one of the most infrastructure-cohesive labels
in either ground truth, which argues against reflexively excluding it as
"just an outlier." Full per-pulse table (top 10, with and without the
outlier) in `evaluation_runs/` is not yet persisted by this diagnostic run
(only item 7's main harness writes to that directory) — re-run
`app/evaluation/diagnostics.py`'s numbers are in this session's log,
reproduce via the same harness if this needs to go in the paper.

**3. Best ARI achieved by unrestricted-connectivity clustering — not a
"theoretical ceiling," and that distinction matters enough to state
correctly the first time. Computed as a degree-threshold connectivity
sweep (union-find over shared features, restricted to features at or below
each threshold). Deliberately not called a ceiling or a maximum: see the
"does not cleanly answer" paragraph below, where the OTX-without-outlier
column proves it is not an upper bound over infrastructure methods in
general — actual BFS already exceeds it. It is the best result found by
one specific, swept method family (single global degree threshold, all
feature types pooled), nothing stronger.**

| Threshold | ThreatFox ARI | OTX (+outlier) ARI | OTX (−outlier) ARI |
|---|---|---|---|
| ≤2 | 0.0000 | 0.0007 | 0.0005 |
| ≤10 | 0.0025 | 0.0632 | 0.0134 |
| ≤50 | 0.0091 | 0.2248 | 0.0127 |
| ≤100 | 0.0097 | 0.2370 | **0.0191** |
| ≤500 | 0.1282 | 0.2663 | 0.0152 |
| unrestricted | **0.2194** | **0.2691** | 0.0139 |

Actual BFS (reported-only, from item 7): ThreatFox 0.0716, OTX+outlier
0.0703, OTX−outlier 0.0587.

**This is not "0.07 is what % of ceiling" — that framing was wrong and is
retracted. It answers something more specific and more useful: how much
does the best result found by unrestricted-connectivity clustering exceed
actual BFS, and why.** For ThreatFox and OTX-with-outlier, the best result
in the sweep is reached at **unrestricted** connectivity (no degree limit —
every hub feature allowed to connect) at 0.2194 and 0.2691 respectively,
roughly **3–4× actual BFS's reported-only ARI**. That gap is real, but it
is produced by *embracing* hub-driven merging, not avoiding it — the
opposite of this paper's thesis — and it is a candidate artifact of class
skew (§3.1's own prior warning): a few giant, highly-cohesive
families/pulses (`js.clearfake` at 908 members, 85.5% cohesive; the
4,497-member OTX outlier at 83.1% cohesive) could contribute enough
same-label pairs to swing aggregate ARI even when merged into large,
imprecise components. Whether that candidate explanation is actually what's
happening is decomposed below, not assumed. **For OTX-without-outlier, the
relationship inverts:** actual BFS (0.0587) already *exceeds* every point
in this sweep (max 0.0191) — a single global degree threshold, however
tuned, cannot match what BFS's depth+relation-type-combined traversal
achieves for this label set. **This is the proof, not just a caveat, that
this sweep is not an upper bound over infrastructure-clustering methods in
general** — it's the best result from one family of methods (single global
threshold, all feature types pooled), already beaten by a different method
on one of the three ground truths. Report it as evidence that a gap exists
for two of three ground truths, not as a ceiling being approached.

**Decomposing the 0.2194-vs-0.0716 gap (ThreatFox) — leave-one-family-out,
not assumed to be class skew until checked.** Requested directly, because
"headroom exists but is only reachable via a mechanism we argue is wrong"
is a real tension the paper has to address, not a footnote, and which of
the two explanations is true changes what the required paragraph says:

| Held out | n | Unrestricted-connectivity ARI | Δ from baseline (0.2194) |
|---|---|---|---|
| *(none — baseline)* | 4,108 | 0.2194 | — |
| **`js.clearfake`** | 908 | **0.0302** | **−0.1892** |
| `win.metastealer` | 997 | 0.2931 | +0.0736 |
| `unknown` | 662 | 0.2905 | +0.0711 |
| `js.kongtuke` | 121 | 0.2469 | +0.0274 |
| `win.vidar` | 247 | 0.2380 | +0.0186 |
| `js.iclickfix` | 58 | 0.2315 | +0.0120 |
| `win.cobalt_strike` | 257 | 0.2107 | −0.0088 |
| `win.adaptix_c2` | 144 | 0.2131 | −0.0063 |
| `win.asyncrat` | 69 | 0.2163 | −0.0031 |
| `elf.aisuru` | 54 | 0.2167 | −0.0028 |

**Answer: class skew, confirmed with numbers, not assumed — the tension
dissolves exactly as anticipated if this outcome held.** Holding out
`js.clearfake` alone drops unrestricted-connectivity ARI from 0.2194 to
**0.0302 — below actual BFS's 0.0716.** One family, 908 of 4,108 labelled
indicators (22.1%), accounts for more than the entire gap between
unrestricted connectivity and actual BFS; every other family's effect is
noise-sized (−0.009 to +0.074, no consistent sign, consistent with
sampling variation from removing a chunk of the pair-count denominator
rather than a real clustering effect). This is arithmetically expected
once stated: `js.clearfake` alone contributes up to `C(908,2)≈411,778`
same-family pairs to the ARI computation, a large fraction of the total
labelled-pair budget, so how well its ~781 enriched members (86.2%
enriched × 908) cluster together dominates the aggregate number
regardless of every other family's behavior.

**Solo evaluation (restricting the comparison to just each family's own
members) confirms *why* `js.clearfake` swings the aggregate so hard: it
clusters into itself cleanly, not into a hub-driven blob.** Precision
1.0, recall 0.7416 under fully unrestricted connectivity (every hub
feature allowed) — meaning unrestricted connectivity essentially never
merges a `js.clearfake` indicator with a non-`js.clearfake` one, and
correctly groups 74% of `js.clearfake`'s own same-family pairs. (`js.kongtuke`,
the other fully-enriched family, is solo-perfect: ARI 1.0, P=1.0, R=1.0,
n=121.) **This means the "3–4× headroom bought via hub-embracing merging"
framing was itself imprecise — unrestricted connectivity is not winning by
lumping `js.clearfake` into a giant undifferentiated blob together with
unrelated material; `js.clearfake` behaves like a large, cohesive,
low-noise cluster on its own**, and the aggregate ARI simply reflects
that one huge, well-behaved family dominating the pairwise-count budget
(§3.1's class-skew warning), not a genuine hub-suppression-vs-accuracy
trade-off spread across the dataset. The open question this reframes,
not answers: *why does actual BFS (depth=2, k=3, confidence-filtered)
score only 0.0716 when `js.clearfake` alone is this cleanly clusterable
under full connectivity?* — plausibly BFS's `d=2` depth limit or the
medium-confidence reporting threshold is fragmenting `js.clearfake` into
many small pieces rather than merging it into one connected campaign, in
which case that's a parameter-tuning gap (item 3.2), not evidence against
degree weighting itself. Not yet checked — worth a direct look (does
`js.clearfake` survive as one or a handful of large BFS clusters, or
dozens of small ones?) before writing the paper's evaluation section, but
out of scope for this diagnosis per the requested stopping point.

**RETRACTION, 2026-07-23, same day — the paragraph above (P=1.0 → "not a
hub-driven blob") is wrong and is left in place, struck through in effect
by this note rather than deleted, because the wrong claim was recorded and
the record should show the correction, not erase the mistake.** Precision
computed on a single-label evaluation (`true_labels` containing only
`js.clearfake`) is a tautology, not a finding: with no other class present
in the comparison, every same-cluster pair among `js.clearfake` members is
correct by construction — the metric structurally cannot detect dilution
by non-`js.clearfake` material sharing the same predicted cluster, because
that material was excluded from `true_labels` before the metric ever ran.
P=1.0 was guaranteed by the evaluation's construction, independent of
whether `js.clearfake` was actually isolated or drowning in noise.

**The follow-up check that exposes this — actual BFS, not unrestricted
connectivity, with cluster composition, not just pairwise precision:**

| Configuration | Clusters touching | Members captured | ARI | Precision | Recall |
|---|---|---|---|---|---|
| Raw BFS (`d=2`, `k=3`, no filter) | 16 | 782/908 | 0.0000 | 1.0000 | 0.1609 |
| Reported, unweighted (confidence≥40) | 10 | 605/908 | 0.0000 | 1.0000 | 0.1405 |
| Reported, weighted (confidence≥40) | 8 | 603/908 | 0.0000 | 1.0000 | 0.1405 |

Precision is 1.0 in every row for the same tautological reason above — it
is not evidence of clean clustering here either, and should not be read
as such. Recall is the only informative column in this table.

**Cluster composition (size vs. `js.clearfake` share) is what actually
answers the question, and it contradicts the retracted claim directly:**

| Cluster size | `js.clearfake` members | `js.clearfake` % |
|---|---|---|
| 1,849 | 295 | 16.0% |
| 1,073 | 82 | 7.6% |
| 1,054 | 127 | 12.0% |
| 258 | 12 | 4.7% |
| 196 | 124 | 63.3% |
| 98 | 79 | 80.6% |

The four largest clusters here are the **same four commodity-hub clusters**
from item 2.1's Cloudflare finding (1,849 / 1,073 / 1,054 / 258 — the exact
top-4 sizes measured there). 554 of 782 captured `js.clearfake` members
(61%) sit inside those four clusters, diluted to 5–17% of each cluster's
own membership by thousands of unrelated indicators. Only ~215 members
(the 196/98/17-sized clusters) sit in clusters where `js.clearfake`
actually dominates (63–81%) — a plausible genuine sub-campaign detection,
much smaller than the family itself.

**Recategorized: this is not item 3.2 (parameter tuning) — it is a direct
instance of item 2.1's commodity-hub finding, and the paragraph above that
filed it under 3.2 is corrected accordingly.** Comparing raw BFS recall
(0.1609) to confidence-filtered recall (0.1405) isolates the confidence
threshold's own cost at ~0.02 — small. The dominant loss (capping recall
at 0.16 before any filtering happens at all) occurs at the raw `d=2`/`k=3`
clustering step itself, via dilution into the identical commodity-hub
clusters `AS13335` already produces elsewhere in this document. This is
not a separate BFS-parameter defect to sweep later; it is the same failure
mode this paper's central claim is about, now shown concretely absorbing a
specific, well-enriched, genuinely cohesive real campaign (`js.clearfake`)
rather than only abstractly inflating cluster counts.

**The tension this creates, recorded rather than resolved — degree
weighting does not rescue `js.clearfake` from the hubs, and that has to be
stated plainly, not buried under the finding above.** If item 6's
mechanism worked as the paper's thesis predicts, the weighted-reported row
should show `js.clearfake` recovering more of `js.clearfake` — either more
members captured, or the same members captured in fewer, purer clusters.
It does neither: weighted-reported recall (0.1405) is *identical* to
unweighted-reported recall (0.1405), and weighted-reported captures fewer
clusters (8 vs. 10) and fewer members (603 vs. 605) than unweighted, not
more. Degree weighting changes confidence *scores*, not which indicators
end up in the same BFS component (methodology note earlier in item 6/7),
so `js.clearfake`'s members stay diluted inside the 1,849/1,073/1,054/258
clusters regardless of weighting — weighting can only affect whether those
already-diluted clusters clear the reporting threshold, not un-dilute
them. This is a real limitation of degree weighting as currently scoped:
it corrects the *score* a hub-dominated cluster receives, but does not
recover the specific real-campaign signal already lost to hub-driven
merging at the clustering step. Left open, not resolved here.

**What this means for the paper's evaluation design, stated plainly:**
the metric is not fundamentally wrong — infrastructure and label are
genuinely correlated wherever enrichment exists (Result 1's 91–100%
cohesion), so ARI-against-label is a valid signal in principle. The
low aggregate numbers are explained by two compounding, identifiable
causes, not by "infrastructure and campaigns are unrelated":
1. **Scope mismatch, dominant.** ~37% of the ThreatFox-labelled population
   (led by the single largest family, `win.metastealer`) is hash-only and
   structurally unenrichable (item 2.4) — no infrastructure method, however
   good, can ever cluster it correctly, and it is currently averaged into
   the same aggregate ARI as the domain/URL families that show 90–100%
   cohesion. This inflates the denominator with unwinnable cases.
2. **The apparent headroom on the enrichable subset is class skew,
   confirmed by leave-one-family-out, not a genuine hub-suppression-vs-
   accuracy trade-off.** Holding out `js.clearfake` alone (908 of 4,108
   labelled indicators) drops the best unrestricted-connectivity result
   from 0.2194 to 0.0302 — below actual BFS's 0.0716 — while every other
   family's effect is noise-sized. `js.clearfake` also solo-clusters
   cleanly (precision 1.0, recall 0.74 under full connectivity), so it
   isn't winning by getting swept into a hub-driven blob; it's one large,
   well-behaved family whose sheer size (≈412K possible same-family pairs)
   dominates the aggregate pairwise-count budget (§3.1's class-skew
   warning). There is no dataset-wide "unweighted connectivity beats
   degree-weighted BFS" effect to chase here — it is one family's
   arithmetic weight. The real, still-open question this reframes rather
   than closes: why does actual BFS score only 0.0716 when `js.clearfake`
   is this cleanly clusterable in principle — is BFS's `d=2` depth or the
   confidence-filter threshold fragmenting it? Not yet checked.

**Corrections applied this round, 2026-07-23, per direct review:** the
earlier draft of this section called the unrestricted-connectivity result
a "theoretical ceiling" / used "maximum achievable" language. Both are
retracted and replaced throughout — the OTX-without-outlier result (actual
BFS 0.0587 exceeding the sweep's best of 0.0191) is direct proof it is not
an upper bound over infrastructure methods in general, only the best
result found by one swept method family
(`connectivity_threshold_sweep()`, renamed from `ceiling_sweep()` in code
to match). The "3–4× headroom, likely class skew" framing was a hedged
guess in that draft; it is now a checked, numeric finding (immediately
above), not a guess.

**Recommended next steps — two of four already ruled out by the
decomposition above, two queued and explicitly not yet applied pending
direction:**
- ~~Do not chase the unrestricted-connectivity ceiling by loosening BFS's
  constraints~~ — superseded: there was never a real dataset-wide effect
  to chase. Instead, check whether BFS is under-merging `js.clearfake`
  specifically (item 3.2 parameter territory), independent of degree
  weighting.
- ~~Report the domain/URL-restricted cohesion numbers as direct positive
  evidence~~ — still true and still recommended, unaffected by this
  round's corrections.
- **Queued, not yet applied:** define the scope condition ("indicators
  carrying ≥1 enriched infrastructure attribute") as a declared rule
  applied identically to every method and baseline, and report
  full-population ARI alongside the scoped number in the same table —
  explicitly held pending direction per this round's request, not
  actioned yet.
- **Queued, not yet applied:** probe what fields the free hash-lookup
  sources actually return before committing to item 2.4 — sample-level
  metadata (file type, size, first-seen) is not infrastructure and may not
  make hashes clusterable even if it makes them better-labelled. Not run
  yet.

Then rewrite the paper around whatever the results actually show.

---

## 6a. Environment integrity incident, 2026-07-23 — every number above needed re-checking

**What happened.** Every command this session was prefixed
`source .venv/bin/activate 2>/dev/null`, run from `backend/`. There is no
`.venv` under `backend/` — the project's actual virtualenv lives at the
repo root, `aletheia/.venv`. Activation therefore failed every single time,
`2>/dev/null` silently swallowed the error, and every command in this
session ran against the *system* Python instead. This was not caught for
the length of the entire item-6/item-7 investigation. It surfaced only
when a command threw (`ModuleNotFoundError: geoip2`, during the item 2.4
follow-up's enrichment step) — an error loud enough to notice, unlike
everything before it, which ran to completion and produced plausible
output. This is the same class of defect as item 2.7 (a rate-limited
external call silently indistinguishable from "no ASN found"): a failure
mode masked well enough to look like a legitimate result. Concretely, it
also means **112 and 116 were never the real test count.**
`test_asn_lookup.py`/`test_enrichment_worker.py` were excluded from every
run this session because system Python lacked `geoip2` — silently, without
that exclusion ever being flagged as a gap rather than a deliberate
scoping choice. The real suite is 141 (146 after this incident's own new
tests).

**(a) Fixed — the masking is gone and a guard now exists.**
`app/core/venv_safety.py::ensure_correct_interpreter()`, same convention
as `db_safety.py`'s `ensure_distinct_databases()`/
`ensure_distinct_redis_targets()`: raises `RuntimeError` immediately, with
the exact `source .../.venv/bin/activate` command to fix it, if
`sys.prefix` doesn't resolve to the repo root's `.venv`. Wired into
`conftest.py` (runs before any other guard, any fixture, any test) and
into every worker's `if __name__ == "__main__":` block (`ingestion_worker.py`,
`indicator_worker.py`, `graph_worker.py`, `enrichment_worker.py`).
Verified both directions: `pytest` under the correct venv passes clean
(146 tests); `pytest` under system Python fails immediately with a clear,
actionable message naming the exact activation command, instead of running
to completion on the wrong interpreter. 5 new tests
(`test_venv_safety.py`), parameterized on `sys_prefix`/`repo_root` so the
failure path is tested without needing an actually-wrong interpreter.

**(b) Full environment diff — `pip freeze`, venv (62 packages) vs. system
Python (755 packages). Every divergence, not a summary:**

*In the venv, absent from system Python (11):*
`black==26.3.0`, `cfgv==3.5.0`, `geoip2==5.3.0`, `identify==2.6.17`,
`maxminddb==3.1.1`, `mypy_extensions==1.1.0`, `nodeenv==1.10.0`,
`pre_commit==4.5.1`, `psycopg2-binary==2.9.10`, `pytokens==0.4.1`,
`ruff==0.15.5`. (System Python has `psycopg2==2.9.12` instead of
`psycopg2-binary` — same C extension, different packaging, functionally
equivalent; not a real gap.)

*Present in both, version differs (30):*

| Package | venv | system |
|---|---|---|
| **`neo4j`** | **6.1.0** | **5.2.dev0** |
| `sqlalchemy` | 2.0.41 | 2.0.48 |
| `pydantic` | 2.12.5 | 2.13.4 |
| `pydantic-settings` | 2.13.1 | 2.14.2 |
| `pydantic_core` | 2.41.5 | 2.46.4 |
| `fastapi` | 0.135.1 | 0.135.3 |
| `starlette` | 0.52.1 | 1.1.0 |
| `redis` | 5.0.4 | 6.4.0 |
| `python-whois` | 0.9.6 | 0.9.3 |
| `python-dotenv` | 1.0.1 | 2.1.0 |
| `uvicorn` | 0.41.0 | 0.38.0 |
| `pytest` | 9.0.2 | 9.0.3 |
| `aiohttp` | 3.14.2 | 3.14.1 |
| `certifi` | 2026.2.25 | 2026.6.17 |
| `charset-normalizer` | 3.4.9 | 3.4.7 |
| `click` | 8.3.1 | 8.1.8 |
| `filelock` | 3.25.0 | 3.29.7 |
| `greenlet` | 3.5.4 | 3.3.2 |
| `idna` | 3.11 | 3.18 |
| `iniconfig` | 2.3.0 | 2.1.0 |
| `multidict` | 6.7.1 | 6.4.3 |
| `packaging` | 26.0 | 26.2 |
| `platformdirs` | 4.9.4 | 4.10.0 |
| `pygments` | 2.19.2 | 2.20.0 |
| `python-dateutil` | 2.9.0.post0 | 2.9.0 |
| `python-discovery` | 1.1.1 | 1.4.2 |
| `pytz` | 2026.2 | 2025.2 |
| `typing_extensions` | 4.15.0 | 4.16.0 |
| `virtualenv` | 21.1.0 | 21.5.1 |
| `yarl` | 1.24.5 | 1.23.0 |

*Present in both, identical version (21):* `aiohappyeyeballs`,
`aiosignal`, `annotated-doc`, `annotated-types`, `anyio`, `attrs`,
`colorama`, `distlib`, `dnspython`, `frozenlist`, `h11`, `httpcore`,
`httpx`, `pathspec`, `pluggy`, `propcache`, `pyyaml`, `requests`, `six`,
`typing-inspection`, `urllib3`.

**The one divergence that matters: `neo4j` 6.1.0 vs. `5.2.dev0`.** Not a
patch difference — the system interpreter was running a *prerelease dev
build* of a major version behind the project's pin. Every other mismatch
above is a minor/patch version, low risk for the simple ORM queries and
HTTP calls this codebase makes.

**(c) Which numbers are affected — re-run under the correct venv and
diffed against what was reported, not assumed either way:**

- **Neo4j-dependent (the real risk): CONFIRMED IDENTICAL, verified not
  assumed.** Re-ran `CampaignDetector().find_connected_clusters()` and the
  full `js.clearfake` composition/solo-under-actual-BFS check under
  `neo4j==6.1.0`. Byte-for-byte match against every previously reported
  number: 1,396 clusters, top-10 sizes
  `[1849, 1073, 1054, 485, 258, 231, 196, 170, 145, 136]`, 13,496 total
  members, 16 clusters touching `js.clearfake`, 782/908 captured, and the
  exact same per-cluster composition percentages (16.0%, 7.6%, 12.0%,
  4.7%, 16.5%, 63.3%, 80.6%, 1.2%). **These numbers stand.** The BFS Cypher
  query's determinism (explicit `ORDER BY`, no reliance on driver-internal
  ordering) is the likely reason a full major-version jump produced no
  observable difference — worth knowing, not worth relying on next time
  without checking again.
- **Postgres-only (cohesion tables, connectivity sweep, leave-one-out
  decomposition, type-attributed breakdown): re-run, numbers matched, but
  with a confound worth stating plainly rather than glossing over.** The
  unrestricted-connectivity ARI (0.2194) and the `js.clearfake`-held-out
  ARI (0.0302) both reproduced exactly under the correct venv. The
  `win.metastealer`/`js.clearfake`/`win.cobalt_strike` cohesion figures
  also reproduced exactly. **However, this was not a clean interpreter-only
  comparison:** the item-2.4-follow-up `ip:port` backfill (next section)
  ran on the live database *between* the original computation and this
  re-check, so the underlying `IndicatorEnrichment` data is not identical
  across the two runs (component count under unrestricted connectivity
  shifted 75→103, though ARI net was unaffected). The raw ThreatFox
  `ioc_type` counts (domain/`ip:port`/url/hash — untouched by that backfill,
  since `RawIndicator` is immutable) were independently re-verified and
  match exactly: 2,317/977/551/111/76/76. **Verdict: these numbers stand,
  on the evidence above, but the Postgres-side re-check is not as clean a
  proof as the Neo4j-side one** — a fully isolated re-run (before the
  `ip:port` fix touched the database) was not possible after the fact
  without extra archaeology, and wasn't done.
- **`sqlalchemy`/`pydantic` minor-version deltas:** no specific behavioral
  divergence found or suspected in the query patterns this codebase uses
  (simple ORM filters, no version-sensitive features); not exhaustively
  proven absent, but the neo4j check above — the one dependency with an
  actual major-version gap — is the one this session's numbers most
  plausibly could have depended on, and it's now confirmed clean.

**(d) This note is that write-up.** Filed under its own heading rather
than folded into item 6 or item 7 because it's an environment-integrity
finding that touches everything above it, not a finding about degree
weighting or the evaluation harness specifically.

---

## 6b. Ground-truth join-key fix and corrected enrichment/cohesion figures, 2026-07-23

**Item 1 — the join-key mismatch, root cause and fix.**
`ground_truth.py` keyed labels on `RawIndicator.value` (the raw,
as-collected display string); `InfrastructureEngine.build_fingerprints()`/
`build_weighted_fingerprints()` key on `Indicator.value` (post-validation,
post-normalization). `create_indicator()` (`indicator_service.py`)
routinely changes the value between the two — canonicalizing pseudo-types
(item 2.4's `ip:port` fix) and normalizing (`normalize_url()` strips a
trailing slash, `normalize_domain()` lowercases and strips `www.`/scheme)
— so the two tables' values differ for the same real indicator far more
often than just the `ip:port` case this was discovered investigating.

**Measured before this fix, not assumed: 764/4,108 (18.6%) of
ThreatFox-labelled indicators were silently unjoinable for reasons
entirely unrelated to `ip:port`** — overwhelmingly URL trailing-slash
normalization (e.g. `https://insights.business/` in `RawIndicator.value`
vs. `https://insights.business` in `Indicator.value`). A further 1/4,108
(`Toureurpi51924.icu`) has no corresponding `Indicator` row at all even
after canonicalization — not investigated further, negligible at this
scale. **This means the original item-7 diagnostic's cohesion figures
(the "bimodal" table, §6 above) were computed on a join that was already
dropping 18.6% of labels before the `ip:port` migration was ever
implemented.** They are superseded below, not just re-run for the
migration's sake.

**Fix:** `ground_truth.py::_canonical_key()` recomputes the same
`canonicalize_indicator_type()` → `normalize_indicator()` transform
`create_indicator()` applies, and both `build_threatfox_labels()`/
`build_otx_labels()` now key on that instead of the raw value — a pure
function of already-stored data, not a schema change (no FK currently
exists between `RawIndicator` and `Indicator`; adding one was the
alternative considered and not taken, to keep this fix scoped). 3 new
tests (`test_ground_truth.py`): an `ip:port` label survives the join, a
trailing-slash URL label survives the join, and a mixed batch's labelled
count matches exactly. Full suite: 149 passed.

**Side effect, quantified, not hidden: keying by canonical value collapses
some distinct `RawIndicator` rows onto the same real indicator.** Labelled
`RawIndicator` rows: 4,108. Distinct canonical keys (`build_threatfox_labels()`'s
output size) post-fix: **3,628** — mostly `ip:port` entries differing only
by port, correctly recognized as the same underlying IP (this is the
Postgres side of the exact 977→498 collapse the `ip:port` migration itself
already reported). Checked explicitly for the failure mode this could
cause: 176 canonical keys received more than one raw row, and of those,
**2 had genuinely conflicting family labels** — the same IP, different
ports, reported by ThreatFox under two different malware families
(`23.94.197.120`: `win.asyncrat` on two ports, `win.remcos` on a third;
`141.11.243.110`: `jar.adwind` vs. `jar.strrat`). Python dict semantics
keep whichever the query returns last, silently discarding the other. 2 of
4,108 (0.05%) — noted, not fixed further; a multi-label scheme would be
needed to represent this correctly and isn't justified at this rate.

**Item 2 — type-attributed enrichment table, recomputed with both fixes
applied. This replaces both prior figures, not just the more recent one:**

| Type | n | % of set | Enriched | No `Indicator` row |
|---|---|---|---|---|
| `domain` | 2,317 | 56.4% | 51.2% (1,186) | 1 |
| `ip:port` | 977 | 23.8% | **100.0%** (977) | 0 |
| `url` | 551 | 13.4% | **88.2%** (486) | 0 |
| `sha256_hash` | 111 | 2.7% | 0.0% | 0 |
| `sha1_hash` | 76 | 1.9% | 0.0% | 0 |
| `md5_hash` | 76 | 1.9% | 0.0% | 0 |

**Total enriched: 2,649/4,108 (64.5%). Total unenriched: 1,458/4,108
(35.5%).** Deltas from each prior figure, stated explicitly:
- vs. the original claim (**"~37% unenriched, hash-driven"**): both
  magnitude and attribution were wrong, already corrected once (§6, "the
  hash-only, item 2.4 attribution above is wrong"). This entry supersedes
  that correction's own numbers too.
- vs. the intermediate figure (**"65.3% unenriched"**, reported
  immediately after the `ip:port` migration but before this join fix): also
  wrong, and by a large margin — the true unenriched rate is **35.5%, essentially
  half of what was reported.** That 65.3% was itself an artifact of this
  same join-key bug: it showed `ip:port` at 0.0% enriched (in reality
  100.0%, the migration worked correctly the whole time) and `url` at 44.3%
  (in reality 88.2%). The migration was never broken; the measurement of
  it was.

**Item 3 — family cohesion, recomputed under both fixes. `win.metastealer`
confirms as predicted; the bimodal shape does not survive intact.**

| Family | n | Enriched | Cohesion (overall) | vs. original figure |
|---|---|---|---|---|
| `win.metastealer` | 997 | 0.3% | 0.3% | 0.2% → 0.3%, **unchanged as predicted** |
| `js.clearfake` | 908 | 86.3% | 85.7% | 85.5% → 85.7%, unchanged |
| `unknown` | 528 | 96.6% | 85.4% | 35.3% → **85.4%**, large move |
| `win.vidar` | 247 | 78.5% | 73.7% | 34.4% → 73.7%, large move |
| `js.kongtuke` | 121 | 100.0% | 100.0% | unchanged |
| **`win.cobalt_strike`** | 88* | 100.0% | **76.1%** | **0.0% → 76.1%** |
| `js.iclickfix` | 58 | 98.3% | 60.3% | 58.6% → 60.3%, minor move |
| **`win.adaptix_c2`** | 54* | 100.0% | **55.6%** | **0.0% → 55.6%** |
| `win.asyncrat` | 48* | 75.0% | 47.9% | 0.0% → 47.9% |

*n dropped from the original count (257/144/69) because of the canonical
collapse above — this is the same family measured on fewer, correctly
deduplicated real indicators, not a different population.

**`win.metastealer` sits exactly where predicted: ~0%, unrelated to
either fix.** Re-verified the mechanism directly (unchanged from the
earlier check): its domains are DGA-pattern, have an `IndicatorEnrichment`
row (enrichment was attempted), and every field is null — dead or never-
registered infrastructure, a genuine data property neither fix touches.
Two other families keep their original near-zero reading correctly too:
`py.venus_stealer` (0.0%, 39 members) and `win.wannacryptor` (0.0%, 24
members) are ThreatFox's actual hash-reported families (confirmed in the
item-2.4 follow-up's family-hash-count check) — item 2.4 is a real,
correct explanation for *these specific* families, just never the dominant
one overall.

**But `win.cobalt_strike`, `win.adaptix_c2`, and `win.asyncrat` — three of
the five families the original diagnostic filed as "hash-only,
structurally unenrichable" — move from 0% to 48–76% cohesion.** They were
never hash-reported at all (confirmed earlier: 100% `ip:port`, `win.asyncrat`
mostly `ip:port`); their true near-zero reading was entirely the join-key
bug hiding real, substantial infrastructure cohesion that was there the
whole time. **The original "clean bimodal" finding (91–100% vs. 0–3%,
domain/URL vs. hash-reported) does not survive as stated and is retracted
as a clean two-cluster claim, left visible here rather than silently
corrected.** The corrected distribution is a spectrum — 0%, 0.3%, 16.7%
(`elf.mirai`), 17.2% (`win.valley_rat`), 25.9% (`unknown_stealer`), 47.9%,
55.6%, 60.3%, 73.7%, 76.1%, 85.4%, 85.7%, 100%, 100% — not two clusters.
The genuinely-near-zero cases (`win.metastealer`, `py.venus_stealer`,
`win.wannacryptor`) remain real and remain explained the same way (dead
DGA infrastructure; genuine hash-only reporting, respectively) — what's
gone is the implication that *most* of the near-zero cases shared that
explanation. Most of them didn't; they were a measurement artifact.

**What this means, stated plainly: the "~37% structurally unclusterable"
claim is retracted in full, and it was the load-bearing explanation for
this whole session's low-ARI finding.** It was wrong on magnitude (true
unenriched rate 35.5%, not ~37% — close by coincidence, not because the
reasoning was right), wrong on attribution (hashes are ~6% of the set, not
the driver), and its supporting evidence (the clean bimodal cohesion
split) was itself a join-key measurement artifact, not a real structural
pattern in the data. Item 2.4 (hash enrichment) is demoted to a minor,
correctly-scoped item covering `py.venus_stealer` and `win.wannacryptor`
specifically (~1.5% of the labelled set combined) — not a claim about the
evaluation's validity. **The open question of why ThreatFox ARI sits
around 0.07 is therefore reopened, not answered.** Every prior attempt to
explain it in this session (the bimodal cohesion story, the
unrestricted-connectivity "headroom" framing) was computed on joins
silently dropping 18.6% of labels, under an unverified interpreter. Item 3
below re-runs the numbers the paper's central claim actually rests on
against the corrected data.

---

## 6c. Core evaluation numbers, re-run against corrected joins, 2026-07-23

**ThreatFox ARI/precision/recall — baselines and both BFS rows, corrected
join, deltas from the pre-fix figures stated explicitly:**

| Method | ARI (old → new) | Δ ARI | Precision (old → new) | Recall (old → new) |
|---|---|---|---|---|
| Random baseline | 0.0000 → -0.0001 | ~0 | 0.1481 → 0.1548 | 0.0006 → 0.0006 |
| GROUP BY ASN | 0.0530 → 0.0535 | +0.0005 | 0.3480 → 0.3145 | 0.0499 → 0.0648 |
| GROUP BY resolved IP | 0.0062 → 0.0107 | +0.0045 (+73%) | 0.9982 → 0.9969 | 0.0036 → 0.0065 |
| GROUP BY hosting_provider | 0.0530 → 0.0534 | +0.0004 | 0.3479 → 0.3140 | 0.0499 → 0.0648 |
| Jaccard v1 | 0.0432 → 0.0514 | +0.0082 (+19%) | 0.9842 → 0.9280 | 0.0258 → 0.0320 |
| BFS, all clusters (unweighted) | 0.0827 → 0.0897 | +0.0070 (+8.5%) | 0.5687 → 0.5755 | 0.0596 → 0.0682 |
| BFS reported, unweighted | 0.0716 → 0.0777 | +0.0061 (+8.5%) | 0.5375 → 0.5454 | 0.0523 → 0.0601 |
| **BFS reported, weighted** | 0.0712 → 0.0770 | +0.0058 (+8.1%) | 0.5364 → 0.5434 | 0.0521 → 0.0596 |

**Every method's ARI moved up modestly (0–19%) — correctly joining
previously-invisible labels added real signal across the board, not
selectively to any one method.** The comparison that actually decides
item 6's central question is unchanged: **weighted-vs-unweighted BFS is
still flat** (0.0777 → 0.0770, Δ -0.0007, -0.9%; was Δ -0.0004, -0.6%
pre-fix). Degree weighting still shows no ARI improvement over unweighted
BFS on corrected data — that conclusion survives the join fix.

**Connectivity sweep — this one moved a lot, and not in the direction a
naive "more correct joins = higher ARI" expectation would predict:**

| Threshold | ARI (old, buggy join → new, corrected) |
|---|---|
| unrestricted | **0.2194 → 0.0962** (Δ -0.1232, **-56%**) |

The unrestricted-connectivity result **more than halved**, not improved.
Explanation, best available, not fully decomposed further: previously
join-invisible families (`win.cobalt_strike`, `win.adaptix_c2`,
`win.asyncrat` — §6b) are now correctly evaluated, and under
*unrestricted* connectivity (no depth limit, everything sharing any
feature merges transitively — only 103 components total, largest 11,200)
their members mostly land inside the same few giant, low-purity
components as everyone else, rather than staying grouped with each other.
Consistent with this: in the leave-one-out sweep below, holding out
*any* family except `js.clearfake` (and marginally `elf.mirai`) now
*increases* the aggregate ARI — most families are net-negative
contributors to this particular unrestricted-connectivity number, not net
contributors. This was invisible before the join fix because those
families weren't in the evaluated population at all.

**Leave-one-out, corrected join — `js.clearfake`'s dominance is not
weakened by the correction, it's strengthened:**

| Held out | ARI | Δ from baseline (0.0962) |
|---|---|---|
| *(none — corrected baseline)* | 0.0962 | — |
| **`js.clearfake`** | **0.0093** | **-0.0869 (90.3% of baseline)** |
| `unknown` | 0.1285 | +0.0323 |
| `win.vidar` | 0.1213 | +0.0251 |
| `js.kongtuke` | 0.1169 | +0.0207 |
| `win.metastealer` | 0.1095 | +0.0133 |
| `win.cobalt_strike` | 0.1073 | +0.0111 |
| `js.iclickfix` | 0.1047 | +0.0085 |
| `win.adaptix_c2` | 0.1012 | +0.0050 |
| `win.asyncrat` | 0.0970 | +0.0008 |
| `elf.mirai` | 0.0926 | -0.0036 |

Pre-fix, `js.clearfake` accounted for 0.1892/0.2194 (86.2%) of the
unrestricted-connectivity ARI. Post-fix, it accounts for 0.0869/0.0962
(**90.3%**). The class-skew finding (§6, item 6's write-up) is confirmed,
not weakened, by the corrected join — if anything the dependence on one
family is now more extreme, since the other families that used to be
invisible turned out to be net drags on the aggregate, not contributors.

**`js.clearfake` composition and solo-under-actual-BFS check — exactly
unchanged, confirmed not assumed.** `js.clearfake`'s own raw values are
almost entirely `domain`-type (86.2%→86.3% enriched across both fixes,
essentially no movement), so its evaluation was never meaningfully exposed
to either the `ip:port` migration or the join-key bug. Re-ran the full
composition/solo table against actual BFS under the corrected join: 16
clusters touching, 782/908 captured, pairwise recall 0.1609 (raw) /
0.1405 (both reported variants) — **identical to every previously reported
number, to four decimal places**, including the exact same per-cluster
composition percentages (16.0%, 7.6%, 12.0%, 4.7%, 16.5%, 63.3%, 80.6%,
1.2%). **The hub-dilution finding (§6b's retraction, item 6's write-up)
stands, fully verified against corrected data — it was never affected by
either the `ip:port` or join-key bug in the first place.**

**Net picture:** the two findings this session's central claims actually
rest on — (1) weighted vs. unweighted BFS shows no ARI improvement, and
(2) `js.clearfake` dominates the unrestricted-connectivity signal and is
substantially diluted into commodity-hub clusters under real BFS — both
**survive the corrected data, essentially unchanged**. What did not
survive was the *explanation* for the low aggregate ARI (§6b) and the
exact magnitude of the connectivity-sweep "headroom" number, which was
overstated by more than half.

**The two load-bearing findings survived clean data, stated in exactly
those terms because it's the important outcome of this whole correction
cycle: the paper's central claim does not rest on any retracted number.**
(1) Weighted-vs-unweighted BFS shows no ARI improvement — flat before the
join fix, flat after, on data now verified clean of both the venv and the
join-key defects. (2) `js.clearfake` dominates the unrestricted-
connectivity signal and is substantially diluted into commodity-hub
clusters under real BFS — unaffected by either bug from the start, and
confirmed to four decimal places twice now.

**Where this leaves the claim.** The paper's §3 framing as written —
"present a degree-weighted correlation method that suppresses [commodity
over-clustering]" as a method that produces better campaign detection — is
not supported by any measurement taken this session, clean or otherwise.
What *is* supported, on evidence collected this session:
- Commodity hubs measurably absorb real campaign signal (`js.clearfake`,
  61% of captured members diluted into four hub clusters at 5–17% purity
  each — item 6/§6b).
- The type-level "has another shared attribute" check undercounts
  commodity exposure (item 6's `Nameserver`/`Registrar` finding,
  independent of ARI).
- Degree weighting suppresses commodity `R(C)` contribution exactly as
  designed, with a monotonic gradient by exposure level (item 6) — but
  this does not translate into clustering accuracy, confirmed twice on
  clean data (§6c).
- ARI ~0.07 is not explained by ground-truth orthogonality — that
  explanation is retracted in full (§6b) and superseded below.

That is a coherent, defensible paper: quantify the failure mode, show the
intuitive fix (degree weighting) works mechanically but does not move
accuracy, and explain why. It is a narrower claim than §3 currently states.

---

## 6d. Connectivity-sweep decomposition and the §10 open question, 2026-07-23

**Decomposing the 0.2194→0.0962 drop: distributed across many families,
not concentrated in one — upgrading this from "best available explanation"
to a checked finding, per the standard applied throughout this
correction cycle.** Partitioned the corrected 3,628-label set into
"old-visible" (764 raw values that were already exact-match joinable
before the fix) and "newly-visible" (764 keys only reachable via
canonicalization). `ARI(old-visible only) = 0.1658`, not a clean
reproduction of the original 0.2194 — the intervening `ip:port` backfill
changed the underlying connectivity graph itself (new ASN/hosting features
on 498 indicators), so even the "old" subset is being measured against a
graph that has since changed; noted as a real confound, not smoothed over.
`ARI(new-visible only) = 0.0418`. Combined = 0.0962 (matches §6c).

Excluding each newly-visible family's contribution individually (all else
held constant): `win.vidar` +0.0117, `win.cobalt_strike` +0.0111,
`win.adaptix_c2` +0.0050, `apk.kimwolf` +0.0038, `elf.aisuru` +0.0032,
`win.havoc` +0.0028, `win.vshell` +0.0025, `win.asyncrat` +0.0024,
`elf.mirai` +0.0001 — and `unknown` **-0.0034** (its newly-visible members
are a net-positive contributor, the one exception). **No single family
accounts for more than ~10% of the total drop; excluding all ten largest
newly-visible families together only recovers to 0.1498, not back to
0.2194.** The drop is a broad dilution effect — many previously-invisible
families' members each individually landing in the same few giant,
low-purity unrestricted-connectivity components as unrelated material —
not a single culprit. This is now a checked, decomposed finding, not an
inference.

**§10 reopened question, answered with evidence: (a) method, not (b)
ground truth, not primarily (c) task infeasibility.**

(b) is dead: cohesion is 76–100% across every enrichable family checked
(§6b). Ground truth is not orthogonal to infrastructure.

The decisive check — does actual BFS capture what's demonstrably
*achievable* for a given family, checked across five families, not
assumed from one:

| Family | n | Achievable recall (unrestricted connectivity) | Actual recall (BFS, reported, weighted) | Gap |
|---|---|---|---|---|
| `unknown` | 528 | 0.7822 | 0.0429 | 0.7393 |
| `win.cobalt_strike` | 88 | 0.6695 | **0.0000** | 0.6695 |
| `js.clearfake` | 908 | 0.7435 | 0.1609 | 0.5826 |
| `win.vidar` | 247 | 0.5973 | 0.0300 | 0.5673 |
| `win.adaptix_c2` | 54 | 0.4941 | **0.0000** | 0.4941 |

**Every family checked shows a large gap (0.49–0.74) between what is
demonstrably achievable and what BFS actually captures; two families
(`win.cobalt_strike`, `win.adaptix_c2`) show actual recall of exactly
zero despite being 49–67% achievably cohesive.** This is not one case
study (the `js.clearfake` hub-dilution finding) generalizing by
assumption — it is now checked across five families independently and
holds in all five. **(a) is the current best-evidenced answer: BFS's own
traversal (`d=2`, `k=3`) and/or the confidence-reporting threshold
systematically fail to capture same-family cohesion that demonstrably
exists in the data**, largely via the same hub-dilution mechanism §6b
already demonstrated concretely for `js.clearfake` (61% of its captured
members diluted into four low-purity commodity-hub clusters). (c) task
infeasibility remains real and separately quantified (~6% hash-typed,
~24% `win.metastealer`'s dead-DGA-domains — both categorically out of
scope for any infrastructure method) but is a distinct, independent
ceiling-lowering factor, not an explanation for the shortfall on the
demonstrably-cohesive, in-scope portion this table measures.

**Practical implication, not yet acted on:** since degree weighting only
changes confidence *scores* and never changes BFS's own clustering
membership (methodology note, item 6/7), this finding points squarely at
BFS's traversal parameters (`d=2`/`k=3`) or the confidence-reporting
threshold as the next lever to check — item 3.2's parameter sweep,
already on the work order, now has direct evidence motivating it rather
than being a generic "parameters were asserted, not derived" concern.

Both items complete. Still not starting the scope-condition table.

---

## 6e. `d`/`k` traversal sweep, and a genuine new graph-construction defect, 2026-07-23

**SUSPENDED, not deleted, 2026-07-23, same day — read this before citing
any conclusion below.** This section's "the failure is structural to BFS"
verdict (task 1) and the achievable-vs-actual gap table (§6d, item 2) were
both computed on a graph confirmed by this same section (below) to be
missing every `RESOLVES_TO_ASN`/`HOSTED_BY` edge for any `:IP` node —
8,120 nodes, the entire history of the graph. BFS cannot traverse edges
that were never built, so "structural to BFS" is confounded with
"structural to a graph missing a whole edge class" and cannot currently
be told apart. Likewise, the achievable-recall side of the gap table was
computed from Postgres enrichment directly (bypassing Neo4j), while the
actual-recall side came from this same edge-missing graph — the two sides
were never measuring the same data. §6f fixes the defect, rebuilds the
graph, and re-runs both. **If §6f reproduces this section's numbers, the
structural conclusion is real and far better evidenced. If the gaps close
materially, the paper's central claim changes again.** Both outcomes are
live until §6f reports.

**RESOLVED in §6f, 2026-07-23, same day: split verdict, not a clean win
for either side of the question above.** `js.clearfake`/`unknown`/
`win.vidar` (never exposed to the defect) reconfirmed almost exactly —
`js.clearfake` bit-for-bit identical. `win.cobalt_strike`/`win.adaptix_c2`
(the two exact-zero cases) recovered substantially after the fix (to 18%
and 6% of their achievable ceilings respectively) but did not close —
large gaps remain. Read §6f before citing anything below as a final
number; the table below is superseded for those two families and
confirmed for the other three.

**Task 1 — swept `d` ∈ {1,2,3} × `k` ∈ {2,3,5}, raw BFS (no confidence
filter), recall against each family's known achievable ceiling (§6d):**

| d | k | n_clusters | `unknown` | `cobalt_strike` | `js.clearfake` | `vidar` | `adaptix_c2` |
|---|---|---|---|---|---|---|---|
| 1 | 2/3/5 | 6483/3180/306 | 0.002–0.004 | 0.0000 | 0.0002 | 0.004–0.005 | 0.0000 |
| 2 | 2/3/5 | 4938/1396/407 | 0.042–0.043 | 0.0000 | 0.1609 | 0.030–0.031 | 0.0000 |
| 3 | 2/3/5 | 1684/744/334 | 0.103–0.104 | 0.0000 | **0.1609** | 0.074 | 0.0000 |

(Achievable ceilings, for reference: `unknown` 0.78, `cobalt_strike` 0.67,
`js.clearfake` 0.74, `vidar` 0.60, `adaptix_c2` 0.49.)

**`k` has essentially no effect on any family at any `d`.** **`d` has a
real but small effect for `unknown`/`win.vidar`** — roughly doubles going
`d=2→d=3` (0.043→0.103, 0.030→0.074) — but even at `d=3` this reaches only
~10–13% of the achievable ceiling, not a material fraction of the gap.
**`js.clearfake` — the single largest, most consequential family — shows
*zero* sensitivity to depth: 0.1609 at `d=2`, 0.1609 at `d=3`, identical.**
Extra traversal depth does not recover any of its cohesion; consistent
with §6b's finding that its captured members are already fully absorbed
into the same giant commodity-hub clusters at `d=2`, and going deeper
apparently grows those same clusters with more unrelated material rather
than pulling in more `js.clearfake` pairs specifically. `win.cobalt_strike`/
`win.adaptix_c2` are flat zero across every `(d,k)` combination tested —
addressed directly below, because the cause turned out not to be depth at
all. **Verdict on task 1's stated test: no parameter setting in the tested
range materially closes the gap for the two families that matter most
(`js.clearfake` by size, `cobalt_strike`/`adaptix_c2` by being the
starkest zero). The failure is structural, not a tuning gap** — though for
two different structural reasons, not one, found below.

**Task 2 — neither the confidence filter nor traversal depth explains
`win.cobalt_strike`/`win.adaptix_c2`'s exact-zero recall. A third,
previously undiscovered cause does: these indicators were never wired into
the Neo4j graph at all.**

Checked directly, not inferred: raw (unfiltered) BFS at `d=2,k=3` already
shows **zero clusters touching either family** — so the confidence filter
has nothing to do with it (there was nothing to filter). Checked whether
depth was the cause by querying the graph directly for all 88
`win.cobalt_strike` and 54 `win.adaptix_c2` IP values: **all 142 have no
`:IP` node in Neo4j at all** — not "a node with zero edges," genuinely
absent.

**A first attempt at this same check produced a wrong intermediate
result, corrected in the same investigation rather than left standing:**
an initial per-value Cypher query (`MATCH (n:IP {value:$val}) OPTIONAL
MATCH (n)-[r]-() RETURN count(r)...`) reported "node exists, degree 0" for
a 15-value sample. That reading was wrong — Cypher's aggregation semantics
mean a non-optional `MATCH` that finds nothing still returns one row with
`count(r)=0` (the same way `SELECT COUNT(*) FROM t WHERE false` returns
one row reading 0 in SQL, not zero rows), so that query could not actually
distinguish "node absent" from "node present with no edges." A corrected
query (`OPTIONAL MATCH` on the node itself, returning `n IS NOT NULL`
explicitly) resolved this: node absent, not node-present-empty. Left in
the record as a caught, corrected error, same convention as every other
retraction this session.

**Root cause, found by then checking the whole graph, not just these two
families: `GraphBuilder` has never created an ASN/hosting edge from any
`:IP` node's own enrichment, for the entire life of this graph.** Queried
every relationship touching any `:IP` node, graph-wide (8,120 `:IP`
nodes): only `INDICATES` (225, the generic-layer edges item 2.5 already
flags) and `RESOLVES_TO_IP` (11,131, domains resolving *to* an IP) appear.
**Zero `RESOLVES_TO_ASN` or `HOSTED_BY` edges touch any `:IP` node in the
graph.** Confirmed against the code: `GraphBuilder.ingest_indicator()`'s
`if indicator_type == "ip":` branch (`graph_builder.py`) does only
`MERGE (ip:IP {value:$ip})` — no relationship creation at all — while the
equivalent `domain`/`url` branches call
`create_domain_infrastructure_relationship()`, which does wire
ASN/hosting/registrar/nameserver edges. An IP-type indicator's own
enrichment (populated in Postgres — confirmed 99%+ ASN coverage after the
item-2.4 `ip:port` fix) has **never** been reflected into the graph;
any `:IP` node with nonzero degree has it purely incidentally, via some
unrelated domain's `RESOLVES_TO_IP` edge landing on the same IP value, not
via its own infrastructure data.

**A second, compounding cause specific to these two families: the graph
was never rebuilt after the `ip:port`→`ip` Postgres migration (§6b).**
That fix updated `Indicator` rows and re-ran enrichment in Postgres; it
never triggered `graph_worker.py`. So even if the `GraphBuilder` defect
above were fixed today, these specific 498 migrated indicators would
still need a graph rebuild to appear as nodes at all — two independent,
stacked gaps, not one.

**This is a genuine, previously undiscovered, structural defect —
recommended as a new TIER 2 item (provisionally 2.9) when this document is
next reorganized, not fixed here per this round's report-only scope.** It
plausibly caps BFS's ability to cluster *any* IP-type indicator via
shared infrastructure, for the whole dataset, not just these two ThreatFox
families — 723 type=`ip` indicators total, of which only 233 have any
graph connectivity, and that connectivity is entirely incidental.

Both tasks answered. Still not starting the scope-condition table.

---

## 6f. GraphBuilder fix, full rebuild, and §6e's suspended conclusion resolved, 2026-07-23

**Item 2.9 fixed.** `GraphBuilder.create_ip_infrastructure_relationship()`
added, mirroring `create_domain_infrastructure_relationship()`'s
`RESOLVES_TO_ASN`/`HOSTED_BY` wiring but scoped to only `asn`/
`hosting_provider` (the only fields `build_enrichment_data()` ever
populates for IP-type indicators — no registrar/nameservers/resolved_ips
apply to a bare IP). Wired into `ingest_indicator()`'s `ip` branch, after
the existing bare-node `MERGE`. 4 new tests
(`test_graph_builder.py`): an IP indicator with enrichment produces both
edge types with correct values; the comma-separated multi-ASN case
(mirroring item 2.3's domain test); no enrichment still creates the bare
node. Full suite: 152 passed.

**Full rebuild run: `GraphBuilder.ingest_all_indicators()`, all 23,135
indicators, 1,230.7s (20.5 min).** Node/edge counts before → after, every
type, not a summary:

| Node label | Before | After | Δ |
|---|---|---|---|
| `Indicator` | 22,637 | 23,135 | +498 |
| `IP` | 8,120 | 8,610 | +490 |
| `ASN` | 619 | 736 | +117 |
| `HostingProvider` | 582 | 693 | +111 |
| `URL`/`Domain`/`Registrar`/`Nameserver`/`Hash` | unchanged | unchanged | 0 |

| Edge type | Before | After | Δ |
|---|---|---|---|
| `INDICATES` | 22,642 | 23,140 | +498 |
| `RESOLVES_TO_ASN` | 7,602 | 8,320 | **+718** |
| `HOSTED_BY` | 7,439 | 8,157 | **+718** |
| `HOSTS`/`REGISTERED_WITH`/`RESOLVES_TO_IP`/`USES_NS` | unchanged | unchanged | 0 |

**718 of 723 type=`ip` indicators (99.3% — matches item 2.7's known
GeoLite2 hit rate exactly) now carry their own `RESOLVES_TO_ASN`/
`HOSTED_BY` edge; before this fix, zero did.** The `+490` `IP`-node delta
and `+498` `Indicator`/`INDICATES` delta both come from the previously
un-graph-built `ip:port`→`ip` migration cohort (§6b) finally getting
built at all, confirmed by count: 723 total type=`ip` indicators − 233
that already had a node (§6e) = 490, exact match.

**§6e resolved, not simply reconfirmed or overturned — the answer splits
cleanly by which families were actually exposed to the defect:**

| Family | Achievable | Actual, pre-rebuild (§6e) | Actual, post-rebuild | Δ |
|---|---|---|---|---|
| `js.clearfake` | 0.7435 | 0.1405 | **0.1405** | **0.0000 — bit-for-bit unchanged** |
| `unknown` | 0.7822 | 0.0429 | 0.0428 | -0.0001, noise |
| `win.vidar` | 0.5973 | 0.0300 | 0.0224 | -0.0076, slightly worse |
| **`win.cobalt_strike`** | 0.6695 | **0.0000** | **0.1186** | **+0.1186** |
| **`win.adaptix_c2`** | 0.4941 | **0.0000** | **0.0287** | **+0.0287** |

**`js.clearfake`, `unknown`, `win.vidar` (all domain/URL-type, never
touched by the IP-edge defect): essentially exactly reconfirmed.**
`js.clearfake` in particular is identical to four decimal places — the
third independent confirmation of this specific number this session (§6c,
§6e, §6f). Their large achievable-vs-actual gaps (0.60–0.74) are real,
were never confounded by the graph defect, and stand as genuinely
structural to BFS's traversal/dilution behavior.

**`win.cobalt_strike`/`win.adaptix_c2`: the defect was real and partially
explains their zero, but does not fully explain it.** Fixing the missing
edges moved both off exact zero — `cobalt_strike` recovers to 0.1186
(**18% of its 0.6695 ceiling**), `adaptix_c2` to 0.0287 (**6% of its
0.4941 ceiling**). Large gaps remain (0.55, 0.47) even with the edges
present. The `d`/`k` sweep on the rebuilt graph confirms these two are
now flat *at their new, nonzero* value across `d=2` and `d=3`
(`cobalt_strike`: 0.1217 at both; `adaptix_c2`: 0.0468 at both) — so once
the edges exist, additional traversal depth doesn't recover more, the
same "depth doesn't help" pattern §6e found for `js.clearfake`, just from
a higher floor. **Verdict: two stacked causes, not one — the graph defect
capped these two families at literally zero; fixing it reveals the same
underlying structural BFS limitation the other three families already
showed, just previously invisible under total absence of signal.**

**ThreatFox ARI, weighted vs. unweighted, rebuilt graph — third
independent confirmation, still flat:**

| | Pre-rebuild (§6c) | Post-rebuild | Δ |
|---|---|---|---|
| BFS reported, unweighted | 0.0777 | 0.0785 | +0.0008 |
| BFS reported, weighted | 0.0770 | 0.0777 | +0.0007 |
| **weighted − unweighted** | **-0.0007** | **-0.0008** | **~0, unchanged** |

The graph-wide fix moved the aggregate ARI by less than a point (both
rows +0.0007–0.0008) — `cobalt_strike`/`adaptix_c2`'s relative recovery is
real but their 142 combined members are too small a share of the
3,628-label aggregate to move it further. **The finding that matters most
for the paper survives a third time, now on a graph independently
verified complete for IP-derived infrastructure: degree weighting still
shows no ARI improvement over unweighted BFS.**

**Resolution of §6e's suspension, stated plainly as requested:** the
"failure is structural to BFS" conclusion is **confirmed for the
domain/URL-type majority of cases** (`js.clearfake`, `unknown`,
`win.vidar` — unaffected by the defect, numbers essentially unchanged) and
**was genuinely confounded, but only partially, for the two IP-type
cases** (`win.cobalt_strike`, `win.adaptix_c2` — real recovery from zero,
real remaining gap on top). Neither "reproduces §6e exactly" nor "the gaps
close materially" is the full story; both partially happened, cleanly
separable by which families the fixed defect could possibly have touched.

Item 2.9 should be added to the TIER 2 defect list proper the next time
this document is reorganized (currently only referenced from §6e/§6f).

Both re-runs and the fix are complete. Still not starting the
scope-condition table — awaiting direction as instructed.

---

## 6g. Scope-condition table and confidence-filtered baselines, 2026-07-23 — item 7 complete

**Scope condition, declared as an input property before computing
anything, applied identically to every method and every baseline:** an
indicator is in scope iff it carries ≥1 enriched infrastructure attribute
(`InfrastructureEngine.build_weighted_fingerprints()` returns a non-empty
feature set for it — an indicator with an enrichment row but every field
null maps to an empty set and is correctly excluded, same as an indicator
never enriched at all). Computed once, against the corrected labels
(§6b's join fix) on the rebuilt graph (§6f). **2,169 of 3,628 labelled
indicators (59.8%) are in scope.** This is an input property, not tuned
per method — the same 2,169 indicators are used to compute every method's
"scoped" column below.

**Every baseline now scored and confidence-filtered exactly like the two
BFS rows already were — the apples-to-apples gap open since item 7's
first pass (§6, "Not done, worth doing...") is closed.** Every method's
clusters were passed through `CampaignConfidenceScorer` (unweighted
fingerprints, `degrees=None` — the same "unweighted" convention the
`bfs_unweighted_reported` row already used) and filtered to
confidence≥40, producing a "reported" set for `random_baseline`,
`group_by_asn`, `group_by_resolved_ip`, `group_by_hosting_provider`, and
`jaccard_v1`, alongside the two existing BFS reported rows (weighted BFS
keeps its own weighted fingerprints/degrees, as it must to mean anything).

**All clusters (unfiltered) — full-population vs. scoped ARI, side by side, neither replacing the other:**

| Method | n | ARI (full) | ARI (scoped) | Precision | Recall |
|---|---|---|---|---|---|
| Random baseline | 1,334 | -0.0000 | -0.0001 | 0.1642 | 0.0007 |
| GROUP BY ASN | 290 | 0.0535 | 0.0846 | 0.3145 | 0.0648 |
| GROUP BY resolved IP | 579 | 0.0107 | 0.0238 | 0.9969 | 0.0065 |
| GROUP BY hosting_provider | 277 | 0.0534 | 0.0843 | 0.3140 | 0.0648 |
| Jaccard v1 | 1,331 | 0.0514 | 0.1113 | 0.9280 | 0.0320 |
| **BFS, all clusters** | 1,334 | **0.0904** | **0.1776** | 0.5685 | 0.0692 |

**Reported (confidence≥40) — the completed apples-to-apples comparison,
precision/recall given for both populations (precision is identical
full vs. scoped for every method — see the note below, this is expected,
not a coincidence):**

| Method | n | ARI (full) | ARI (scoped) | Precision | Recall (full) | Recall (scoped) |
|---|---|---|---|---|---|---|
| Random baseline | 1,334 | -0.0000 | -0.0001 | 0.1642 | 0.0007 | 0.0007 |
| GROUP BY ASN | 275 | 0.0535 | 0.0846 | 0.3145 | 0.0648 | 0.1506 |
| GROUP BY resolved IP | 549 | 0.0105 | 0.0233 | 0.9968 | 0.0063 | 0.0147 |
| GROUP BY hosting_provider | 260 | 0.0534 | 0.0843 | 0.3140 | 0.0648 | 0.1507 |
| Jaccard v1 | 1,189 | 0.0409 | 0.0891 | 0.9272 | 0.0254 | 0.0590 |
| BFS, unweighted | 673 | 0.0785 | 0.1540 | 0.5387 | 0.0612 | 0.1422 |
| **BFS, weighted** | 333 | 0.0777 | **0.1525** | 0.5371 | 0.0606 | 0.1409 |

**Why precision is exactly identical between the full and scoped columns
for every method, not approximately — a clean internal-consistency check,
not a coincidence.** An out-of-scope indicator (no enrichment) is never
part of any real infrastructure-derived cluster — every method here
groups on shared infrastructure, so a fingerprint-less indicator always
lands as its own singleton in the predicted partition, contributing zero
pairs (`C(1,2)=0`) to precision's numerator or denominator either way.
Scoping only shrinks recall's denominator (true same-label pairs that
include an out-of-scope member, which could never have been captured by
any method). This is a useful check on the metric implementation, not
just a result.

**Three findings, stated together because they're the complete answer,
not three separate ones:**

1. **The scoped column is uniformly higher than the full column, for
   every method, by roughly 1.8–2.3× on ARI.** Expected and correct — the
   scoped population excludes indicators no method could ever cluster
   correctly (dead-DGA `win.metastealer`, genuine hash-only families), so
   the same clusters agree better with a ground truth that only contains
   in-principle-answerable cases. Neither column should be reported
   alone: full-population is what a deployer actually gets; scoped is the
   method's honest operating domain.

2. **BFS clearly beats every naive baseline on ARI, on every cut of this
   table — but the precision/recall story is not the same shape for every
   baseline, and the two halves must be told apart.** Reported/scoped:
   BFS weighted 0.1525, BFS unweighted 0.1540, next-best Jaccard 0.0891 —
   roughly 1.7×. `GROUP BY resolved_ip` (P=0.9968) and `Jaccard v1`
   (P=0.9272) fit the "near-perfect precision, much lower recall" pattern
   cleanly — recall 0.0147 and 0.0590 (scoped) against BFS's 0.1409–0.1422,
   roughly **9.7× and 2.4× lower**. `GROUP BY ASN`/`hosting_provider` do
   **not** fit that pattern and the framing must not be applied to them:
   their precision (0.3140–0.3145) is *lower* than BFS's (0.5371–0.5387),
   not higher, while their recall (0.1506–0.1507, scoped) is actually
   marginally *higher* than BFS's — they are simply noisier overall (more
   false-positive pairs per true-positive pair), not making a
   precision-for-recall trade the way `resolved_ip`/Jaccard do. BFS beats
   both `GROUP BY` variants on ARI net despite this because ARI weighs the
   precision loss more heavily than the small recall gain buys back.

3. **Weighted vs. unweighted BFS, reported, scoped: 0.1525 vs. 0.1540 —
   still flat, the fourth confirmation, on the most complete and
   correctly-scoped comparison run this session.** No configuration of
   this evaluation — full population, scoped population, unfiltered
   clusters, confidence-filtered clusters, pre- or post-graph-rebuild —
   has shown degree weighting improving ARI over unweighted BFS. This is
   settled; per the instruction this round, not re-tested again without a
   new reason to.

**The positive result, stated as its own contribution, not folded into
the baseline comparison as a footnote.** BFS (the connected-components
formulation) beats both the similarity-threshold approach the prototype
actually ran (Jaccard v1, the "v1 method" item 1.1 found silently
substituted for the paper's own described algorithm) and every naive
`GROUP BY` grouping, on a declared scope, apples-to-apples, by ~1.7× ARI.
This is independent of the weighted-vs-unweighted question — a genuine
methods contribution, not a consolation finding.

**One line worth keeping in the paper: item 1.1's defect — the published
algorithm was never the one actually running — turns out to have been
hiding the better method the whole time.** The paper's originally
*claimed* algorithm (BFS/connected components, §1.1) is the one this
session's evaluation shows actually winning, once wired in and measured
honestly; the silently-substituted Jaccard "v1" path it was swapped for is
the one that underperforms.

**`R(C)` decision: freeze the formula, document the defects as
limitations, do not fix — decided, not deferred.** Rationale: `N(C)`'s
per-run normalization (item 2.2) invalidates cross-run aggregate claims,
but no cross-run aggregate claim survives in the current paper spine, so
this is reportable as a limitation with no cost. `R(C)`'s `/cluster_size`
normalization under-measuring commodity exposure in large clusters is
already a stated, evidenced finding (item 2.2's addendum) — more valuable
as a documented metric defect than as something quietly patched. `D(C)`
near-constant given the input mix (~90% URLs) should be reported with the
actual type distribution, not fixed. `E(C)`'s circularity (scoring
whether the pipeline's own enrichment succeeded, not whether the campaign
is real) should be reported, not fixed. **Fixing any of these changes
confidence scores, which would invalidate the four-times-confirmed
weighted/unweighted comparison and the scope-condition table just
produced — the cost is high and the paper's claim no longer depends on
`R(C)` being good.** Not acted on; recorded as the decision, with reasons,
so it doesn't get silently revisited during the write-up.

**Item 7 is complete.** The §3 results table, the ARI diagnosis, the
ground-truth join fix, the graph-construction fix, and the
scope-condition/apples-to-apples comparison are all done, on a graph and
join verified correct, with `R(C)` explicitly frozen rather than left as
an open question. See §8 for the paper-ready results ledger.

---

## 6h. OTX re-run against corrected data, 2026-07-23 — does not cleanly reproduce ThreatFox, reported honestly

**Every OTX-side number in the record before this section predated the
join fix, the interpreter fix, and the graph rebuild** — flagged
correctly as the last open item before writing. Re-run through the
identical corrected pipeline and scope-condition treatment as §6g
(same BFS/Jaccard/GROUP BY/random clusters — clustering doesn't depend on
which ground truth is being evaluated — confidence-filtered identically,
scope condition computed the same way). **Answer: partially generalizes.
The non-result generalizes cleanly; the positive result does not, and
that's reported here rather than smoothed over.**

**Scope condition, OTX: markedly lower coverage than ThreatFox.** With
outlier: 8,900/17,199 in scope (51.7%, vs ThreatFox's 59.8%). Without
outlier: 4,492/12,705 (35.4%) — noticeably lower, consistent with the
excluded pulse being unusually well-enriched (84.9%, §6 diagnosis) and
its removal disproportionately lowering the remaining population's
coverage.

**Reported (confidence≥40), OTX with outlier (n=17,199):**

| Method | n | ARI (full) | ARI (scoped) | P (full) | R (full) | R (scoped) |
|---|---|---|---|---|---|---|
| Random baseline | 1,334 | 0.0000 | -0.0000 | 0.0734 | 0.0007 | 0.0007 |
| GROUP BY ASN | 275 | 0.0729 | 0.0218 | 0.3122 | 0.0547 | 0.0599 |
| GROUP BY resolved IP | 549 | 0.0025 | 0.0021 | 0.8570 | 0.0014 | 0.0015 |
| GROUP BY hosting_provider | 260 | 0.0741 | 0.0225 | 0.3136 | 0.0556 | 0.0608 |
| Jaccard v1 | 1,189 | 0.0084 | 0.0055 | 0.5057 | 0.0050 | 0.0054 |
| BFS, unweighted | 673 | 0.0849 | **0.0390** | 0.3684 | 0.0604 | 0.0660 |
| BFS, weighted | 333 | 0.0843 | 0.0386 | 0.3679 | 0.0599 | 0.0655 |

**Reported (confidence≥40), OTX without outlier (n=12,705):**

| Method | n | ARI (full) | ARI (scoped) | P (full) | R (full) | R (scoped) |
|---|---|---|---|---|---|---|
| Random baseline | 1,334 | 0.0000 | -0.0001 | 0.0091 | 0.0007 | 0.0007 |
| GROUP BY ASN | 275 | 0.0458 | 0.0623 | 0.0566 | 0.0515 | 0.2050 |
| **GROUP BY resolved IP** | 549 | 0.0333 | **0.1248** | 0.9206 | 0.0171 | 0.0682 |
| GROUP BY hosting_provider | 260 | 0.0461 | 0.0627 | 0.0568 | 0.0520 | 0.2073 |
| **Jaccard v1** | 1,189 | 0.0378 | **0.1223** | 0.2917 | 0.0208 | 0.0831 |
| BFS, unweighted | 673 | 0.0601 | 0.0963 | 0.0819 | 0.0566 | 0.2255 |
| BFS, weighted | 333 | 0.0549 | 0.0874 | 0.0762 | 0.0520 | 0.2071 |

**Finding 1 — the settled non-result generalizes cleanly, on both OTX
variants.** Weighted vs. unweighted BFS: with outlier, 0.0386 vs. 0.0390
(Δ -0.0004, scoped); without outlier, 0.0874 vs. 0.0963 (Δ -0.0089,
scoped) — larger in magnitude than ThreatFox's ~-0.0008 but the *same
direction* every single time, now across two independent datasets and
five total measurement configurations. **Degree weighting never once
beats unweighted BFS on ARI, in any configuration run this session.**
The larger OTX-without-outlier delta is plausibly sampling noise from a
smaller, more fragmented label set (488 pulses vs. 81 ThreatFox
families) rather than a different underlying effect — not decomposed
further, flagged as a magnitude difference worth noting, not a
direction reversal.

**Finding 2 — the scoped-is-always-higher pattern from ThreatFox does
NOT hold for OTX-with-outlier; it inverts.** Every method's scoped ARI is
*lower* than its full-population ARI when the outlier pulse is included
(e.g. BFS unweighted: 0.0849 full → 0.0390 scoped). This is the opposite
direction from every ThreatFox result and from OTX-without-outlier
(where the expected direction returns: BFS unweighted 0.0601 → 0.0963).
Best candidate explanation, not fully decomposed: the 4,497-member
outlier pulse is itself unusually well-enriched (84.9%) and barely
shrinks under scoping, so scoping *increases* its relative share of an
already-skewed, 489-class label population more than it removes noise —
ARI's chance-correction term is sensitive to exactly this kind of
class-size-distribution shift in a way pairwise precision/recall are not
(precision is unaffected by scoping for the same structural reason as
§6g; the ARI-specific sensitivity is new to this larger, more fragmented,
outlier-dominated label set). **Reported as a genuine, checked divergence
from the ThreatFox pattern — the "scoped is the honest operating domain"
framing needs the caveat that this depends on the label population's own
class-size distribution, not just on scoping being applied.**

**Finding 3 — the positive result ("BFS beats every naive baseline") does
NOT universally generalize, and must not be stated as if it does.**
Holds against ThreatFox (§6g) and OTX-with-outlier (0.0390/0.0386 vs.
next-best `group_by_hosting_provider` 0.0225, ~1.7×) — but **breaks
down against OTX-without-outlier: `GROUP BY resolved IP` (0.1248) and
`Jaccard v1` (0.1223) both beat BFS (0.0963/0.0874) on the scoped
comparison.** This is exactly the kind of divergence worth finding before
a reviewer does. Plausible reading: `GROUP BY resolved_ip`'s
near-perfect precision (0.9206) pays off specifically when the label
population is smaller/more fragmented and the outlier's diluting effect
is removed — but this is offered as a candidate explanation, not a
checked one, and should not be stated more strongly in the paper than
"BFS's advantage over naive grouping/similarity baselines held on
ThreatFox and the largest OTX pulse, but not on the OTX population with
that pulse excluded."

**What this means for the paper's spine 4 positive-result claim: scope
it precisely.** State "BFS beats naive baselines on ThreatFox families
and the single largest OTX pulse" rather than "BFS beats naive baselines
on threat intelligence ground truth generally" — the second phrasing is
not supported by this data and a reviewer with access to the same OTX
data could show the counter-example directly. The non-result (spine 3)
carries no such caveat — it is the more robust of the two claims, now
doubly so.

---

## 6i. Final-state re-verification, 2026-07-23 — every remaining number re-run against the current system

Requested directly: every number cited above was computed at some point
during this session's correction cycle, not necessarily against the
*final* state (post-join-fix, post-graph-rebuild, correct venv). This
section re-runs the ones not already re-verified in §6f–§6h, reports old
vs. new side by side, and closes out the pre-write-up verification pass.

### 1. Spine 1 baseline (commodity hub bridging) — methodology error caught and corrected within this same task

First attempt used `InfrastructureEngine.build_weighted_fingerprints()`
(Postgres fingerprints) to recompute per-cluster attribute sharing. That
produced 441/1,334 (33.1%) touching, with Cloudflare bridging only 70
clusters — a ~3× drop from the original that didn't match the expected
scale of change. **Wrong methodology, caught before being reported**: the
original item 2.1 measurement was computed via **direct Neo4j graph
traversal** (bulk Cypher queries against the actual `HOSTED_BY`/
`RESOLVES_TO_ASN` edges), not Postgres fingerprints — a real difference,
not a rounding issue, because a URL indicator's Postgres enrichment
carries its domain's ASN/hosting directly on its own row, while in the
graph those edges sit on the shared `:Domain` node, one `HOSTS` hop away.
Redone via the correct method (`UNWIND` over `(cluster_idx, member)`
pairs, graph traversal, matching the original's "5 bulk queries" approach):

| Metric | Old (1,396 clusters) | New (1,334 clusters) |
|---|---|---|
| Clusters touching a recurring hub value | 953 (68.3%) | 838 (62.8%) |
| `Cloudflare, Inc.` (HostingProvider) bridges | 223 | **223 — exact match** |
| `AS13335` (ASN) bridges | 255 | **255 — exact match** |
| `Hostinger International Limited` bridges | 138 | 130 |
| `AS47583` (Hostinger) bridges | 138 | 130 |
| `Amazon.com, Inc.` bridges | 73 | 47 |
| `AS16509` (Amazon) bridges | 61 | 41 |
| Clusters with ASN shared but not HostingProvider (or vice versa) | 0/1,396 | **0/1,334 — exact match** |

Cloudflare's numbers are bit-for-bit identical — expected, since none of
this session's fixes touched domain-ASN edges (only IP-node edges were
added). The overall touching percentage dropped modestly (68.3%→62.8%,
~8% relative), and Amazon's bridge count dropped by roughly a third
(73→47) — plausibly real cluster restructuring from the graph rebuild's
new IP connectivity merging some previously-separate clusters, not
independently decomposed further. **The core finding survives: still
comfortably majority (62.8%) of clusters touch a recurring commodity hub,
collinearity is still exact (0 violations), Cloudflare's dominance is
completely unchanged.**

### 2. Spine 3 mechanism (monotonic `R(C)` gradient) — reconfirmed, Postgres-fingerprint methodology was already correct here

Unlike task 1, this measurement (`CampaignConfidenceScorer`'s `R(C)`
before/after) was always Postgres-fingerprint-based by design — no
methodology correction needed, re-run directly on the current
1,334-cluster set:

| Band | Old n (of 1,396) | New n (of 1,334) | Old drop | New drop |
|---|---|---|---|---|
| Low exposure (max degree ≤10) | 180 (12.9%) | 219 (16.4%) | 56.4% | 61.9% |
| Medium exposure (10–100) | 235 (16.8%) | 229 (17.2%) | 72.4% | 72.6% |
| High exposure (>100) | 362 (25.9%) | 299 (22.4%) | 77.2% | 80.3% |
| No shared infra | 619 (44.3%) | 587 (44.0%) | 0.0% | 0.0% |

**Gradient is still monotonic (61.9%→72.6%→80.3%), band sizes shifted
modestly with the cluster count, drops are uniformly slightly larger than
before.** Mechanism confirmed stable on the current system.

### 3. The 1,849-member cluster — unchanged

| Metric | Old | New |
|---|---|---|
| Cluster size | 1,849 | **1,849 — unchanged** |
| `AS13335` member coverage | 1,849/1,849 (100.0%) | **1,849/1,849 (100.0%) — unchanged** |
| `AS13335` global degree (domains) | 2,048 | **2,048 — unchanged** |
| Denominator (domains with any ASN edge) | 7,439 | **7,439 — unchanged** |
| Denominator including IPs (new, post-rebuild) | n/a | 8,157 (of which 718 are IPs; **zero IPs resolve through `AS13335` itself**) |

Completely stable — expected, since this cluster and `AS13335`'s
connectivity are entirely domain-based, and the graph rebuild only added
edges for `:IP` nodes, none of which happen to sit on Cloudflare's ASN.

### 4. Determinism — verified live, and now a regression test in the suite

**Live check, real frozen graph, no writes in between:** ran
`CampaignDetector().find_connected_clusters()` twice. Compared cluster
count (1,334 both times), full membership, and list order.
**Exact list equality (`run1 == run2`): True.** Set-of-clusters equality
(membership only, order-independent): also True. The claim holds as
stated — same graph state produces the same partition, count, membership,
and order.

**What "now a test in the suite" actually means, precisely — the claim
splits into two parts and only one is unit-testable:** the full guarantee
depends on Neo4j honoring `ORDER BY node.value` identically across
repeated live queries, which a mocked-driver test cannot verify (a mock
returns whatever it's told, in whatever order, proving nothing about real
Neo4j behavior) — that part is verified by the live check above, once,
manually, not by CI. What *is* now a real regression test
(`test_find_connected_clusters_is_deterministic_given_fixed_input`,
`test_campaign_detector.py`): given the same mocked rows back from the
driver, in the same order, `find_connected_clusters()`'s own Python-side
logic (non-overlapping greedy assignment, visited-set tracking) is a pure
function of that input — two calls against an identical fixture produce
identical output. This guards against a real, plausible regression class
(accidental reliance on dict/set iteration order in the Python layer)
that the live check alone would not catch between sessions. **Both parts
of the claim are now verified — one live and once, one automated in
every CI run — and that split is stated honestly rather than claiming
full coverage from the unit test alone.**

### 5. Population equivalence — the two sides are NOT the same population, and correcting for it widens the gaps, not narrows them

Checked directly: "achievable" recall's population is
`connectivity_components()`'s output over `fp_weighted` (Postgres
enrichment); "actual" recall's population is `find_connected_clusters()`'s
output (Neo4j graph traversal, `d=2, k=3`). **These are measurably
different populations, confirmed by direct count:**

| Population | Count |
|---|---|
| Postgres connectivity (achievable side) | 11,600 |
| Neo4j BFS, all clusters (actual side) | 13,825 |
| Intersection | 11,002 |
| Only in Postgres connectivity | 598 |
| Only in Neo4j BFS clusters | 2,823 |

The 2,823-item gap is the larger and more explicable one: Neo4j's
traversal includes *structural* edges (`HOSTS`, `RESOLVES_TO_IP` — e.g. a
URL and its own domain, or two URL paths on the same domain) that the
Postgres connectivity check does not — it only unions on shared *feature
values* (the four merged classes), never on "these two indicators share
the same underlying domain" structurally. This is exactly the
"same-literal-domain, different URL path" phenomenon item 2.1's original
small-scale baseline already named (56% of small-scale clusters were
this, not shared infrastructure) — it was never fixed or intended to be,
it's a real structural signal BFS legitimately uses that the Postgres-only
connectivity check cannot see.

**Recomputed the five-family table restricted to the intersection only,
as requested. The gaps widen, they do not shrink — the opposite of what
population inflation would predict:**

| Family | Achievable (full) | Actual (full) | Achievable (∩) | Actual (∩) | Gap (full) | Gap (∩) |
|---|---|---|---|---|---|---|
| `unknown` | 0.7822 | 0.0428 | 0.8878 | 0.0589 | 0.7394 | **0.8289** |
| `js.clearfake` | 0.7435 | 0.1405 | **0.9974** | 0.1885 | 0.6030 | **0.8089** |
| `win.cobalt_strike` | 0.6695 | 0.1186 | 0.8319 | 0.1474 | 0.5509 | **0.6845** |
| `win.vidar` | 0.5973 | 0.0224 | 0.9635 | 0.0516 | 0.5749 | **0.9119** |
| `win.adaptix_c2` | 0.4941 | 0.0287 | 0.6768 | 0.0414 | 0.4654 | **0.6354** |

**Why the gap widens, not narrows, once the population is corrected:**
restricting to the intersection drops each family's poorly-connected,
harder-to-cluster members from *both* sides — the members that remain are
disproportionately the ones with strong, well-represented infrastructure
in both Postgres and Neo4j. On this cleaner, better-matched core
population, "achievable" jumps dramatically (`js.clearfake` reaches
0.9974 — essentially every same-family pair among the intersection *is*
connectable via some shared feature), while "actual" (BFS) only rises
modestly. **Spine 4's central finding — the loss is in the traversal, not
the weighting — is strengthened by this correction, not weakened.** The
population mismatch was real, exactly as suspected, but the direction of
its effect on the paper's claim is the opposite of what "inflated gaps"
would mean: the previous, population-mismatched numbers were
*understating* how much achievable cohesion BFS fails to capture.

### 6. `d`/`k` sweep re-run for internal consistency against the corrected ceilings

The §6e/§6f sweep cited "~10–13% of ceiling" against the *uncorrected*
achievable ceilings (§6f's table). Once §6i's intersection correction
changed those ceilings substantially (`js.clearfake` 0.7435→0.9974), that
percentage no longer matched the corrected numbers in the same ledger.
Re-run: same 9 `(d,k)` combinations, same intersection population
(11,002) and labels used throughout this section, recall reported as a
percentage of the *corrected* ceiling.

| Family | Corrected ceiling | Old actual @ d=2,k=3 (% of old ceiling) | New actual @ d=2,k=3 (% of corrected ceiling) | Best across sweep (d=3) |
|---|---|---|---|---|
| `unknown` | 0.8878 | 0.0429 (5.5%) | 0.0609 (6.9%) | 0.1443 (16.2%) |
| `js.clearfake` | 0.9974 | 0.1609 (21.6%) | 0.2158 (21.6%) | 0.2158 (21.6% — flat across `d`, again) |
| `win.cobalt_strike` | 0.8319 | 0.1217 (18.2%) | 0.1512 (18.2%) | 0.1512 (18.2% — flat across `d`, again) |
| `win.vidar` | 0.9635 | 0.0770 (12.9%) | 0.0767 (8.0%) | 0.1770 (18.4%) |
| `win.adaptix_c2` | 0.6768 | 0.0468 (9.5%, vs. old ceiling 0.4941) | 0.0677 (10.0%) | 0.0677 (10.0% — flat across `d`, again) |

**Conclusion holds, does not change direction — if anything it's
restated more precisely now.** Best case across the entire sweep
(`js.clearfake` at any `d`≥2) reaches 21.6% of the corrected achievable
ceiling; every other family peaks lower. `k` is still negligible at
every `d`. The `js.clearfake`/`win.cobalt_strike`/`win.adaptix_c2`
flat-across-`d` pattern (§6e/§6f) reproduces exactly on the corrected
population too — these three are still completely insensitive to
traversal depth, now confirmed under the population-matched comparison.
`unknown`/`win.vidar` still show `d=3` roughly doubling recall, still
capping out well under a fifth of what's achievable. **No parameter
setting in `{1,2,3}×{2,3,5}` closes a material part of the gap for any
of the five families, now stated against the ceiling that actually
belongs in the paper.**

---

## 6j. Second determinism defect found by the re-run-and-diff discipline, 2026-07-23 — evaluation-harness fix applied under the audit's measurement-neutral protocol

**Context: this was found mid-way through applying the code audit's fixes,
specifically while verifying fix A1 (a pure docstring change in
`campaign_detector.py`, expected and confirmed to have zero runtime
effect).** The audit's protocol requires re-running the full measurement
suite and diffing programmatically after every fix, even ones expected to
be no-ops — "it's free and it confirms the harness is deterministic." It
was not: two independent runs of the *exact same* committed code (A1's
docstring edit touches nothing on this code path) produced different
`group_by_resolved_ip` figures. That is the seventh instance of Spine 5's
pattern, and finding it is itself evidence the discipline works — a fix
that was assumed safe surfaced a real, unrelated latent bug purely because
the protocol insisted on re-measuring instead of trusting the "docstring
only" assumption.

**Root cause, confirmed by 5 repeated runs (3 with default hash
randomization producing 3 different values, 2 with `PYTHONHASHSEED=0`
producing identical values):** Python randomizes string hashing per
process by default, which changes `set` iteration order between runs.
`group_by_feature_prefix()` (`baselines.py`) iterates a per-indicator
feature `set` to build a `feat -> [values]` dict; the *order* of the
returned cluster list depends on that iteration order whenever an
indicator has more than one feature under the same prefix (multi-IP
indicators, from item 2.3's fix). `build_predicted_labels()`
(`metrics.py`) resolved multi-cluster membership by unconditional
overwrite — "last cluster in the list wins" — so which predicted cluster
a multi-IP indicator landed in depended on iteration order that varies
run to run.

**A second source of the same defect class was found while investigating
the first, not from the original audit list: `jaccard_v1`
(`InfrastructureEngine.detect_clusters()`) also returns overlapping
clusters — 141 of 8,810 distinct values appear in more than one cluster,
max multiplicity 50 — and was exposed to the identical
`build_predicted_labels()` overwrite-order defect.** It had not visibly
misbehaved before now only because its cluster order came from a Postgres
query with no explicit `ORDER BY`, which happened to return rows in a
stable order across the runs actually performed to date — an accident of
an unchanging table and no concurrent writes, not a guarantee. Confirmed
by the multi-membership audit before any fix was applied:

| method | clusters | distinct values | values in >1 cluster | max multiplicity |
|---|---|---|---|---|
| `bfs_all_clusters` | 1,334 | 13,825 | 0 | 0 |
| `jaccard_v1` | 1,331 | 8,810 | 141 | 50 |
| `group_by_asn` | 290 | 8,534 | 0 | 0 |
| `group_by_hosting_provider` | 277 | 8,577 | 0 | 0 |
| `group_by_resolved_ip` | 579 | 2,556 | 838 | 10 |
| `random_baseline` | 1,334 | 22,637 | 0 | 0 |

**Two fixes applied, treated as separate causes rather than one patch
masking the other, per explicit instruction:**

1. **`build_predicted_labels()` (`metrics.py`)** now sorts `clusters` into
   a canonical order (by each cluster's own sorted membership) before
   assigning ids, and the first cluster in that order to claim a
   multiply-assigned value keeps it. The predicted partition is now a
   pure function of cluster *content*, independent of whatever order the
   caller happened to build the clusters list in. This is the semantic
   fix — it would still be correct even if Python's hashing were made
   deterministic by some other means.
2. **`app/core/hash_safety.py`: `ensure_deterministic_hashing()`**, wired
   into `run_evaluation.py`'s `__main__` block, re-execs the process with
   `PYTHONHASHSEED=0` if not already set. Defence in depth against any
   other code path — present or future — that implicitly depends on
   `set`/`dict` iteration order, following the same "raise/guard loudly
   at entrypoint start" pattern already established by
   `ensure_correct_interpreter()` (§6a) and
   `ensure_distinct_databases()`/`ensure_distinct_redis_targets()`.

**Verification, per the audit's protocol — 3 runs post-fix, diffed
pairwise and against the pre-fix baseline snapshot
(`evaluation_runs/baseline_20260723T165406Z/`, committed before any fix
was applied):**

- **3/3 post-fix runs are bit-identical** across every file, including
  `feature_degrees.json` (whose key order was itself non-deterministic
  pre-fix, purely a serialization artefact of the same hash-randomization
  root cause — now also fixed).
- **BFS: zero movement, confirmed rather than assumed.** All BFS rows
  (weighted/unweighted, all-clusters/reported, every ground truth)
  bit-identical to the pre-fix baseline — expected, since BFS clusters
  are non-overlapping by construction, and now verified directly rather
  than inferred.
- **`group_by_resolved_ip`: moves, magnitude negligible everywhere**
  (5th significant digit or beyond on every cell, every ground truth) —
  the pre-authorized case; the old value was never anything but
  incidental.
- **`jaccard_v1`: moves, negligible on ThreatFox and OTX-without-outlier
  (matches every cited 4-decimal value), but material on
  OTX-with-outlier** — the smallest scoped population of the three, so
  the same handful of reassigned multi-IP indicators move it
  proportionally further:

  | metric | old (cited, §6h) | new | relative |
  |---|---|---|---|
  | ARI (full) | 0.0084 | 0.0108 | +29% |
  | P (full) | 0.5057 | 0.5597 | +11% |
  | R (full) | 0.0050 | 0.0063 | +26% |
  | ARI (scoped) | 0.0055 | 0.0076 | +37% |
  | R (scoped) | 0.0054 | 0.0069 | +26% |

  **The §6h table at that row (OTX-with-outlier, `jaccard_v1`) is now
  stale and should be read as: ARI (full) 0.0108, ARI (scoped) 0.0076, P
  (full) 0.5597, R (full) 0.0063, R (scoped) 0.0069 — n unchanged at
  1,189. Old values left in place there, not edited, per this project's
  standing convention of leaving a superseded number visible alongside
  its correction rather than silently rewriting it.**

**Every §8 claim that cites these baselines was re-checked against the
new numbers before writing this entry, not assumed safe:**

- ThreatFox, BFS vs. next-best (`jaccard_v1`): 1.712×/1.729× (old) →
  **1.710×/1.727×** (new). Holds.
- OTX-with-outlier, BFS vs. next-best (`group_by_hosting_provider`):
  1.713×/1.730× → **1.713×/1.730×**, exactly unchanged — that comparator
  has zero multi-membership and was never exposed to this defect.
- OTX-without-outlier, "`jaccard_v1` (0.1223) and `group_by_resolved_ip`
  (0.1248) both beat BFS (0.0874–0.0963)": new values 0.1225 and 0.1248
  respectively, margin over BFS-weighted widens by 0.0002 and 0.0001.
  **The "2 of 3 confirm, 1 contradicts" framing is unchanged and does not
  need restating** — checked explicitly rather than assumed, since this
  is the one ground-truth configuration where the paper's own headline
  claim doesn't hold and any tightening or loosening of that margin
  needed to be seen before going in the ledger.

**No number in the §8 ledger's prose claims moved. The only stale
artefact is the raw §6h OTX-with-outlier table cell for `jaccard_v1`,
corrected above.** This is the seventh instance of Spine 5's pattern
(§7's rule bullet and the Spine 5 list below should be updated to "7
instances" / "seven times") — a command (a "verify anyway, it's free"
docstring re-run) that surfaced a real defect precisely because it wasn't
skipped as obviously safe.

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
- **Verify the interpreter before trusting any measurement.** An entire
  session (2026-07-23, see §6a) ran against system Python instead of the
  project's `.venv` because activation failed silently (`2>/dev/null`
  masking a missing path). `app/core/venv_safety.py::ensure_correct_interpreter()`
  now fails loudly at test-session start and at every worker's entrypoint —
  but that only covers pytest and the workers. Ad hoc scripts and shell
  one-liners run outside those entrypoints are not covered automatically;
  confirm `which python` / `sys.prefix` points at the repo's `.venv`
  before trusting output from either.
- **A silently-degenerate check reads exactly like a legitimate negative
  result — check for this pattern specifically, it recurred seven times in
  one work session.** Item 2.7 (rate-limited ASN API returning empty-body
  200/429, indistinguishable from "genuinely no ASN" until logging was
  added); the venv defect (§6a: wrong interpreter ran silently instead of
  failing, because `2>/dev/null` masked the activation error); the
  ground-truth join-key bug (§6b: 18.6% of labels silently absent from
  every join, read as "cohesion is low" rather than "the join is broken");
  a Cypher query bug found investigating item 2.9 (§6e: a non-optional
  `MATCH` that finds nothing still returns one aggregation row reading
  `count=0`, indistinguishable from "node exists with zero edges" without
  an explicit `OPTIONAL MATCH ... IS NOT NULL` check); the Spine 1
  re-verification's Postgres-vs-Neo4j methodology mismatch (§6i, a
  spurious ~3× discrepancy caught before being reported); and `git add
  analysis/` silently dropping 17 `.log` files matched by `*.log` in
  `.gitignore` while exiting 0 and printing nothing wrong (§8's Spine 5,
  caught only by diffing the committed tree against the filesystem
  afterward). In every case the command ran to completion, returned or
  did a plausible-looking amount, and was believed until something else
  forced a second look. When a measurement
  comes back as a clean zero, a suspiciously round number, or a result
  that would be very convenient, check whether the *absence* of a value is
  actually distinguishable in that code path from a *genuine* value of
  zero/none/empty before reporting it.

---

## 8. Results ledger — paper-ready findings, skeleton for the results section

Read this before writing the results section, and update it if any number
below is ever re-run. Purpose: prevent anything already retracted this
session from creeping back into the write-up, and give every number a
confirmation count so its evidentiary weight is visible at a glance.

**Every number in this ledger is now current as of the final system state**
(post-join-fix, post-graph-rebuild, correct venv, §6i) — the "not
re-verified against final state" caveats that existed in the previous
version of this ledger are resolved below, one way or the other, not left
open.

### Spine 1 — commodity infrastructure is over-weighted (quantified)

- **838/1,334 clusters (62.8%) touch a `HostingProvider`/`ASN` value
  recurring across other, otherwise-disjoint clusters; `Cloudflare, Inc.`
  alone bridges 223 clusters; `AS13335` bridges 255; `ASN`/`HostingProvider`
  remain empirically collinear (0 clusters with one but not the other,
  N=1,334).** Item 2.1 → **re-verified final state, §6i.** **2
  measurements**: original (953/1,396, 68.3%) and final-state (838/1,334,
  62.8%) — modest reduction (~8% relative), Cloudflare's own bridge count
  is bit-for-bit identical (223, 255) both times, collinearity exact both
  times. A first re-verification attempt used the wrong methodology
  (Postgres fingerprints instead of Neo4j graph traversal), produced a
  spurious ~3× drop, and was caught and corrected within the same task
  (§6i) before being reported — recorded as a 5th instance of the
  silently-degenerate-check pattern (Spine 5).
- **The 1,849-member cluster is bridged end-to-end by one node**
  (`AS13335`, 100% member coverage, global degree 2,048/7,439 domains with
  ASN data — 27.5%). Item 2.1 → **re-verified final state, §6i, exact
  match on every figure**: cluster size (1,849), `AS13335` coverage
  (100.0%), `AS13335` global degree (2,048), and the domain-only
  denominator (7,439) are all bit-for-bit unchanged. New this round: the
  denominator including IPs is 8,157 (718 of them IP nodes, per item 2.9's
  fix), but zero of those IPs sit on `AS13335` itself, so the figure
  above is unaffected either way. **2 measurements, exact agreement.**

### Spine 2 — type-level exposure checks undercount commodity contamination

- **Type-level "does this cluster share another attribute" checks
  misclassify genuinely commodity-driven clusters as having real evidence**
  — demonstrated concretely: Cloudflare's own nameserver pool
  (`harlee.ns.cloudflare.com`, `tosana.ns.cloudflare.com`) bridges ~160
  members of the 1,849-cluster each and would be counted as "additional
  real evidence" by a type-level check, despite being exactly as commodity
  as the ASN it accompanies. Item 6, **1 measurement**, mechanism-level
  finding (not a comparative statistic subject to re-confirmation in the
  same way); the 1,849-cluster's own stability (above) means this specific
  illustration is unaffected by the final-state re-run even though it
  wasn't independently re-checked this round.

### Spine 3 — degree weighting suppresses commodity contribution mechanically, no accuracy gain (settled non-result)

- **Monotonic `R(C)` drop by measured commodity-exposure band: low 61.9%,
  medium 72.6%, high 80.3% (final state).** Item 6 → **re-verified final
  state, §6i.** **2 measurements**: original (56.4%/72.4%/77.2%, n=180/235/362
  of 1,396) and final-state (61.9%/72.6%/80.3%, n=219/229/299 of 1,334) —
  gradient still monotonic, band sizes shifted modestly with the cluster
  count, drops uniformly slightly larger. Circularity caveat still applies
  (degree used to both bucket and score) — the external check below is
  what actually validates the method, not this gradient.
- **Weighted vs. unweighted BFS ARI on ThreatFox: flat, no improvement.
  Final number: 0.1525 vs. 0.1540 (reported, scoped) — Δ -0.0008.**
  **6 independent confirmations**, each on progressively more correct
  data: (1) original run, Δ -0.0004 (0.0716 vs 0.0712); (2) post-join-fix,
  §6c, Δ -0.0007 (0.0777 vs 0.0770); (3) post-graph-rebuild, §6f, Δ -0.0008
  (0.0785 vs 0.0777); (4) scoped/apples-to-apples with every baseline
  confidence-filtered identically, §6g, Δ -0.0008 (0.1540 vs 0.1525,
  scoped); (5) OTX with outlier, §6h, Δ -0.0004 (0.0390 vs 0.0386,
  scoped); (6) OTX without outlier, §6h, Δ -0.0089 (0.0963 vs 0.0874,
  scoped) — same direction, larger magnitude, plausibly sampling noise
  from a smaller/more-fragmented label set, not decomposed further.
  **Same direction in every single configuration across two independent
  ground-truth datasets, on the final system state. This is the most
  robustly re-confirmed number in the entire session. Report as settled;
  do not re-test without a new, specific reason.**
- **Determinism: verified live (two independent runs against the frozen
  final-state graph, exact list equality — count, membership, and order,
  §6i) and now partially covered by an automated regression test**
  (`test_find_connected_clusters_is_deterministic_given_fixed_input`).
  The Python-side algorithm's determinism (no dict/set-iteration
  dependence) is in the suite; Neo4j's own `ORDER BY` reliability across
  repeated live queries — the other half of the claim — is verified live,
  once, not by CI, and that split is stated explicitly rather than
  overclaiming full automated coverage.

### Spine 4 — the loss is in the traversal, not the weighting

- **Achievable-vs-actual pairwise recall gap, checked across 5 families,
  population-matched via explicit intersection (§6i) rather than assumed
  equivalent. Final numbers, population-corrected — supersedes the
  §6f table, which used two measurably different populations:**

  | Family | Achievable (∩) | Actual (∩) | Gap (∩) | Gap (§6f, uncorrected) |
  |---|---|---|---|---|
  | `unknown` | 0.8878 | 0.0589 | **0.8289** | 0.7394 |
  | `js.clearfake` | **0.9974** | 0.1885 | **0.8089** | 0.6030 |
  | `win.cobalt_strike` | 0.8319 | 0.1474 | **0.6845** | 0.5509 |
  | `win.vidar` | 0.9635 | 0.0516 | **0.9119** | 0.5749 |
  | `win.adaptix_c2` | 0.6768 | 0.0414 | **0.6354** | 0.4654 |

  **Population check, §6i: the achievable side (Postgres connectivity,
  11,600 indicators) and the actual side (Neo4j BFS, 13,825 indicators)
  are measurably different populations (intersection 11,002; 598 only in
  Postgres, 2,823 only in Neo4j) — real, not assumed.** Correcting for it
  **widens every gap, it does not narrow any of them** — the opposite of
  what population inflation would predict. Root cause: Neo4j's traversal
  includes structural edges (same domain via different URL paths) that
  the Postgres-fingerprint connectivity check cannot see, so the
  uncorrected "achievable" side was diluted by a lot of poorly-connected
  members that the properly-matched core population excludes.
  `js.clearfake`'s achievable ceiling on the matched population is
  effectively saturated (0.9974). **Spine 4's central claim — the loss is
  in the traversal, not the weighting — is strengthened by this
  correction, not weakened; report the population-corrected numbers as
  the final, defensible version and note that the earlier, uncorrected
  numbers understated the gap.**
- **`d`/`k` traversal sweep: no parameter setting in {1,2,3}×{2,3,5}
  materially closes the gap for any of the five families — swept 3 times
  now, most recently against the population-corrected ceilings (§6i.6),
  and the percentages are updated here to match that final table rather
  than the superseded ones.** `k` negligible throughout, every sweep.
  Best case anywhere in the sweep is `js.clearfake` at 21.6% of its
  corrected ceiling (0.9974) — completely flat across `d=2` and `d=3`,
  the third time this exact insensitivity-to-depth pattern has reproduced
  for this family. `win.cobalt_strike` (peaks at 18.2%) and
  `win.adaptix_c2` (peaks at 10.0%) show the same flat-across-`d` pattern.
  `unknown`/`win.vidar` still show `d=3` roughly doubling recall over
  `d=2` (6.9%→16.2%; 8.0%→18.4%), the only families sensitive to depth at
  all, and still capping out under a fifth of what's achievable. **No
  parameter setting closes a material part of the gap for any family, now
  stated against the ceiling that belongs in the final paper table — the
  conclusion does not change direction, and three of five families are
  now confirmed depth-insensitive across three independent sweeps.**
- **BFS beats every naive baseline on ThreatFox and OTX-with-outlier,
  apples-to-apples: 0.1525–0.1540 vs. next-best (Jaccard v1) 0.0891 on
  ThreatFox (~1.7×); 0.0386–0.0390 vs. next-best (`group_by_hosting_provider`)
  0.0225 on OTX-with-outlier (~1.7×) — but this does NOT hold on
  OTX-without-outlier, where `GROUP BY resolved_ip` (0.1248) and
  `Jaccard v1` (0.1223) both beat BFS (0.0874–0.0963), §6h.** **2 of 3
  ground-truth configurations confirm; 1 contradicts.** Must be stated in
  the paper as scoped to ThreatFox and the dominant OTX pulse, not as a
  general claim about threat-intelligence ground truth — a reviewer with
  the same OTX data could produce the counter-example directly if
  overclaimed. Positive result, independent of the weighting question —
  see the "one line worth keeping" note in §6g on item 1.1's irony (still
  valid: BFS is the paper's originally-claimed algorithm, and it does win
  on 2 of 3 ground truths tested, just not unconditionally).

### Spine 5 — methodological findings (report as part of the paper's contribution, not just as caveats)

- **7 instances of "confident wrong number from a silently-degenerate
  check"** in one session: item 2.7 (rate-limited API, empty-body
  200/429 indistinguishable from "no ASN"), the venv defect (§6a),
  the ground-truth join-key bug (§6b, 18.6% of labels silently dropped),
  the Cypher aggregation bug (§6e, non-optional `MATCH` on nothing still
  returns one `count=0` row), the Spine 1 re-verification's own
  Postgres-vs-Neo4j methodology mismatch (§6i, caught within the same
  task before being reported, produced a spurious ~3× discrepancy),
  `git add analysis/` (2026-07-23, post-§8) silently dropping all 17
  `.log` files matched by the repo's own `*.log` gitignore rule —
  the command printed nothing wrong and exited 0, and the omission was
  only caught by diffing the committed tree against the filesystem
  afterward — and `build_predicted_labels()`'s overwrite-order dependency
  on Python's per-process hash randomization (§6j, 2026-07-23), found
  only because a fix expected to be a complete no-op was re-measured
  anyway and two runs of identical code disagreed. Same pattern as the
  other six: a command that succeeded while doing less than it appeared
  to. Each is a **fix or a caught-and-corrected measurement, verified
  once**, not a comparative statistic — done, not pending
  re-confirmation.
- **Discipline point, now with a seventh instance to cite:** every one of
  the above was caught by re-running a result under changed conditions,
  cross-checking against an independent method, reproducing a prior
  number exactly and noticing when it didn't reproduce, or diffing an
  action's claimed effect against its actual effect — never by
  inspection alone. The practice of re-running rather than assuming is
  itself part of what this session demonstrates, worth a line in the
  paper's methodology section, and the Spine 1 catch (§6i) is the
  clearest self-contained illustration: a wrong number was produced,
  caught by its implausible magnitude, and corrected in the same task
  before ever reaching this ledger.

### Explicitly not paper-ready / decided not to pursue further

- `R(C)`'s formula defects (§2.2: `N(C)` per-run normalization, `R(C)`
  `/cluster_size` under-measurement, `D(C)` near-constant, `E(C)`
  circular) — **frozen, reported as limitations, not fixed** (§6g
  decision). Fixing would invalidate the 6-confirmation weighted/
  unweighted result above.
- Item 2.4 (hash enrichment) — demoted (§6b/§6c): hashes are 6.4% of the
  ThreatFox-labelled set, not the ~37% originally claimed; not a driver of
  evaluation validity. Not planned.
- Item 2.9 (`GraphBuilder` never wiring IP-node infrastructure edges) —
  **fixed and verified (§6f/§6i)**, not yet promoted to a numbered TIER 2
  entry in §4 proper; do that the next time this document is reorganized.
