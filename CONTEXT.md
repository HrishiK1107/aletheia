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

**Next: re-run enrichment, rebuild the graph, then redo the full-volume
cluster-attribution re-measurement** — not done yet as of this entry.

**Honest enrichment coverage baseline, full volume (22,642 indicators),
replacing the paper draft's unmeasured "~80% ECR" claim
(`Documentation/Aletheia_Paper_Revised.md`, cited 5 times with a fabricated
60/25/15% failure breakdown that does not correspond to any real run):**

| Attribute | Coverage | Note |
|---|---|---|
| Resolved IP (DNS A record) | 36.8% (8,340/22,642) | |
| Nameservers (DNS NS record) | 31.3% (7,088/22,642) | |
| Registrar (WHOIS) | 42.0% (9,508/22,642) | highest of the four |
| ASN | 5.6% (1,267/22,642), 14.8% of indicators with a resolved IP | **broken, see item 2.7** — not a real coverage number, re-measure after the GeoLite2 fix |
| ≥1 attribute resolved (paper's own ECR definition) | 48.8% (11,038/22,642) | vs. the paper's claimed ~80% |

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
