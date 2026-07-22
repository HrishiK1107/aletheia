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

**Related, unfixed finding: the same class of risk exists for Redis.**
`test_ingestion_pipeline.py` calls `process_indicator_queue()`, which drains
`indicator_queue.py`'s real Redis queue (`settings.redis_url`, the same
instance the live pipeline uses) via a `while True: dequeue... until empty`
loop — there is no test-specific Redis database or key prefix. Any test that
exercises the ingestion worker will consume whatever is genuinely queued at
that moment (this is what happened to the 23,447 indicators above). Postgres
now has an isolation guard; Redis does not. Worth the same treatment (a
`test_redis_url`/separate logical DB index) before an evaluation run's queued
backlog meets the same fate — not fixed here, flagging for a scoping
decision rather than doing it unrequested.

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
