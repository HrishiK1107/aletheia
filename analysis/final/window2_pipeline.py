"""
CONTEXT.md §6p (Task 2, second collection window): drives collection ->
ingestion -> enrichment -> graph build against window-2's separate
infrastructure. Must be run with POSTGRES_DSN / NEO4J_URI / NEO4J_USER /
NEO4J_PASSWORD / REDIS_URL environment variables already pointed at
window-2's database/instance BEFORE this process starts (settings are
read once, at import time) -- see the invocation in CONTEXT.md's window-2
write-up for the exact env vars used.

Same functions §6m already documents as the pipeline's script of record
(run_collectors, process_indicator_queue, run_enrichment_batch,
run_graph_build) -- nothing new, no parameters changed, just driven
end-to-end in one script instead of four separate long-lived worker
processes, since this is a one-shot batch collection, not a standing
service.
"""

import sys
import time

sys.path.insert(0, ".")

from app.core.config import settings  # noqa: E402


def main():
    print(f"postgres_dsn = {settings.postgres_dsn}")
    print(f"neo4j_uri = {settings.neo4j_uri}")
    print(f"redis_url = {settings.redis_url}")
    assert "window2" in settings.postgres_dsn, "REFUSING: postgres_dsn does not look like window2"
    assert ":7688" in settings.neo4j_uri, "REFUSING: neo4j_uri does not look like window2"
    assert settings.redis_url.endswith("/2"), "REFUSING: redis_url does not look like window2 (db 2)"

    from app.ingestion.collectors.collector_runner import run_collectors
    from app.workers.ingestion_worker import process_indicator_queue
    from app.workers.enrichment_worker import run_enrichment_batch
    from app.workers.graph_worker import run_graph_build

    t0 = time.time()
    print("\n=== Step 1: run_collectors() ===", flush=True)
    indicators = run_collectors()
    print(f"Collected {len(indicators)} indicators in {time.time()-t0:.1f}s", flush=True)

    t1 = time.time()
    print("\n=== Step 2: process_indicator_queue() ===", flush=True)
    process_indicator_queue()
    print(f"Ingestion drained in {time.time()-t1:.1f}s", flush=True)

    t2 = time.time()
    print("\n=== Step 3: run_enrichment_batch() ===", flush=True)
    run_enrichment_batch()
    print(f"Enrichment done in {time.time()-t2:.1f}s", flush=True)

    t3 = time.time()
    print("\n=== Step 4: run_graph_build() ===", flush=True)
    run_graph_build()
    print(f"Graph build done in {time.time()-t3:.1f}s", flush=True)

    print(f"\nTotal pipeline time: {time.time()-t0:.1f}s", flush=True)


if __name__ == "__main__":
    from app.core.venv_safety import ensure_correct_interpreter

    ensure_correct_interpreter()
    main()
