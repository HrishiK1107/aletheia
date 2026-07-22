from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Aletheia"
    environment: str = "development"

    # PostgreSQL
    postgres_dsn: str = "postgresql://aletheia:aletheia@localhost:5432/aletheia"

    # Test database. Must be a distinct database from postgres_dsn --
    # conftest.py drops/recreates every table in this DSN on every test
    # session, so pointing it at the dev DSN destroys real run data (this
    # happened once, 2026-07-23). See tests/conftest.py's guard rail.
    test_database_url: str = "postgresql://aletheia:aletheia@localhost:5432/aletheia_test"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Test Redis target. Must be a distinct logical database from redis_url
    # -- tests that exercise the ingestion queue drain it until empty, so
    # pointing this at the dev database destroys whatever is genuinely
    # queued (same reasoning as test_database_url above). Redis supports 16
    # logical databases per server (0-15); index 1 keeps this on the same
    # container without needing a second Redis instance. See
    # tests/conftest.py's guard rail.
    test_redis_url: str = "redis://localhost:6379/1"

    # Threat intelligence feeds
    otx_api_key: str | None = None
    abusech_api_key: str | None = None

    # ThreatFox lookback window in days. Verified live against the API
    # 2026-07-22: it rejects anything outside 1-7 ("illegal_days"), despite
    # CONTEXT.md documenting a max of 90 — 7 is the true ceiling.
    threatfox_lookback_days: int = 7

    # OTX /pulses/subscribed pagination. The API caps results per page at 50
    # regardless of the requested limit (verified live 2026-07-22). The
    # subscribed count was 8,821 pulses (~220k indicators) at verification
    # time, far more than one collection run should pull, so max_pages
    # bounds each run; raise it for a larger accumulation pass.
    otx_pulse_page_size: int = 50
    otx_max_pages: int = 10

    # Enrichment worker thread pool size. CONTEXT.md item 2.6: serial
    # enrichment was ~1-3s/indicator (10-25 hours at 30k indicators);
    # enrichment lookups are I/O-bound (DNS/WHOIS/HTTP), so a thread pool
    # -- not multiprocessing -- is the right tool. 30 is the middle of the
    # 20-50 range CONTEXT.md suggested.
    enrichment_worker_threads: int = 30

    # GeoLite2 ASN database (offline, frozen snapshot -- CONTEXT.md item
    # 2.7). Path is relative to the repository root regardless of process
    # cwd (see asn_lookup.py). Not committed to git (data/*.mmdb) -- must
    # be downloaded and placed here manually; there is no network fallback
    # if it's missing, by design (item 2.7: the previous network-based
    # lookup collapsed under item 2.6's concurrency).
    geolite2_asn_db_path: str = "data/GeoLite2-ASN.mmdb"

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
