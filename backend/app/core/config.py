from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Aletheia"
    environment: str = "development"

    # PostgreSQL
    postgres_dsn: str = "postgresql://aletheia:aletheia@localhost:5432/aletheia"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    # Redis
    redis_url: str = "redis://localhost:6379"

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

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
