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

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
