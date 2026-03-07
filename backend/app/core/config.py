from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Aletheia"
    environment: str = "development"

    postgres_dsn: str = "postgresql://user:password@localhost:5432/aletheia"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    redis_url: str = "redis://localhost:6379"

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
