import pytest
from app.core.config import settings
from app.core.db_safety import ensure_distinct_databases, ensure_distinct_redis_targets
from app.db import model_registry  # noqa: F401 -- registers all models on Base.metadata
from app.db.base import Base
from app.db.redis import redis_client
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Guard rail: setup_database (below) drops and recreates every table in
# test_database_url on every test session. Fail at collection time, before
# any fixture or test runs, if that ever resolves to the dev database.
ensure_distinct_databases(settings.test_database_url, settings.postgres_dsn)

# Same guard for Redis: process_indicator_queue() drains the queue until
# empty, so pointing tests at the dev Redis database would destroy
# whatever is genuinely queued there.
ensure_distinct_redis_targets(settings.test_redis_url, settings.redis_url)

test_engine = create_engine(
    settings.test_database_url,
    pool_pre_ping=True,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
)

# redis_client is a single shared singleton imported by reference everywhere
# (indicator_queue.py, etc.) rather than a factory like SessionLocal, so
# redirecting its connection_pool here -- once, at collection time -- is
# enough to isolate every module that already imported it, with no need to
# monkeypatch each import site individually.
redis_client.connection_pool = Redis.from_url(
    settings.test_redis_url, decode_responses=True
).connection_pool


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """
    Create tables once before the test session begins, against the
    dedicated test database (never the dev database -- see the guard rail
    above).
    """
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    yield

    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_redis():
    """
    Start each test session with a clean test Redis database (never the
    dev database -- see the guard rail above).
    """
    redis_client.flushdb()

    yield

    redis_client.flushdb()


@pytest.fixture(scope="function")
def db_session():
    """
    Creates a fresh database session for each test, against the test
    database.
    """
    db = TestingSessionLocal()

    try:
        yield db
    finally:
        db.close()
