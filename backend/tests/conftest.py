import pytest
from app.core.config import settings
from app.core.db_safety import ensure_distinct_databases
from app.db import model_registry  # noqa: F401 -- registers all models on Base.metadata
from app.db.base import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Guard rail: setup_database (below) drops and recreates every table in
# test_database_url on every test session. Fail at collection time, before
# any fixture or test runs, if that ever resolves to the dev database.
ensure_distinct_databases(settings.test_database_url, settings.postgres_dsn)

test_engine = create_engine(
    settings.test_database_url,
    pool_pre_ping=True,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
)


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
