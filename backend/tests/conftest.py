import pytest
from app.db.postgres import Base, engine

# IMPORTANT: load models so SQLAlchemy metadata registers tables
from app.ingestion.enrichment.models.indicator_models import Indicator  # noqa
from sqlalchemy.orm import sessionmaker

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def pytest_sessionstart(session):
    """
    Ensure all tables exist before tests run.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """
    Creates a fresh database session for each test.
    """

    db = TestingSessionLocal()

    try:
        yield db
    finally:
        db.close()
