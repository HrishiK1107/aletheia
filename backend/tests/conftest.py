import pytest
from app.db.base import Base
from app.db.postgres import engine
from app.ingestion.enrichment.models.feed_models import Feed  # noqa

# Import models so SQLAlchemy registers them
from app.ingestion.enrichment.models.indicator_models import Indicator  # noqa
from sqlalchemy.orm import sessionmaker

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """
    Create tables once before the test session begins.
    Ensures CI environments have the schema.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield

    Base.metadata.drop_all(bind=engine)


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
