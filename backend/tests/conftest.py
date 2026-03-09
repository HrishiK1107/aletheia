import pytest
from app.db.postgres import Base, engine
from sqlalchemy.orm import sessionmaker

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def pytest_sessionstart(session):
    """
    Ensure database tables exist before tests run.
    """
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
