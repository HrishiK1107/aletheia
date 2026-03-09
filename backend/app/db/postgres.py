from app.core.config import settings
from app.db.base import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import models so SQLAlchemy registers them

engine = create_engine(
    settings.postgres_dsn,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


Base.metadata.create_all(bind=engine)
