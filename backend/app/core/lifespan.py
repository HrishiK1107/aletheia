from contextlib import asynccontextmanager

from app.core.logging import get_logger
from app.db.base import Base
from app.db.neo4j import driver
from app.db.postgres import engine
from app.db.redis import redis_client
from fastapi import FastAPI

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Aletheia backend services")

    Base.metadata.create_all(bind=engine)

    # Startup checks
    try:
        engine.connect().close()
        logger.info("PostgreSQL engine initialized")
    except Exception:
        logger.warning("PostgreSQL not available")

    try:
        redis_client.ping()
        logger.info("Redis client initialized")
    except Exception:
        logger.warning("Redis not available")

    try:
        with driver.session() as session:
            session.run("RETURN 1")
        logger.info("Neo4j driver initialized")
    except Exception:
        logger.warning("Neo4j not available")

    yield

    logger.info("Shutting down Aletheia backend")

    try:
        driver.close()
    except Exception:
        pass
