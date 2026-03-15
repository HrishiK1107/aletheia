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

    # Create database tables
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("PostgreSQL tables initialized")
    except Exception as e:
        logger.warning(f"PostgreSQL table initialization failed: {e}")

    # PostgreSQL connection check
    try:
        engine.connect().close()
        logger.info("PostgreSQL engine initialized")
    except Exception as e:
        logger.warning(f"PostgreSQL connection failed: {e}")

    # Redis check
    try:
        redis_client.ping()
        logger.info("Redis client initialized")
    except Exception as e:
        logger.warning(f"Redis not available: {e}")

    # Neo4j check
    try:
        with driver.session() as session:
            session.run("RETURN 1")
        logger.info("Neo4j driver initialized")
    except Exception as e:
        logger.warning(f"Neo4j not available: {e}")

    yield

    logger.info("Shutting down Aletheia backend")

    try:
        driver.close()
    except Exception:
        pass
