from app.core.logging import get_logger, setup_logging
from app.db.postgres import engine
from app.db.redis import check_redis
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

setup_logging()

logger = get_logger(__name__)

app = FastAPI(title="Aletheia")


@app.get("/health")
def health():
    logger.info("Health check requested")
    return {"status": "ok"}


@app.get("/db/status")
def db_status():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"database": "ok"}
    except SQLAlchemyError:
        return {"database": "unavailable"}


@app.get("/redis/status")
def redis_status():
    if check_redis():
        return {"redis": "ok"}
    return {"redis": "unavailable"}
