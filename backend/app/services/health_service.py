from app.db.neo4j import check_neo4j
from app.db.postgres import engine
from app.db.redis import check_redis
from sqlalchemy import text


def check_postgres():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def system_health():
    return {
        "postgres": "ok" if check_postgres() else "unavailable",
        "redis": "ok" if check_redis() else "unavailable",
        "neo4j": "ok" if check_neo4j() else "unavailable",
    }
