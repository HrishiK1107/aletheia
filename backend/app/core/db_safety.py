from redis.connection import parse_url as parse_redis_url
from sqlalchemy.engine import make_url


def _db_identity(dsn: str) -> tuple:
    """
    (host, port, database name) a DSN actually points at, independent of
    driver string or credentials -- two DSNs with different users/passwords
    can still be the same database.
    """
    url = make_url(dsn)
    return (url.host, url.port or 5432, url.database)


def ensure_distinct_databases(test_dsn: str, dev_dsn: str) -> None:
    """
    Raise loudly if test_dsn and dev_dsn resolve to the same database.

    Test fixtures that drop/recreate every table on each session must never
    run against the dev database -- this happened once (2026-07-23) and
    destroyed real collection/detection run data. Call this at import time
    in conftest.py, before any fixture or test runs.
    """
    if _db_identity(test_dsn) == _db_identity(dev_dsn):
        raise RuntimeError(
            "Refusing to run tests: test_database_url and postgres_dsn resolve "
            f"to the same database ({test_dsn!r} vs {dev_dsn!r}). The test "
            "suite drops and recreates every table in test_database_url each "
            "session -- pointing it at the dev database destroys real data. "
            "Set test_database_url (or the TEST_DATABASE_URL env var) to a "
            "separate database, e.g. postgresql://.../aletheia_test."
        )


def _redis_identity(url: str) -> tuple:
    """(host, port, logical db index) a Redis URL actually points at."""
    parsed = parse_redis_url(url)
    return (parsed.get("host"), parsed.get("port", 6379), parsed.get("db", 0))


def ensure_distinct_redis_targets(test_url: str, dev_url: str) -> None:
    """
    Raise loudly if test_redis_url and redis_url resolve to the same Redis
    target (host, port, and logical database index).

    Tests that exercise the ingestion queue drain it until empty
    (process_indicator_queue loops until dequeue_indicator returns nothing)
    -- pointing test_redis_url at the dev Redis database destroys whatever
    is genuinely queued there, the same class of risk as the Postgres
    dev/test collision this mirrors. Call this at import time in
    conftest.py, before any fixture or test runs.
    """
    if _redis_identity(test_url) == _redis_identity(dev_url):
        raise RuntimeError(
            "Refusing to run tests: test_redis_url and redis_url resolve to "
            f"the same Redis target ({test_url!r} vs {dev_url!r}). Tests that "
            "exercise the ingestion queue drain it until empty -- pointing "
            "test_redis_url at the dev Redis database destroys whatever is "
            "genuinely queued. Set test_redis_url to a distinct logical "
            "database on the same server, e.g. redis://localhost:6379/1."
        )
