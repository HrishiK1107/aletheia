import pytest
from app.core.db_safety import ensure_distinct_databases, ensure_distinct_redis_targets


def test_allows_distinct_databases():
    ensure_distinct_databases(
        "postgresql://aletheia:aletheia@localhost:5432/aletheia_test",
        "postgresql://aletheia:aletheia@localhost:5432/aletheia",
    )


def test_raises_when_same_database():
    with pytest.raises(RuntimeError, match="same database"):
        ensure_distinct_databases(
            "postgresql://aletheia:aletheia@localhost:5432/aletheia",
            "postgresql://aletheia:aletheia@localhost:5432/aletheia",
        )


def test_raises_when_same_database_different_credentials():
    """
    Host/port/database name is what defines "the same database" -- a
    different user or password string must not mask that the underlying
    database is identical.
    """
    with pytest.raises(RuntimeError, match="same database"):
        ensure_distinct_databases(
            "postgresql://other_user:other_pass@localhost:5432/aletheia",
            "postgresql://aletheia:aletheia@localhost:5432/aletheia",
        )


def test_allows_same_host_different_database_name():
    ensure_distinct_databases(
        "postgresql://aletheia:aletheia@localhost:5432/aletheia_test",
        "postgresql://aletheia:aletheia@localhost:5432/aletheia",
    )


def test_default_port_applied_when_omitted():
    """
    Postgres defaults to port 5432 when a DSN omits it -- an explicit
    :5432 and an omitted port on the same host+database must still be
    treated as the same database, not silently allowed through.
    """
    with pytest.raises(RuntimeError, match="same database"):
        ensure_distinct_databases(
            "postgresql://aletheia:aletheia@localhost/aletheia",
            "postgresql://aletheia:aletheia@localhost:5432/aletheia",
        )


def test_different_host_is_distinct():
    ensure_distinct_databases(
        "postgresql://aletheia:aletheia@test-db-host:5432/aletheia",
        "postgresql://aletheia:aletheia@localhost:5432/aletheia",
    )


def test_redis_allows_distinct_db_index():
    ensure_distinct_redis_targets(
        "redis://localhost:6379/1",
        "redis://localhost:6379",
    )


def test_redis_raises_when_same_target():
    with pytest.raises(RuntimeError, match="same Redis target"):
        ensure_distinct_redis_targets(
            "redis://localhost:6379",
            "redis://localhost:6379",
        )


def test_redis_raises_when_same_db_index_explicit_and_default():
    """
    An explicit /0 and an omitted db index (which defaults to 0) must be
    treated as the same logical database, not silently allowed through.
    """
    with pytest.raises(RuntimeError, match="same Redis target"):
        ensure_distinct_redis_targets(
            "redis://localhost:6379/0",
            "redis://localhost:6379",
        )


def test_redis_default_port_applied_when_omitted():
    with pytest.raises(RuntimeError, match="same Redis target"):
        ensure_distinct_redis_targets(
            "redis://localhost/1",
            "redis://localhost:6379/1",
        )


def test_redis_different_host_is_distinct():
    ensure_distinct_redis_targets(
        "redis://test-redis-host:6379/0",
        "redis://localhost:6379/0",
    )
