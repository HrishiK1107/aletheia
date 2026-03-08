from app.db.redis import redis_client
from app.ingestion.indicator_queue import dequeue_indicator, enqueue_indicator, queue_length

QUEUE_NAME = "aletheia:indicator_ingest"


def setup_function():
    """
    Clear queue before each test.
    """
    redis_client.delete(QUEUE_NAME)


def test_enqueue_indicator():

    indicator = {
        "value": "http://example.com",
        "type": "url",
        "source": "test",
        "confidence": 80,
    }

    enqueue_indicator(indicator)

    assert queue_length() == 1


def test_dequeue_indicator():

    indicator = {
        "value": "http://test.com",
        "type": "url",
        "source": "test",
        "confidence": 90,
    }

    enqueue_indicator(indicator)

    result = dequeue_indicator(timeout=1)

    assert result["value"] == "http://test.com"
    assert result["type"] == "url"


def test_queue_empty_returns_none():

    result = dequeue_indicator(timeout=1)

    assert result is None
