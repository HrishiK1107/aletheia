import json
from typing import Dict, List, Optional

from app.db.redis import redis_client

QUEUE_NAME = "aletheia:indicator_ingest"


def enqueue_indicator(indicator: Dict):
    """
    Push single indicator into Redis queue.
    """
    payload = json.dumps(indicator)
    redis_client.lpush(QUEUE_NAME, payload)


def enqueue_indicators(indicators: List[Dict]):
    """
    Push multiple indicators into queue.
    """
    for indicator in indicators:
        enqueue_indicator(indicator)


def dequeue_indicator(timeout: int = 5) -> Optional[Dict]:
    """
    Pop indicator from queue.
    Uses blocking pop to allow worker waiting.
    """
    result = redis_client.brpop(QUEUE_NAME, timeout=timeout)

    if not result:
        return None

    _, payload = result

    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def queue_length() -> int:
    """
    Check current queue size.
    """
    return redis_client.llen(QUEUE_NAME)
