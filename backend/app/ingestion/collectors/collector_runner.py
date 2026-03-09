from app.ingestion.indicator_queue import enqueue_indicators
from app.ingestion.registry.feed_registry import registry


def run_collectors():
    """
    Execute all registered collectors and push indicators to queue.
    """

    collectors = registry.get_collectors()

    indicators = []

    for collector in collectors:

        results = collector.collect()

        indicators.extend(results)

    # Push indicators into Redis queue
    enqueue_indicators(indicators)

    return indicators
