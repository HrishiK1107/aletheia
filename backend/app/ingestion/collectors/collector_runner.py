from app.ingestion.collectors.openphish_collector import OpenPhishCollector
from app.ingestion.indicator_queue import enqueue_indicators


def run_collectors():

    collectors = [
        OpenPhishCollector(),
    ]

    indicators = []

    for collector in collectors:

        results = collector.collect()

        indicators.extend(results)

    # Push indicators into Redis queue
    enqueue_indicators(indicators)

    return indicators
