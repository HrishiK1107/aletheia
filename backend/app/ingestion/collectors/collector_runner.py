from app.ingestion.collectors.openphish_collector import OpenPhishCollector


def run_collectors():

    collectors = [
        OpenPhishCollector(),
    ]

    indicators = []

    for collector in collectors:

        results = collector.collect()

        indicators.extend(results)

    return indicators
