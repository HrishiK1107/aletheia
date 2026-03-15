from app.core.logging import get_logger
from app.ingestion.indicator_queue import enqueue_indicators
from app.ingestion.registry.feed_registry import registry

logger = get_logger(__name__)


def run_collectors():
    """
    Execute all registered collectors and push indicators to queue.
    Each collector runs independently so a failure does not stop the pipeline.
    """

    collectors = registry.get_collectors()

    indicators = []

    for collector in collectors:

        try:
            logger.info(f"Running collector: {collector.__class__.__name__}")

            results = collector.collect()

            if results:
                indicators.extend(results)

            logger.info(f"{collector.__class__.__name__} returned {len(results)} indicators")

        except Exception as e:
            logger.warning(f"Collector {collector.__class__.__name__} failed: {str(e)}")

    if indicators:
        enqueue_indicators(indicators)
        logger.info(f"Queued {len(indicators)} indicators for processing")

    return indicators
