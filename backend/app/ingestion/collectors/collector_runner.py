from app.core.logging import get_logger
from app.db.postgres import SessionLocal
from app.ingestion.indicator_queue import enqueue_indicators
from app.ingestion.registry.feed_registry import registry
from app.services.feed_service import record_feed_run, update_feed_status

logger = get_logger(__name__)


def run_collectors():
    """
    Execute all registered collectors and push indicators to queue.
    Each collector runs independently so a failure does not stop the pipeline.
    Persists a FeedRun (per-run history) and the Feed's current status for
    every collector, success or failure -- collect() never raises for a
    BaseCollector subclass, so success/failure is read from last_error
    rather than relying on an exception here.
    """

    collectors = registry.get_collectors()

    indicators = []

    db = SessionLocal()

    try:
        for collector in collectors:

            class_name = collector.__class__.__name__
            feed_name = getattr(collector, "name", class_name)

            try:
                logger.info(f"Running collector: {class_name}")

                results = collector.collect()

                if results:
                    indicators.extend(results)

                logger.info(f"{class_name} returned {len(results)} indicators")

                error = getattr(collector, "last_error", None)
                success = error is None

                record_feed_run(db, feed_name, len(results), success, error)
                update_feed_status(db, feed_name, len(results), success)

            except Exception as e:
                logger.warning(f"Collector {class_name} failed: {str(e)}")

                record_feed_run(db, feed_name, 0, False, str(e))
                update_feed_status(db, feed_name, 0, False)

    finally:
        db.close()

    if indicators:
        enqueue_indicators(indicators)
        logger.info(f"Queued {len(indicators)} indicators for processing")

    return indicators
