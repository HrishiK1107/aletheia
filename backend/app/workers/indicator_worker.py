import json
import time

from app.core.logging import get_logger
from app.db.postgres import SessionLocal
from app.ingestion.indicator_queue import dequeue_indicator
from app.schemas.indicator_schema import IndicatorCreate
from app.services.indicator_service import create_indicator

logger = get_logger(__name__)


def safe_parse_indicator(data):
    """
    Defensive parsing for malformed queue payloads.
    Collectors sometimes push entire API responses accidentally.
    """

    if not data:
        return None

    # If the value field is huge JSON, ignore it
    value = data.get("value")

    if isinstance(value, str) and len(value) > 2000:
        logger.warning("Skipping oversized indicator payload")
        return None

    # If the collector pushed raw JSON
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            parsed = json.loads(value)

            # Detect collector API responses
            if "results" in parsed or "data" in parsed:
                logger.warning("Skipping collector API response payload")
                return None
        except Exception:
            pass

    return data


def run_worker():

    logger.info("Indicator worker started")

    while True:

        indicator_data = dequeue_indicator()

        if not indicator_data:
            time.sleep(1)
            continue

        indicator_data = safe_parse_indicator(indicator_data)

        if not indicator_data:
            continue

        db = SessionLocal()

        try:

            indicator = IndicatorCreate(**indicator_data)

            create_indicator(db, indicator)

            logger.info(f"Processed indicator {indicator.value}")

        except Exception as e:

            logger.warning(f"Worker failed: {e}")

        finally:

            db.close()


if __name__ == "__main__":
    run_worker()
