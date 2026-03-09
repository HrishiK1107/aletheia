import logging
import time

from app.db.postgres import SessionLocal
from app.ingestion.enrichment.models.raw_indicator_model import RawIndicator
from app.ingestion.indicator_queue import dequeue_indicator
from app.schemas.indicator_schema import IndicatorCreate
from app.services.indicator_service import create_indicator
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def process_indicator(db: Session, raw_indicator: dict):
    """
    Convert raw indicator → schema → service layer
    while preserving raw indicator storage.
    """

    # Store raw indicator
    raw = RawIndicator(
        value=raw_indicator.get("value"),
        type=raw_indicator.get("type"),
        source=raw_indicator.get("source"),
        confidence=raw_indicator.get("confidence"),
        raw_payload=raw_indicator,
    )

    db.add(raw)
    db.commit()

    # Continue existing processing pipeline
    indicator = IndicatorCreate(**raw_indicator)

    create_indicator(db, indicator)


def process_indicator_queue():
    """
    Process all indicators currently in the queue once.
    Used by tests and batch execution.
    """

    db = SessionLocal()

    try:
        while True:

            raw_indicator = dequeue_indicator()

            if not raw_indicator:
                break

            process_indicator(db, raw_indicator)

    finally:
        db.close()


def run_worker():
    """
    Continuous ingestion worker.
    """

    logger.info("Ingestion worker started")

    while True:

        raw_indicator = dequeue_indicator()

        if not raw_indicator:
            time.sleep(1)
            continue

        db = SessionLocal()

        try:
            process_indicator(db, raw_indicator)

        except Exception as e:
            logger.error(f"Worker failed processing indicator: {e}")

        finally:
            db.close()


if __name__ == "__main__":
    run_worker()
