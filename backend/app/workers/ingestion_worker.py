import logging
import time

from app.db.postgres import SessionLocal
from app.ingestion.enrichment.models.raw_indicator_model import RawIndicator
from app.ingestion.indicator_queue import dequeue_indicator
from app.schemas.indicator_schema import IndicatorCreate
from app.services.indicator_service import create_indicator
from app.services.timeline_service import TimelineService
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def process_indicator(db: Session, raw_indicator: dict):
    """
    Convert raw indicator → schema → service layer
    while preserving raw indicator storage.
    """

    # Store raw indicator, deduplicated on (value, source): the same feed
    # re-reporting the same value on every run must not accumulate a new
    # row each time (CONTEXT.md item 1.4 -- 1,344 rows from two ~670
    # collections). Scoped to (value, source) rather than value alone so a
    # DIFFERENT feed reporting the same value still gets its own row --
    # that's cross-feed corroboration, not a duplicate (CONTEXT.md §5).
    # ON CONFLICT DO NOTHING at the DB level so this is safe under
    # concurrent workers, not just a check-then-insert race.
    stmt = (
        pg_insert(RawIndicator)
        .values(
            value=raw_indicator.get("value"),
            type=raw_indicator.get("type"),
            source=raw_indicator.get("source"),
            confidence=raw_indicator.get("confidence"),
            raw_payload=raw_indicator,
        )
        .on_conflict_do_nothing(index_elements=["value", "source"])
    )

    db.execute(stmt)

    timeline = TimelineService()

    timeline.record_event(
        db,
        event_type="indicator_discovered",
        event_value=raw_indicator.get("value"),
        source=raw_indicator.get("source"),
    )

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
    from app.core.venv_safety import ensure_correct_interpreter

    ensure_correct_interpreter()
    run_worker()
