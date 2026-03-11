import logging
import time

from app.correlation.graph_builder import GraphBuilder
from app.db.postgres import SessionLocal

logger = logging.getLogger(__name__)


def run_graph_build():

    db = SessionLocal()

    try:

        builder = GraphBuilder()

        builder.ingest_all_indicators(db)

    finally:
        db.close()


def run_worker():

    logger.info("Graph worker started")

    while True:

        try:
            run_graph_build()

        except Exception as e:
            logger.error(f"Graph build failed: {e}")

        time.sleep(300)


if __name__ == "__main__":
    run_worker()
