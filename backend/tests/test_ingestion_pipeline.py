from app.ingestion.collectors.openphish_collector import OpenPhishCollector
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.indicator_queue import enqueue_indicators
from app.workers.ingestion_worker import process_indicator_queue


def test_ingestion_pipeline(db_session):

    collector = OpenPhishCollector()

    # Simulated feed data
    sample_data = """
http://malicious-test-1.com
http://malicious-test-2.com
"""

    indicators = collector.parse(sample_data)

    # push to queue
    enqueue_indicators(indicators)

    # run worker
    process_indicator_queue()

    # verify database insertion
    stored = db_session.query(Indicator).all()

    assert len(stored) >= 2
