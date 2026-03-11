from unittest.mock import MagicMock, patch

from app.ingestion.enrichment.models.indicator_models import Indicator
from app.workers.enrichment_worker import enrich_indicator


def test_enrichment_worker_runs():

    db = MagicMock()

    indicator = Indicator(
        id=1,
        value="1.1.1.1",
        type="ip",
    )

    with patch("app.ingestion.enrichment.asn_lookup.lookup_asn") as mock_asn:

        mock_asn.return_value = {"asn": "AS13335", "hosting_provider": "Cloudflare"}

        enrich_indicator(db, indicator)

        assert db.add.called
