from app.ingestion.enrichment.models.feed_source_model import FeedSource


def test_feed_source_creation():

    source = FeedSource(name="otx", description="AlienVault OTX feed")

    assert source.name == "otx"
    assert source.description == "AlienVault OTX feed"
