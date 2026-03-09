from app.ingestion.collectors.openphish_collector import OpenPhishCollector
from app.ingestion.collectors.otx_collector import OTXCollector
from app.ingestion.collectors.threatfox_collector import ThreatFoxCollector


class FeedRegistry:
    """
    Central registry for all threat feeds.
    """

    def __init__(self):
        self.collectors = []

    def register(self, collector):
        self.collectors.append(collector)

    def get_collectors(self):
        return self.collectors


registry = FeedRegistry()

# Register collectors
registry.register(OpenPhishCollector())
registry.register(OTXCollector())
registry.register(ThreatFoxCollector())
