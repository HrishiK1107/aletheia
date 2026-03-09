from app.ingestion.collectors.openphish_collector import OpenPhishCollector


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

registry.register(OpenPhishCollector())
