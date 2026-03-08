import requests
from app.ingestion.collectors.base_collector import BaseCollector


class OpenPhishCollector(BaseCollector):

    name = "openphish"

    FEED_URL = "https://openphish.com/feed.txt"

    def fetch(self):

        response = requests.get(self.FEED_URL, timeout=10)
        response.raise_for_status()

        return response.text

    def parse(self, data):

        indicators = []

        for line in data.splitlines():

            url = line.strip()

            if not url:
                continue

            indicators.append(
                {
                    "value": url,
                    "type": "url",
                    "source": "openphish",
                    "confidence": 80,
                }
            )

        return indicators
