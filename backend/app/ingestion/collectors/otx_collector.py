import requests
from app.ingestion.collectors.base_collector import BaseCollector


class OTXCollector(BaseCollector):

    name = "otx"

    FEED_URL = "https://otx.alienvault.com/api/v1/indicators/export"

    def fetch(self):
        response = requests.get(self.FEED_URL, timeout=15)
        response.raise_for_status()

        return response.text

    def parse(self, data):

        indicators = []

        for line in data.splitlines():

            value = line.strip()

            if not value:
                continue

            indicators.append(
                {
                    "value": value,
                    "type": "domain",
                    "source": "otx",
                    "confidence": 70,
                }
            )

        return indicators
