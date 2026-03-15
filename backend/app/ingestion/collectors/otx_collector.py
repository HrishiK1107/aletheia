import os

import requests
from app.ingestion.collectors.base_collector import BaseCollector


class OTXCollector(BaseCollector):

    name = "otx"

    FEED_URL = "https://otx.alienvault.com/api/v1/indicators/export"

    def fetch(self):

        api_key = os.getenv("OTX_API_KEY")

        headers = {
            "X-OTX-API-KEY": api_key,
            "User-Agent": "Aletheia-ThreatIntel-Collector",
        }

        response = requests.get(
            self.FEED_URL,
            headers=headers,
            timeout=20,
        )

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
