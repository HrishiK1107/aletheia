import requests
from app.ingestion.collectors.base_collector import BaseCollector


class ThreatFoxCollector(BaseCollector):

    name = "threatfox"

    FEED_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def fetch(self):

        payload = {"query": "get_iocs", "limit": 100}

        response = requests.post(self.FEED_URL, json=payload, timeout=15)
        response.raise_for_status()

        return response.json()

    def parse(self, data):

        indicators = []

        if "data" not in data:
            return indicators

        for item in data["data"]:

            value = item.get("ioc")

            if not value:
                continue

            indicators.append(
                {
                    "value": value,
                    "type": item.get("ioc_type", "domain"),
                    "source": "threatfox",
                    "confidence": 75,
                }
            )

        return indicators
