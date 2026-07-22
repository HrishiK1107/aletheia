import requests
from app.core.config import settings
from app.core.logging import get_logger
from app.ingestion.collectors.base_collector import BaseCollector

logger = get_logger(__name__)


class URLhausCollector(BaseCollector):
    """
    URLhaus (abuse.ch) -- labelled URLs, closing the gap left by OpenPhish
    (~300 URLs/run with no usable ground truth).

    Note: /urls/recent/ does not expose a clean, separate malware-family
    field the way ThreatFox's malware_printable does. Family names, when
    present, are embedded unstructured inside `tags` alongside
    architecture/format tags (e.g. ["32-bit", "elf", "mips", "Mozi"]). A
    clean per-payload `signature` field does exist, but only via the
    single-URL lookup endpoint (/v1/url/), which would cost one API call
    per URL (~900+ per run at current volume) -- not implemented here.
    """

    name = "urlhaus"

    FEED_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    def fetch(self):

        headers = {
            "User-Agent": "Aletheia-ThreatIntel-Collector",
            "Auth-Key": settings.abusech_api_key,
        }

        response = requests.get(
            self.FEED_URL,
            headers=headers,
            timeout=20,
        )

        response.raise_for_status()

        return response.json()

    def parse(self, data):

        indicators = []

        # Like ThreatFox/MalwareBazaar, abuse.ch APIs return HTTP 200 on
        # request errors (bad/missing Auth-Key, etc.) and signal it only
        # via query_status.
        if data.get("query_status") != "ok":
            logger.warning(
                f"urlhaus query did not return ok: query_status={data.get('query_status')!r}"
            )
            return indicators

        for item in data.get("urls", []):

            value = item.get("url")

            if not value:
                continue

            indicators.append(
                {
                    "value": value,
                    "type": "url",
                    "source": "urlhaus",
                    "confidence": 80,
                    "labels": {
                        "threat_type": item.get("threat"),
                        "tags": item.get("tags"),
                        "reporter": item.get("reporter"),
                        "date_added": item.get("date_added"),
                    },
                }
            )

        return indicators
