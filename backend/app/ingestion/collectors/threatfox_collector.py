import requests
from app.core.config import settings
from app.core.logging import get_logger
from app.ingestion.collectors.base_collector import BaseCollector

logger = get_logger(__name__)

KNOWN_TYPES = {"ip", "domain", "url", "hash"}


class ThreatFoxCollector(BaseCollector):

    name = "threatfox"

    FEED_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def build_payload(self):
        """
        Build the request payload. Split out from fetch() so the query
        parameters (e.g. the lookback window) can be asserted on without
        making a live network call.
        """

        return {
            "query": "get_iocs",
            "days": settings.threatfox_lookback_days,
        }

    def fetch(self):

        headers = {
            "User-Agent": "Aletheia-ThreatIntel-Collector",
            "Auth-Key": settings.abusech_api_key,
        }

        response = requests.post(
            self.FEED_URL,
            json=self.build_payload(),
            headers=headers,
            timeout=20,
        )

        response.raise_for_status()

        return response.json()

    def parse(self, data):

        indicators = []
        unrecognized_types = {}

        # ThreatFox returns HTTP 200 even on request errors (bad params,
        # auth issues, ...), signaled only via query_status. On error,
        # "data" is a human-readable string, not a list -- iterating over
        # it silently produces garbage (or crashes) instead of a clear log.
        if data.get("query_status") != "ok":
            logger.warning(
                f"threatfox query did not return ok: "
                f"query_status={data.get('query_status')!r} detail={data.get('data')!r}"
            )
            return indicators

        for item in data["data"]:

            value = item.get("ioc")

            if not value:
                continue

            ioc_type = item.get("ioc_type", "domain")

            if ioc_type not in KNOWN_TYPES:
                unrecognized_types[ioc_type] = unrecognized_types.get(ioc_type, 0) + 1

            indicators.append(
                {
                    "value": value,
                    "type": ioc_type,
                    "source": "threatfox",
                    "confidence": 75,
                    "labels": {
                        "malware": item.get("malware"),
                        "malware_printable": item.get("malware_printable"),
                        "threat_type": item.get("threat_type"),
                        "tags": item.get("tags"),
                        "confidence_level": item.get("confidence_level"),
                        "first_seen": item.get("first_seen"),
                        "reporter": item.get("reporter"),
                    },
                }
            )

        if unrecognized_types:
            logger.warning(
                f"threatfox returned ioc_type values outside {sorted(KNOWN_TYPES)}: "
                f"{unrecognized_types} — these pass through unnormalized/unvalidated, "
                f"see CONTEXT.md item 2.4 (hash enrichment / type normalization)"
            )

        return indicators
