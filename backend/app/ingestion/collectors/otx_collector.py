import requests
from app.core.config import settings
from app.core.logging import get_logger
from app.ingestion.collectors.base_collector import BaseCollector

logger = get_logger(__name__)

PULSE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# OTX indicator types that map cleanly onto our internal type set.
# Everything else (FileHash-PEHASH, CIDR, email, Mutex, CVE, YARA, ...)
# passes through with its raw OTX type string, unnormalized.
TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
}


class OTXCollector(BaseCollector):

    name = "otx"

    def _headers(self):
        return {
            "X-OTX-API-KEY": settings.otx_api_key,
            "User-Agent": "Aletheia-ThreatIntel-Collector",
        }

    def fetch(self):
        """
        Page through /pulses/subscribed. Each pulse is a human-curated
        group of indicators (a campaign), which parse() carries through as
        a label. Bounded by otx_max_pages so one run doesn't try to pull
        every subscribed pulse (thousands, at the free-tier default).
        """

        pulses = []

        url = PULSE_URL
        params = {"limit": settings.otx_pulse_page_size, "page": 1}

        for _ in range(settings.otx_max_pages):

            response = requests.get(url, headers=self._headers(), params=params, timeout=20)
            response.raise_for_status()

            payload = response.json()
            pulses.extend(payload.get("results", []))

            next_url = payload.get("next")

            if not next_url:
                break

            # "next" is already a fully-qualified URL with its own query string.
            url = next_url
            params = None

        return pulses

    def parse(self, data):

        indicators = []
        unrecognized_types = {}

        for pulse in data:

            pulse_id = pulse.get("id")
            pulse_name = pulse.get("name")

            for item in pulse.get("indicators", []):

                value = item.get("indicator")

                if not value:
                    continue

                otx_type = item.get("type", "")
                mapped_type = TYPE_MAP.get(otx_type)

                if mapped_type is None:
                    unrecognized_types[otx_type] = unrecognized_types.get(otx_type, 0) + 1
                    mapped_type = otx_type

                indicators.append(
                    {
                        "value": value,
                        "type": mapped_type,
                        "source": "otx",
                        "confidence": 70,
                        "labels": {
                            "pulse_id": pulse_id,
                            "pulse_name": pulse_name,
                        },
                    }
                )

        if unrecognized_types:
            logger.warning(
                f"otx returned indicator types outside {sorted(TYPE_MAP)}: "
                f"{unrecognized_types} — these pass through unnormalized/unvalidated, "
                f"see CONTEXT.md item 2.4 (hash enrichment / type normalization)"
            )

        return indicators
