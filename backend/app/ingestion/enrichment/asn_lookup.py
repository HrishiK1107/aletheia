import requests

API_URL = "http://ip-api.com/json/{ip}?fields=as,isp,status"


def lookup_asn(ip: str) -> dict | None:
    """
    Resolve IP → ASN + hosting provider.
    Returns:
        {
            "asn": "AS13335",
            "hosting_provider": "Cloudflare"
        }
    """

    try:
        response = requests.get(API_URL.format(ip=ip), timeout=5)

        if response.status_code != 200:
            return None

        data = response.json()

        if data.get("status") != "success":
            return None

        as_field = data.get("as", "")

        asn = None

        if as_field:
            # Example: "AS13335 Cloudflare, Inc."
            parts = as_field.split()
            if parts:
                asn = parts[0]

        return {
            "asn": asn,
            "hosting_provider": data.get("isp"),
        }

    except Exception:
        return None
