import dns.resolver


def lookup_dns(domain: str) -> dict | None:
    """
    Resolve domain DNS infrastructure.

    Returns:
    {
        "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        "ips": ["104.16.132.229", "104.16.133.229"]
    }
    """

    result = {
        "nameservers": [],
        "ips": [],
    }

    try:

        # Resolve nameservers
        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            result["nameservers"] = [str(r.target).rstrip(".") for r in ns_answers]
        except Exception:
            pass

        # Resolve A records
        try:
            a_answers = dns.resolver.resolve(domain, "A")
            result["ips"] = [r.address for r in a_answers]
        except Exception:
            pass

        if not result["nameservers"] and not result["ips"]:
            return None

        return result

    except Exception:
        return None
