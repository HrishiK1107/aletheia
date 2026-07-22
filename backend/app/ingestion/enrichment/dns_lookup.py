import logging

import dns.resolver

logger = logging.getLogger(__name__)


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

    # NS and A lookups are logged individually (not just the outer
    # try/except) since they fail independently and for different
    # reasons -- silent-failure audit, CONTEXT.md item 2.7's follow-up:
    # every except here used to be a bare `pass`/`return None` with no
    # signal at all about *why*, which is exactly what let the ASN
    # rate-limit collapse go unnoticed. NXDOMAIN/NoAnswer are expected and
    # common (aged/dead OSINT infrastructure -- see the coverage baseline
    # in CONTEXT.md item 2.6/2.7); Timeout/NoNameservers repeated at scale
    # would be the same class of systemic problem ASN had.

    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        result["nameservers"] = [str(r.target).rstrip(".") for r in ns_answers]
    except Exception as e:
        logger.debug(f"NS lookup failed for {domain}: {type(e).__name__}: {e}")

    try:
        a_answers = dns.resolver.resolve(domain, "A")
        result["ips"] = [r.address for r in a_answers]
    except Exception as e:
        logger.debug(f"A lookup failed for {domain}: {type(e).__name__}: {e}")

    if not result["nameservers"] and not result["ips"]:
        return None

    return result
