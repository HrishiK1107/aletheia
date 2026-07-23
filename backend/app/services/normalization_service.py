import ipaddress
from urllib.parse import urlparse


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()

    if domain.startswith("http://") or domain.startswith("https://"):
        parsed = urlparse(domain)
        domain = parsed.netloc

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def normalize_url(url: str) -> str:
    url = url.strip()

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    return f"{scheme}://{netloc}{path}"


def normalize_hash(hash_value: str) -> str:
    return hash_value.strip().lower()


def normalize_ip(ip: str) -> str:
    return ip.strip()


def canonicalize_indicator_type(value: str, indicator_type: str) -> tuple[str, str]:
    """
    Rewrites source-reported pseudo-types that are actually a known type
    plus incidental formatting into the real type, before validation/
    normalization/enrichment ever see them. Currently handles ThreatFox's
    "ip:port" ioc_type (CONTEXT.md item 2.4 follow-up, 2026-07-23):
    validator.py/normalization_service.py only recognize
    {domain, url, hash, ip}, so "ip:port" previously fell through both as
    an unvalidated, unenrichable literal string -- confirmed 977/977
    sampled values parse to a valid IP once the port is stripped, i.e. this
    was a parsing gap on our side, not a data-scope limitation.

    IPv6-safe: bracketed "[addr]:port" is unwrapped explicitly; a bare
    "host:port" is only split if the part before the last ':' is itself a
    valid IP address and the part after is a valid port number -- an
    unbracketed bare IPv6 address (which contains multiple ':' and no
    port) fails that check on its rightmost split and is tried whole
    instead, so it passes through unsplit rather than being mangled.

    Anything that isn't recognized as this pattern is returned unchanged.
    """
    if indicator_type != "ip:port":
        return value, indicator_type

    candidate = value.strip()

    if candidate.startswith("[") and "]" in candidate:
        host = candidate[1 : candidate.index("]")]
        if _is_valid_ip(host):
            return host, "ip"
        return value, indicator_type

    if ":" in candidate:
        host, _, port = candidate.rpartition(":")
        if _is_valid_ip(host) and _is_valid_port(port):
            return host, "ip"

    if _is_valid_ip(candidate):
        return candidate, "ip"

    return value, indicator_type


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_port(value: str) -> bool:
    return value.isdigit() and 0 <= int(value) <= 65535


def normalize_indicator(value: str, indicator_type: str) -> str:
    indicator_type = indicator_type.lower()

    if indicator_type == "domain":
        return normalize_domain(value)

    if indicator_type == "url":
        return normalize_url(value)

    if indicator_type == "hash":
        return normalize_hash(value)

    if indicator_type == "ip":
        return normalize_ip(value)

    return value
