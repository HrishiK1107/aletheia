import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_REGEX = re.compile(r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$")


def validate_domain(domain: str) -> bool:

    if ".." in domain:
        return False

    return bool(DOMAIN_REGEX.match(domain))


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_url(url):
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


def validate_hash(hash_value):
    return len(hash_value) in (32, 40, 64)


def validate_indicator(value, indicator_type):

    indicator_type = indicator_type.lower()

    if indicator_type == "domain":
        return validate_domain(value), "invalid domain"

    if indicator_type == "ip":
        return validate_ip(value), "invalid ip"

    if indicator_type == "url":
        return validate_url(value), "invalid url"

    if indicator_type == "hash":
        return validate_hash(value), "invalid hash"

    return True, None
