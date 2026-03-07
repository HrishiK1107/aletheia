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
