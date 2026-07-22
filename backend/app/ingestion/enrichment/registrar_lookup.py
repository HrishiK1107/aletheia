import logging

import whois

logger = logging.getLogger(__name__)


def lookup_registrar(domain: str) -> dict | None:
    """
    Resolve registrar information for a domain.

    Returns:
    {
        "registrar": "Namecheap"
    }
    """

    try:

        w = whois.whois(domain)

        registrar = None

        if isinstance(w.registrar, list):
            registrar = w.registrar[0]
        else:
            registrar = w.registrar

        if not registrar:
            logger.debug(f"WHOIS lookup for {domain} returned no registrar field")
            return None

        return {"registrar": registrar}

    except Exception as e:
        # Silent-failure audit, CONTEXT.md item 2.7's follow-up: this used
        # to be a bare `except Exception: return None` with no signal at
        # all. The underlying `whois`/socket library also prints its own
        # connection errors directly to stdout (not through logging),
        # which is the wall of "Error trying to connect to socket" text
        # seen during the full-volume enrichment run -- that's a separate,
        # third-party logging channel this can't silence, but at least our
        # own code now records *why* a given domain's lookup failed.
        logger.debug(f"WHOIS lookup failed for {domain}: {type(e).__name__}: {e}")
        return None
