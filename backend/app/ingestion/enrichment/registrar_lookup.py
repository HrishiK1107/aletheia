import whois


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
            return None

        return {"registrar": registrar}

    except Exception:
        return None
