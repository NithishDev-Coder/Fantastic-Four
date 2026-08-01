"""
WHOIS-based domain metadata. Purely a registry lookup -- doesn't send
anything to the target's own infrastructure.
"""

import datetime

import whois


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _stringify_date(value):
    value = _first(value)
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d")
    if isinstance(value, datetime.date):
        return value.strftime("%Y-%m-%d")
    return value


def lookup(domain):
    try:
        w = whois.whois(domain)
    except Exception:
        return {"available": False}

    if not w or not w.domain_name:
        return {"available": False}

    name_servers = w.name_servers
    if isinstance(name_servers, str):
        name_servers = [name_servers]

    return {
        "available": True,
        "registrar": _first(w.registrar),
        "creation_date": _stringify_date(w.creation_date),
        "expiration_date": _stringify_date(w.expiration_date),
        "name_servers": sorted({ns.lower() for ns in (name_servers or [])}),
        "org": _first(getattr(w, "org", None)),
        "country": _first(getattr(w, "country", None)),
    }
