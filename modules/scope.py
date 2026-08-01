"""
Scope and authorization enforcement for ReconGuard.

Before anything gets scanned, a target has to clear three checks:
  1. It has to be a syntactically valid, resolvable public domain
     (not an IP, not localhost, not something on a private network).
  2. It can't be on the protected list (gov/mil suffixes, a handful
     of apex domains that are never appropriate targets for a class
     project regardless of what someone types in).
  3. The person running the scan has to explicitly confirm they're
     authorized to test it.

Nothing downstream should ever see a target that hasn't passed all
three.
"""

import ipaddress
import re
import socket

from config import Config

DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# Suffixes we refuse to touch outright.
PROTECTED_SUFFIXES = (".gov", ".mil", ".gov.in", ".nic.in", ".gov.uk")

# A short denylist of apex domains that are never an appropriate
# target for this tool, no matter what authorization checkbox gets
# ticked. This isn't meant to be exhaustive -- it's a guardrail, not
# a substitute for the allowlist below.
PROTECTED_APEX_DOMAINS = {
    "google.com", "facebook.com", "meta.com", "amazon.com", "microsoft.com",
    "apple.com", "cloudflare.com", "github.com", "gitlab.com", "anthropic.com",
}


class ScopeError(Exception):
    """Raised whenever a target fails scope validation."""


def _is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_PATTERN.match(domain)) and len(domain) <= 253


def _is_private_or_reserved(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def normalize_domain(raw_domain: str) -> str:
    domain = raw_domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    return domain.rstrip(".")


def check_scope(raw_domain: str, authorized: bool = False) -> str:
    """
    Validate a target before it goes anywhere near the recon engine.
    Returns the normalized domain on success, raises ScopeError with a
    human-readable reason otherwise.
    """
    if not raw_domain or not raw_domain.strip():
        raise ScopeError("No target domain was provided.")

    domain = normalize_domain(raw_domain)

    if not _is_valid_domain(domain):
        raise ScopeError(f"'{raw_domain}' doesn't look like a valid domain name.")

    if domain == "localhost" or domain.endswith(".local"):
        raise ScopeError("Local/loopback targets are out of scope.")

    for suffix in PROTECTED_SUFFIXES:
        if domain.endswith(suffix):
            raise ScopeError(
                f"'{domain}' falls under a protected suffix ({suffix}) and is excluded from scanning."
            )

    labels = domain.split(".")
    apex = ".".join(labels[-2:]) if len(labels) >= 2 else domain
    if apex in PROTECTED_APEX_DOMAINS:
        raise ScopeError(f"'{apex}' is on the protected domain list and can't be scanned here.")

    if Config.ALLOWLIST_ENFORCED:
        allowed = Config.ALLOWED_DOMAINS
        if allowed and not any(domain == entry or domain.endswith("." + entry) for entry in allowed):
            raise ScopeError(
                f"'{domain}' is not on the configured allowlist. "
                "Add it to ALLOWED_DOMAINS (see config.py) if you're authorized to test it."
            )

    if not authorized:
        raise ScopeError("You need to confirm you own or are authorized to test this target first.")

    try:
        resolved_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        raise ScopeError(f"'{domain}' doesn't resolve to an IP address.")

    if _is_private_or_reserved(resolved_ip):
        raise ScopeError(f"'{domain}' resolves to a private/reserved address ({resolved_ip}) and is out of scope.")

    return domain
