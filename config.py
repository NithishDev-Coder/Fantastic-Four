"""
ReconGuard Application Configuration
"""

import os
import secrets


class Config:
    """Base configuration. Override any of this via environment variables."""

    # No hardcoded fallback secret -- that defeats the point of having one.
    # Falls back to a fresh random key per process if SECRET_KEY isn't set,
    # which is fine for a demo/hackathon run (sessions just won't survive
    # a restart) but should always be set explicitly for anything longer-lived.
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    DEBUG = os.environ.get("FLASK_DEBUG", "False") == "True"
    APP_NAME = "ReconGuard"
    VERSION = "2.0"
    LOG_LEVEL = "INFO"
    JSONIFY_PRETTYPRINT_REGULAR = True

    # Scope enforcement. With ALLOWLIST_ENFORCED off, any public, non-
    # protected domain can be scanned once the requester confirms
    # authorization (see modules/scope.py for the protected-domain
    # denylist). Turn it on and populate ALLOWED_DOMAINS to lock the
    # tool down to a fixed set of domains you control.
    ALLOWLIST_ENFORCED = os.environ.get("ALLOWLIST_ENFORCED", "False") == "True"
    ALLOWED_DOMAINS = [
        d.strip() for d in os.environ.get("ALLOWED_DOMAINS", "").split(",") if d.strip()
    ]

# Scan Settings
REQUEST_DELAY = 0.5      # seconds between HTTP requests
MAX_THREADS = 5          # concurrent workers
USER_AGENT = "ReconGuard/1.0 (Authorized Security Assessment)"
REQUEST_TIMEOUT = 8