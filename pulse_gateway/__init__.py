"""
PULSE Gateway — Secure API gateway for PULSE Protocol.

Routes PULSE messages to any adapter (AI providers, exchanges).
Built-in prompt injection protection, rate limiting, audit logging.

Example:
    >>> from pulse_gateway import create_app
    >>> app = create_app()
    # Run: uvicorn pulse_gateway:app --host 0.0.0.0 --port 8000
"""

from pulse_gateway.app import create_app
from pulse_gateway.version import __version__

__all__ = ["create_app", "__version__"]
