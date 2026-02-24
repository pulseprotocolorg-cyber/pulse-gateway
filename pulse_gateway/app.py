"""PULSE Gateway — FastAPI application.

Secure API gateway that routes PULSE messages to any adapter.
Built-in prompt injection protection, rate limiting, audit logging.

Usage:
    uvicorn pulse_gateway.app:app --host 0.0.0.0 --port 8000

Or programmatically:
    from pulse_gateway import create_app
    app = create_app()
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from pulse.message import PulseMessage
from pulse_gateway.security import SecurityFilter, sanitize_parameters
from pulse_gateway.rate_limiter import RateLimiter
from pulse_gateway.version import __version__


# --- Request/Response Models ---


class GatewayRequest(BaseModel):
    """Incoming request to the gateway."""
    action: str
    provider: str  # "openai", "anthropic", "binance", "bybit", "kraken", "okx"
    parameters: Dict[str, Any] = {}
    provider_config: Dict[str, Any] = {}  # API keys etc. (never logged)


class GatewayResponse(BaseModel):
    """Response from the gateway."""
    success: bool
    request_id: str
    provider: str
    result: Optional[Any] = None
    error: Optional[str] = None
    usage: Optional[Dict] = None


# --- Adapter Registry ---

# Maps provider names to (module, class) for lazy loading
ADAPTER_REGISTRY = {
    "openai": ("pulse_openai", "OpenAIAdapter"),
    "anthropic": ("pulse_anthropic", "AnthropicAdapter"),
    "binance": ("pulse_binance", "BinanceAdapter"),
    "bybit": ("pulse_bybit", "BybitAdapter"),
    "kraken": ("pulse_kraken", "KrakenAdapter"),
    "okx": ("pulse_okx", "OKXAdapter"),
}


def _load_adapter(provider: str, config: Dict[str, Any]):
    """Dynamically load and instantiate an adapter."""
    if provider not in ADAPTER_REGISTRY:
        available = ", ".join(sorted(ADAPTER_REGISTRY.keys()))
        raise ValueError(
            f"Unknown provider '{provider}'. Available: {available}"
        )

    module_name, class_name = ADAPTER_REGISTRY[provider]

    try:
        import importlib
        module = importlib.import_module(module_name)
        adapter_class = getattr(module, class_name)
    except ImportError:
        raise ValueError(
            f"Provider '{provider}' requires package '{module_name}'. "
            f"Install it: pip install {module_name.replace('_', '-')}"
        )

    return adapter_class(**config)


# --- Audit Log ---


class AuditLog:
    """In-memory audit log for request tracking."""

    def __init__(self, max_entries: int = 10000):
        self._entries: List[Dict] = []
        self._max = max_entries

    def log(self, entry: Dict) -> None:
        if len(self._entries) >= self._max:
            self._entries.pop(0)
        entry["logged_at"] = datetime.now(timezone.utc).isoformat()
        self._entries.append(entry)

    @property
    def entries(self) -> List[Dict]:
        return list(self._entries)

    @property
    def count(self) -> int:
        return len(self._entries)


# --- Application Factory ---


def create_app() -> FastAPI:
    """Create and configure the PULSE Gateway application."""

    app = FastAPI(
        title="PULSE Gateway",
        description=(
            "Secure API gateway for PULSE Protocol. "
            "Routes messages to any AI provider or exchange. "
            "Built-in prompt injection protection."
        ),
        version=__version__,
    )

    # Shared state
    security = SecurityFilter()
    limiter = RateLimiter()
    audit = AuditLog()

    # Register a demo key for testing
    limiter.register_key("demo-key", tier="free")

    # --- Routes ---

    @app.get("/")
    async def root():
        return {
            "service": "PULSE Gateway",
            "version": __version__,
            "status": "running",
            "providers": sorted(ADAPTER_REGISTRY.keys()),
            "docs": "/docs",
        }

    @app.get("/health")
    async def health():
        return {
            "status": "healthy",
            "uptime_checks": audit.count,
            "security_stats": security.stats,
        }

    @app.post("/v1/send", response_model=GatewayResponse)
    async def send_message(
        req: GatewayRequest,
        x_api_key: str = Header(alias="X-API-Key", default=""),
    ):
        """Send a PULSE message through the gateway.

        Routes to the specified provider adapter with security checks.
        """
        request_id = str(uuid.uuid4())[:8]
        start_time = time.time()

        # 1. Rate limiting
        if not x_api_key:
            raise HTTPException(
                status_code=401,
                detail="Missing X-API-Key header. Get a key at pulse-gateway.",
            )

        allowed, rate_info = limiter.check(x_api_key)
        if not allowed:
            raise HTTPException(status_code=429, detail=rate_info)

        # 2. Security check (prompt injection)
        text_to_check = str(req.parameters.get("text", ""))
        if not text_to_check:
            text_to_check = str(req.parameters.get("prompt", ""))
        if not text_to_check:
            text_to_check = str(req.parameters.get("message", ""))

        security_result = security.check(text_to_check)
        if security_result["blocked"]:
            audit.log({
                "request_id": request_id,
                "action": req.action,
                "provider": req.provider,
                "blocked": True,
                "reason": security_result["category"],
                "api_key": x_api_key[:8] + "...",
            })
            return GatewayResponse(
                success=False,
                request_id=request_id,
                provider=req.provider,
                error=f"Request blocked: potential {security_result['category']} detected. "
                      f"If this is a false positive, contact support.",
                usage=rate_info,
            )

        # 3. Sanitize parameters (strip secrets before logging)
        safe_params = sanitize_parameters(req.parameters)

        # 4. Create PULSE message
        try:
            message = PulseMessage(
                action=req.action,
                parameters=safe_params,
                validate=False,
            )
        except Exception as e:
            return GatewayResponse(
                success=False,
                request_id=request_id,
                provider=req.provider,
                error=f"Invalid PULSE message: {e}",
                usage=rate_info,
            )

        # 5. Load adapter and send
        try:
            adapter = _load_adapter(req.provider, req.provider_config)
            response = adapter.send(message)
            result = response.content.get("parameters", {}).get("result")

            elapsed = round((time.time() - start_time) * 1000, 1)

            audit.log({
                "request_id": request_id,
                "action": req.action,
                "provider": req.provider,
                "blocked": False,
                "elapsed_ms": elapsed,
                "api_key": x_api_key[:8] + "...",
            })

            return GatewayResponse(
                success=True,
                request_id=request_id,
                provider=req.provider,
                result=result,
                usage=rate_info,
            )

        except ValueError as e:
            return GatewayResponse(
                success=False,
                request_id=request_id,
                provider=req.provider,
                error=str(e),
                usage=rate_info,
            )
        except Exception as e:
            audit.log({
                "request_id": request_id,
                "action": req.action,
                "provider": req.provider,
                "blocked": False,
                "error": str(e),
                "api_key": x_api_key[:8] + "...",
            })
            return GatewayResponse(
                success=False,
                request_id=request_id,
                provider=req.provider,
                error=f"Provider error: {e}",
                usage=rate_info,
            )

    @app.get("/v1/providers")
    async def list_providers():
        """List available providers and their install status."""
        providers = {}
        for name, (module, cls) in ADAPTER_REGISTRY.items():
            try:
                import importlib
                importlib.import_module(module)
                providers[name] = {"installed": True, "package": module.replace("_", "-")}
            except ImportError:
                providers[name] = {"installed": False, "package": module.replace("_", "-")}
        return {"providers": providers}

    @app.get("/v1/usage")
    async def get_usage(x_api_key: str = Header(alias="X-API-Key", default="")):
        """Check API key usage and remaining quota."""
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header.")
        usage = limiter.get_usage(x_api_key)
        if not usage:
            raise HTTPException(status_code=404, detail="Unknown API key.")
        return usage

    @app.get("/v1/security/stats")
    async def security_stats():
        """Security filter statistics."""
        return security.stats

    # Store references for testing
    app.state.security = security
    app.state.limiter = limiter
    app.state.audit = audit

    return app


# Default app instance for uvicorn
app = create_app()
