"""Rate limiting for PULSE Gateway.

Tracks requests per API key with configurable tiers.
In-memory storage (no external dependencies).
"""

import time
from typing import Dict, Optional, Tuple


# Default tier limits (requests per day)
TIERS = {
    "free": 100,
    "pro": 10_000,
    "business": 1_000_000,  # effectively unlimited
}


class RateLimiter:
    """In-memory rate limiter with tier support.

    Tracks request counts per API key per day.
    Resets automatically at midnight UTC.

    Example:
        >>> limiter = RateLimiter()
        >>> limiter.register_key("key-123", tier="free")
        >>> allowed, info = limiter.check("key-123")
        >>> allowed
        True
    """

    def __init__(self, tiers: Optional[Dict[str, int]] = None):
        self._tiers = tiers or dict(TIERS)
        self._keys: Dict[str, str] = {}  # api_key -> tier
        self._counts: Dict[str, int] = {}  # api_key -> request count today
        self._reset_day: Dict[str, int] = {}  # api_key -> last reset day

    def register_key(self, api_key: str, tier: str = "free") -> None:
        """Register an API key with a tier."""
        if tier not in self._tiers:
            raise ValueError(f"Unknown tier '{tier}'. Available: {list(self._tiers.keys())}")
        self._keys[api_key] = tier
        self._counts[api_key] = 0
        self._reset_day[api_key] = self._current_day()

    def check(self, api_key: str) -> Tuple[bool, Dict]:
        """Check if request is allowed.

        Returns:
            Tuple of (allowed: bool, info: dict with remaining, limit, tier)
        """
        if api_key not in self._keys:
            return False, {
                "error": "invalid_key",
                "message": "Unknown API key. Register at pulse-gateway.",
            }

        # Reset counter if new day
        current_day = self._current_day()
        if self._reset_day.get(api_key) != current_day:
            self._counts[api_key] = 0
            self._reset_day[api_key] = current_day

        tier = self._keys[api_key]
        limit = self._tiers[tier]
        count = self._counts[api_key]

        if count >= limit:
            return False, {
                "error": "rate_limited",
                "tier": tier,
                "limit": limit,
                "used": count,
                "remaining": 0,
                "message": f"Rate limit exceeded ({limit}/day on {tier} tier). Upgrade for more.",
            }

        self._counts[api_key] = count + 1
        return True, {
            "tier": tier,
            "limit": limit,
            "used": count + 1,
            "remaining": limit - count - 1,
        }

    def get_usage(self, api_key: str) -> Optional[Dict]:
        """Get current usage stats for an API key."""
        if api_key not in self._keys:
            return None

        tier = self._keys[api_key]
        limit = self._tiers[tier]
        count = self._counts.get(api_key, 0)

        return {
            "tier": tier,
            "limit": limit,
            "used": count,
            "remaining": max(0, limit - count),
        }

    def _current_day(self) -> int:
        """Current day as integer (days since epoch)."""
        return int(time.time()) // 86400
