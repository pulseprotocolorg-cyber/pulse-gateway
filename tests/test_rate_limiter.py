"""Tests for rate limiter."""

import pytest
from pulse_gateway.rate_limiter import RateLimiter


@pytest.fixture
def limiter():
    rl = RateLimiter()
    rl.register_key("free-key", tier="free")
    rl.register_key("pro-key", tier="pro")
    return rl


class TestRateLimiter:

    def test_allows_valid_key(self, limiter):
        allowed, info = limiter.check("free-key")
        assert allowed is True
        assert info["tier"] == "free"
        assert info["remaining"] == 99

    def test_rejects_unknown_key(self, limiter):
        allowed, info = limiter.check("unknown-key")
        assert allowed is False
        assert info["error"] == "invalid_key"

    def test_tracks_usage(self, limiter):
        limiter.check("free-key")
        limiter.check("free-key")
        limiter.check("free-key")
        usage = limiter.get_usage("free-key")
        assert usage["used"] == 3
        assert usage["remaining"] == 97

    def test_enforces_limit(self, limiter):
        small_limiter = RateLimiter(tiers={"test": 3})
        small_limiter.register_key("test-key", tier="test")
        small_limiter.check("test-key")
        small_limiter.check("test-key")
        small_limiter.check("test-key")
        allowed, info = small_limiter.check("test-key")
        assert allowed is False
        assert info["error"] == "rate_limited"

    def test_pro_has_more_requests(self, limiter):
        _, info = limiter.check("pro-key")
        assert info["limit"] == 10_000

    def test_unknown_tier_raises(self, limiter):
        with pytest.raises(ValueError, match="Unknown tier"):
            limiter.register_key("bad-key", tier="diamond")

    def test_get_usage_unknown_key(self, limiter):
        assert limiter.get_usage("nonexistent") is None

    def test_usage_stats(self, limiter):
        limiter.check("free-key")
        usage = limiter.get_usage("free-key")
        assert usage["tier"] == "free"
        assert usage["limit"] == 100
        assert usage["used"] == 1
