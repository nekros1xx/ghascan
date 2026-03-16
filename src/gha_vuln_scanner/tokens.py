"""
GitHub API token management.

Tokens are loaded ONLY from environment variables — never hardcoded.
Supports multiple tokens via comma-separated GITHUB_TOKEN for higher rate limits.

Usage:
    export GITHUB_TOKEN="your_token_1,your_token_2"
"""

import os
import threading

_TOKENS: list[str] = []
_token_idx = 0
_token_lock = threading.Lock()


def _load_tokens() -> list[str]:
    """Load tokens from GITHUB_TOKEN environment variable."""
    raw = os.environ.get("GITHUB_TOKEN", "")
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def get_tokens() -> list[str]:
    """Get all configured tokens."""
    global _TOKENS
    if not _TOKENS:
        _TOKENS = _load_tokens()
    return _TOKENS


def next_token() -> str | None:
    """Round-robin token selection. Thread-safe."""
    global _token_idx
    tokens = get_tokens()
    if not tokens:
        return None
    with _token_lock:
        token = tokens[_token_idx % len(tokens)]
        _token_idx += 1
    return token


def has_token() -> bool:
    """Check if at least one token is configured."""
    return len(get_tokens()) > 0


def token_count() -> int:
    """Number of configured tokens (used to scale parallelism)."""
    return len(get_tokens())
