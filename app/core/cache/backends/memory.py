"""
Thread-safe in-memory cache with LRU eviction and TTL support.
Uses asyncio.Lock for async safety and OrderedDict for LRU ordering.
"""

from __future__ import annotations

import asyncio
import fnmatch
import pickle
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from app.core.cache.interface import CacheStats
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CacheEntry:
    """Single cache entry with value and expiration tracking."""

    value: Any
    expires_at: float | None  # Unix timestamp, None = no expiry
    created_at: float

    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class InMemoryCacheBackend:
    """Thread-safe in-memory LRU cache implementation.

    Features:
    - LRU eviction when max_size is reached
    - Per-key TTL support
    - Pattern-based invalidation using fnmatch
    - Thread-safe via asyncio.Lock
    - Automatic cleanup of expired entries

    Note: This implementation uses class-level shared state so all
    instances share the same underlying cache storage.  Even if the
    CacheManager singleton is bypassed or multiple CacheManager
    instances are created, a single in-memory cache is used across
    all requests.
    Use Redis for distributed multi-process deployments.
    """

    _shared_cache: OrderedDict[str, CacheEntry] | None = None
    _shared_lock: asyncio.Lock | None = None
    _shared_stats: CacheStats | None = None
    _cleanup_task: asyncio.Task | None = None
    _available: bool = False

    def __init__(
        self,
        max_size: int = 1000,
        default_ttl: int = 300,
        cleanup_interval: int = 300,
        max_entry_bytes: int = 1_000_000,
    ):
        """Initialize in-memory cache.

        Uses class-level shared storage so all instances see the same data.
        Only the first call initialises the shared OrderedDict and Lock;
        subsequent instances reuse them.

        Args:
            max_size: Maximum number of entries before LRU eviction
            default_ttl: Default TTL in seconds for entries without explicit TTL
            cleanup_interval: Interval in seconds for background cleanup of expired entries
            max_entry_bytes: Maximum serialized entry size accepted into memory
        """
        if InMemoryCacheBackend._shared_cache is None:
            InMemoryCacheBackend._shared_cache = OrderedDict()
        if InMemoryCacheBackend._shared_lock is None:
            InMemoryCacheBackend._shared_lock = asyncio.Lock()
        if InMemoryCacheBackend._shared_stats is None:
            InMemoryCacheBackend._shared_stats = CacheStats()

        self._max_size = max_size
        self._default_ttl = default_ttl
        self._cleanup_interval = cleanup_interval
        self._max_entry_bytes = max_entry_bytes

    async def connect(self) -> None:
        """Start the background cleanup task (idempotent)."""
        InMemoryCacheBackend._available = True
        if InMemoryCacheBackend._cleanup_task is None:
            InMemoryCacheBackend._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        logger.info(
            "In-memory cache initialized",
            extra={"max_size": self._max_size, "default_ttl": self._default_ttl},
        )

    async def disconnect(self) -> None:
        """Stop cleanup task and clear cache."""
        InMemoryCacheBackend._available = False
        if InMemoryCacheBackend._cleanup_task:
            InMemoryCacheBackend._cleanup_task.cancel()
            try:
                await InMemoryCacheBackend._cleanup_task
            except asyncio.CancelledError:
                pass
            InMemoryCacheBackend._cleanup_task = None
        async with self._lock:
            self._cache.clear()
        logger.info("In-memory cache disconnected")

    def is_available(self) -> bool:
        """Check if cache is available."""
        return InMemoryCacheBackend._available

    @property
    def _cache(self) -> OrderedDict[str, CacheEntry]:
        return InMemoryCacheBackend._shared_cache

    @property
    def _lock(self) -> asyncio.Lock:
        return InMemoryCacheBackend._shared_lock

    @property
    def stats(self) -> CacheStats:
        return InMemoryCacheBackend._shared_stats

    async def get(self, key: str) -> Any | None:
        """Get value, updating LRU order on access."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self.stats.misses += 1
                return None

            if entry.is_expired():
                del self._cache[key]
                self.stats.misses += 1
                return None

            self._cache.move_to_end(key)
            self.stats.hits += 1
            return entry.value

    async def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        """Set value with optional TTL, evicting LRU if needed."""
        try:
            size = len(pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL))
            if size > self._max_entry_bytes:
                logger.debug(
                    "In-memory cache rejected oversized value",
                    extra={"key": key, "limit": self._max_entry_bytes, "size": size},
                )
                return False

            ttl = ttl if ttl is not None else self._default_ttl
            expires_at = time.time() + ttl if ttl > 0 else None

            async with self._lock:
                if key in self._cache:
                    del self._cache[key]

                while len(self._cache) >= self._max_size:
                    evicted_key, _ = self._cache.popitem(last=False)
                    logger.debug("LRU eviction: %s", evicted_key)

                self._cache[key] = CacheEntry(
                    value=value,
                    expires_at=expires_at,
                    created_at=time.time(),
                )

            self.stats.sets += 1
            return True
        except Exception as e:
            logger.error("In-memory cache set error: %s", e)
            self.stats.errors += 1
            return False

    async def get_and_delete(self, key: str) -> Any | None:
        """Atomically get value and delete key under the same lock."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            if entry.is_expired():
                del self._cache[key]
                self.stats.misses += 1
                return None
            value = entry.value
            del self._cache[key]
            self.stats.hits += 1
            self.stats.deletes += 1
            return value

    async def delete(self, key: str) -> bool:
        """Delete single key."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                self.stats.deletes += 1
                return True
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """Delete keys matching fnmatch pattern (e.g., 'properties:*')."""
        deleted = 0
        async with self._lock:
            keys_to_delete = [
                k for k in self._cache.keys() if fnmatch.fnmatch(k, pattern)
            ]
            for key in keys_to_delete:
                del self._cache[key]
                deleted += 1

        self.stats.deletes += deleted
        if deleted > 0:
            logger.debug("Pattern delete '%s': %s keys removed", pattern, deleted)
        return deleted

    async def exists(self, key: str) -> bool:
        """Check if non-expired key exists."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False
            if entry.is_expired():
                del self._cache[key]
                return False
            return True

    async def clear(self) -> bool:
        """Clear all entries."""
        async with self._lock:
            count = len(self._cache)
            self._cache.clear()
        logger.info("In-memory cache cleared: %s entries", count)
        return True

    async def _periodic_cleanup(self) -> None:
        """Background task to remove expired entries."""
        while InMemoryCacheBackend._available:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Cleanup task error: %s", e)

    async def _cleanup_expired(self) -> None:
        """Remove all expired entries."""
        async with self._lock:
            expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
            for key in expired_keys:
                del self._cache[key]

        if expired_keys:
            logger.debug("Cleaned up %s expired entries", len(expired_keys))

    def get_size(self) -> int:
        """Current number of entries (approximate, not locked)."""
        return len(self._cache)

    def get_stats(self) -> dict:
        """Get cache statistics including size info."""
        stats = self.stats.to_dict()
        stats["size"] = self.get_size()
        stats["max_size"] = self._max_size
        stats["max_entry_bytes"] = self._max_entry_bytes
        return stats
