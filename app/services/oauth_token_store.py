"""
OAuth Token Store Service

Manages OAuth tokens, authorization codes, and sessions.

- Access & refresh tokens are stored in PostgreSQL for persistence
  across server restarts (solves the cache-reset problem).
- Authorization codes and OAuth sessions are kept in cache
  (short-lived, ephemeral).
- Client registrations are kept in cache.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import get_cache_manager
from app.core.database import AsyncSessionLocal
from app.core.logging import get_logger
from app.models.oauth_token import OAuthToken

logger = get_logger(__name__)


class OAuthStorageError(Exception):
    """Raised when OAuth token store cannot persist or retrieve security-critical data."""
    pass


class OAuthTokenStore:
    """OAuth token store.

    Tokens (access & refresh) are persisted in PostgreSQL via the
    ``oauth_tokens`` table so they survive server restarts.  Auth codes,
    sessions, and client registrations use the cache (short-lived).
    """

    @staticmethod
    def _key(prefix: str, identifier: str) -> str:
        return f"oauth:{prefix}:{identifier}"

    def _ensure_cache_available(self) -> None:
        from app.core.cache.manager import NullCacheBackend

        cache = get_cache_manager()
        if isinstance(cache.backend, NullCacheBackend):
            raise OAuthStorageError(
                "OAuth token store cannot operate with NullCacheBackend — "
                "configure Redis or in-memory cache for production"
            )

    async def _get_db(self, db: AsyncSession | None = None) -> AsyncSession:
        """Return provided session or create a new one."""
        if db is not None:
            return db
        return AsyncSessionLocal()

    async def _close_db(self, db: AsyncSession, owned: bool) -> None:
        """Close session if we created it."""
        if owned:
            await db.close()

    # ------------------------------------------------------------------
    # Authorization Codes  (cache — short-lived, ephemeral)
    # ------------------------------------------------------------------

    async def store_auth_code(
        self,
        code: str,
        user_id: str,
        client_id: str,
        redirect_uri: str | None,
        scope: str,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        resource: str | None = None,
        expires_in: int = 600,
        supabase_user_id: str | None = None,
    ) -> bool:
        self._ensure_cache_available()
        try:
            cache = get_cache_manager()
            data = {
                "user_id": user_id,
                "supabase_user_id": supabase_user_id,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "resource": resource,
                "created_at": time.time(),
                "expires_at": time.time() + expires_in,
            }
            await cache.set(self._key("auth_code", code), data, ttl=expires_in)
            logger.debug("Stored auth code", extra={"user_id": user_id, "client_id": client_id})
            return True
        except Exception as e:
            logger.error("Failed to store auth code: %s", e)
            raise OAuthStorageError(f"Failed to store auth code: {e}") from e

    async def get_auth_code(self, code: str) -> dict[str, Any] | None:
        """Retrieve and consume an authorization code (one-time use, atomic)."""
        try:
            cache = get_cache_manager()
            key = self._key("auth_code", code)
            data = await cache.get_and_delete(key)
            if data is None:
                logger.debug("Auth code not found or already consumed")
                return None
            if time.time() > data.get("expires_at", 0):
                logger.debug("Auth code expired")
                return None
            logger.debug("Auth code retrieved and consumed", extra={"user_id": data.get("user_id")})
            return dict[str, Any](data)
        except Exception as e:
            logger.error("Failed to get auth code: %s", e)
            raise OAuthStorageError(f"Failed to get auth code: {e}") from e

    async def delete_auth_code(self, code: str) -> bool:
        try:
            cache = get_cache_manager()
            await cache.delete(self._key("auth_code", code))
            return True
        except Exception as e:
            logger.error("Failed to delete auth code: %s", e)
            return False

    # ------------------------------------------------------------------
    # Access & Refresh Tokens  (PostgreSQL — persistent across restarts)
    # ------------------------------------------------------------------

    async def store_oauth_tokens(
        self,
        access_token: str,
        refresh_token: str,
        user_id: str,
        scope: str,
        client_id: str | None = None,
        resource: str | None = None,
        access_token_expires_in: int = 3600,
        refresh_token_expires_in: int = 2592000,
        supabase_user_id: str | None = None,
        db: AsyncSession | None = None,
    ) -> bool:
        """Store a new OAuth token pair in PostgreSQL.

        Optional ``db`` parameter lets callers reuse an existing session;
        otherwise one is created and closed automatically.
        """
        owned = db is None
        session = await self._get_db(db)
        try:
            now = datetime.now(timezone.utc)
            token_row = OAuthToken(
                access_token=access_token,
                refresh_token=refresh_token,
                user_id=int(user_id),
                supabase_user_id=supabase_user_id,
                scope=scope,
                client_id=client_id,
                resource=resource,
                token_type="Bearer",
                access_token_expires_at=now + timedelta(seconds=access_token_expires_in),
                refresh_token_expires_at=now + timedelta(seconds=refresh_token_expires_in),
                is_revoked=False,
            )

            session.add(token_row)
            await session.commit()

            logger.debug("Stored OAuth tokens in DB for user %s", user_id)
            return True
        except Exception as e:
            await session.rollback()
            logger.error("Failed to store OAuth tokens in DB: %s", e)
            raise OAuthStorageError(f"Failed to store OAuth tokens: {e}") from e
        finally:
            await self._close_db(session, owned)

    async def get_access_token(
        self,
        access_token: str,
        db: AsyncSession | None = None,
    ) -> dict[str, Any] | None:
        """Look up an access token in PostgreSQL.

        Optional ``db`` parameter lets callers reuse an existing session.
        """
        owned = db is None
        session = await self._get_db(db)
        try:
            now = datetime.now(timezone.utc)
            result = await session.execute(
                select(OAuthToken).where(
                    OAuthToken.access_token == access_token,
                    OAuthToken.is_revoked == False,  # noqa: E712
                    OAuthToken.access_token_expires_at > now,
                )
            )
            row = result.scalar_one_or_none()
            if row is None:
                logger.debug("Access token not found in DB")
                return None

            logger.debug("Access token found in DB", extra={"user_id": row.user_id})
            return {
                "user_id": str(row.user_id),
                "supabase_user_id": row.supabase_user_id,
                "scope": row.scope,
                "client_id": row.client_id,
                "resource": row.resource,
                "token_type": row.token_type,
                "created_at": row.created_at.timestamp() if row.created_at else 0,
                "expires_at": row.access_token_expires_at.timestamp(),
                "refresh_token": row.refresh_token,
            }
        except Exception as e:
            logger.error("Failed to get access token from DB: %s", e)
            return None
        finally:
            await self._close_db(session, owned)

    async def get_refresh_token(
        self,
        refresh_token: str,
        db: AsyncSession | None = None,
    ) -> dict[str, Any] | None:
        """Look up a refresh token in PostgreSQL."""
        owned = db is None
        session = await self._get_db(db)
        try:
            now = datetime.now(timezone.utc)
            result = await session.execute(
                select(OAuthToken).where(
                    OAuthToken.refresh_token == refresh_token,
                    OAuthToken.is_revoked == False,  # noqa: E712
                    OAuthToken.refresh_token_expires_at > now,
                )
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None

            return {
                "user_id": str(row.user_id),
                "supabase_user_id": row.supabase_user_id,
                "scope": row.scope,
                "client_id": row.client_id,
                "resource": row.resource,
                "created_at": row.created_at.timestamp() if row.created_at else 0,
                "expires_at": row.refresh_token_expires_at.timestamp(),
                "access_token": row.access_token,
            }
        except Exception as e:
            logger.error("Failed to get refresh token from DB: %s", e)
            return None
        finally:
            await self._close_db(session, owned)

    async def revoke_token(
        self,
        token: str,
        db: AsyncSession | None = None,
    ) -> bool:
        """Mark an access token as revoked in PostgreSQL."""
        owned = db is None
        session = await self._get_db(db)
        try:
            result = await session.execute(
                select(OAuthToken).where(
                    OAuthToken.access_token == token,
                    OAuthToken.is_revoked == False,  # noqa: E712
                )
            )
            row = result.scalar_one_or_none()
            if row:
                row.is_revoked = True
                await session.commit()
                logger.debug("Revoked access token")
            return True
        except Exception as e:
            await session.rollback()
            logger.error("Failed to revoke access token: %s", e)
            return False
        finally:
            await self._close_db(session, owned)

    async def delete_refresh_token(
        self,
        refresh_token: str,
        db: AsyncSession | None = None,
    ) -> bool:
        """Mark a refresh token as revoked in PostgreSQL."""
        owned = db is None
        session = await self._get_db(db)
        try:
            result = await session.execute(
                select(OAuthToken).where(
                    OAuthToken.refresh_token == refresh_token,
                    OAuthToken.is_revoked == False,  # noqa: E712
                )
            )
            row = result.scalar_one_or_none()
            if row:
                row.is_revoked = True
                await session.commit()
            return True
        except Exception as e:
            await session.rollback()
            logger.error("Failed to delete refresh token: %s", e)
            return False
        finally:
            await self._close_db(session, owned)

    async def revoke_refresh_token(
        self,
        refresh_token: str,
        db: AsyncSession | None = None,
    ) -> bool:
        """Revoke a refresh token and its paired access token."""
        owned = db is None
        session = await self._get_db(db)
        try:
            result = await session.execute(
                select(OAuthToken).where(
                    OAuthToken.refresh_token == refresh_token,
                    OAuthToken.is_revoked == False,  # noqa: E712
                )
            )
            row = result.scalar_one_or_none()
            if row:
                row.is_revoked = True
                # Also find and revoke the paired token if stored separately
                paired = await session.execute(
                    select(OAuthToken).where(
                        OAuthToken.access_token == row.access_token,
                        OAuthToken.is_revoked == False,  # noqa: E712
                    )
                )
                paired_row = paired.scalar_one_or_none()
                if paired_row and paired_row.id != row.id:
                    paired_row.is_revoked = True
                await session.commit()
            return True
        except Exception as e:
            await session.rollback()
            logger.error("Failed to revoke refresh token: %s", e)
            return False
        finally:
            await self._close_db(session, owned)

    async def revoke_token_pair(
        self,
        *,
        access_token: str | None = None,
        refresh_token: str | None = None,
        db: AsyncSession | None = None,
    ) -> bool:
        """Revoke both access and refresh tokens by either token value."""
        owned = db is None
        session = await self._get_db(db)
        try:
            if access_token:
                result = await session.execute(
                    select(OAuthToken).where(
                        OAuthToken.access_token == access_token,
                        OAuthToken.is_revoked == False,  # noqa: E712
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    row.is_revoked = True
                    # Also revoke any paired row by refresh token
                    paired = await session.execute(
                        select(OAuthToken).where(
                            OAuthToken.refresh_token == row.refresh_token,
                            OAuthToken.is_revoked == False,  # noqa: E712
                        )
                    )
                    for pr in paired.scalars().all():
                        if pr.id != row.id:
                            pr.is_revoked = True

            if refresh_token:
                result = await session.execute(
                    select(OAuthToken).where(
                        OAuthToken.refresh_token == refresh_token,
                        OAuthToken.is_revoked == False,  # noqa: E712
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    row.is_revoked = True

            await session.commit()
            return True
        except Exception as e:
            await session.rollback()
            logger.error("Failed to revoke token pair: %s", e)
            return False
        finally:
            await self._close_db(session, owned)

    # ------------------------------------------------------------------
    # OAuth Sessions
    # ------------------------------------------------------------------

    async def store_oauth_session(
        self,
        session_id: str,
        client_id: str,
        redirect_uri: str | None,
        scope: str,
        state: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        resource: str | None = None,
        expires_in: int = 1800,
    ) -> bool:
        self._ensure_cache_available()
        try:
            cache = get_cache_manager()
            data = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "resource": resource,
                "created_at": time.time(),
                "expires_at": time.time() + expires_in,
            }
            await cache.set(self._key("session", session_id), data, ttl=expires_in)
            return True
        except Exception as e:
            logger.error("Failed to store OAuth session: %s", e)
            raise OAuthStorageError(f"Failed to store OAuth session: {e}") from e

    async def get_oauth_session(self, session_id: str) -> dict[str, Any] | None:
        try:
            cache = get_cache_manager()
            data = await cache.get(self._key("session", session_id))
            if data is None:
                return None
            if time.time() > data.get("expires_at", 0):
                await cache.delete(self._key("session", session_id))
                return None
            return dict[str, Any](data)
        except Exception as e:
            logger.error("Failed to get OAuth session: %s", e)
            return None

    async def delete_session(self, session_id: str) -> bool:
        try:
            cache = get_cache_manager()
            await cache.delete(self._key("session", session_id))
            return True
        except Exception as e:
            logger.error("Failed to delete OAuth session: %s", e)
            return False

    # ------------------------------------------------------------------
    # Dynamic Client Registration (RFC 7591)
    # ------------------------------------------------------------------

    async def store_client(
        self,
        client_id: str,
        metadata: dict[str, Any],
        expires_in: int | None = None,
    ) -> bool:
        try:
            cache = get_cache_manager()
            data = {
                **metadata,
                "client_id": client_id,
                "client_id_issued_at": int(time.time()),
            }
            if expires_in:
                data["expires_at"] = time.time() + expires_in
                await cache.set(self._key("client", client_id), data, ttl=expires_in)
            else:
                # No expiry — use a very long TTL (10 years) since CacheManager requires one
                await cache.set(self._key("client", client_id), data, ttl=315360000)
            logger.info("Stored OAuth client: %s", client_id)
            return True
        except Exception as e:
            logger.error("Failed to store OAuth client: %s", e)
            raise OAuthStorageError(f"Failed to store OAuth client: {e}") from e

    async def get_client(self, client_id: str) -> dict[str, Any] | None:
        try:
            cache = get_cache_manager()
            data = await cache.get(self._key("client", client_id))
            if data is None:
                return None
            if "expires_at" in data and time.time() > data["expires_at"]:
                await cache.delete(self._key("client", client_id))
                return None
            # Sanitize optional string fields
            for field in ["client_uri", "logo_uri"]:
                if field in data and data[field] is None:
                    data[field] = ""
            return dict[str, Any](data)
        except Exception as e:
            logger.error("Failed to get OAuth client: %s", e)
            return None

    async def delete_client(self, client_id: str) -> bool:
        try:
            cache = get_cache_manager()
            await cache.delete(self._key("client", client_id))
            logger.info("Deleted OAuth client: %s", client_id)
            return True
        except Exception as e:
            logger.error("Failed to delete OAuth client: %s", e)
            return False


# Global token store instance
oauth_token_store = OAuthTokenStore()
