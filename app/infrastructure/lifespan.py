"""Application lifespan wiring and startup job orchestration."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from sqlalchemy import text

from app.config import settings
from app.core.cache import initialize_cache, shutdown_cache
from app.core.database import bg_engine, engine, mark_engines_disposing
from app.core.http import close_all_clients as close_all_http_clients
from app.core.logging import get_logger
from app.infrastructure.scheduler import shutdown_scheduler, start_scheduler

logger = get_logger(__name__)

LifespanFactory = Callable[[FastAPI], Any]


def create_lifespan(testing: bool, user_mcp_app: Any, admin_mcp_app: Any) -> LifespanFactory:
    """Create the FastAPI lifespan manager with existing startup semantics."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Enter each MCP app's lifespan in *this* server async context. The
        # lifespan() context manager builds the concrete app and enters its
        # inner lifespan (starting the StreamableHTTPSessionManager task
        # group), so both enter and exit happen in the same context — avoiding
        # the "ValueError: was created in a different Context" that lazy
        # request-time init would otherwise cause.
        async with user_mcp_app.lifespan(app):
            async with admin_mcp_app.lifespan(app):
                if not testing:
                    # Fail-fast config check runs OUTSIDE the degraded-mode
                    # try/except below: a placeholder Apple Team ID in
                    # production must abort startup, not be logged-and-ignored.
                    # It raises before the cache / DB initialize.
                    _validate_deeplink_config()
                try:
                    if not testing:
                        await _initialize_cache()
                        await _verify_database_ready()
                        await _apply_pending_migrations()
                        await _prewarm_supabase_dns()
                        _register_scheduler_jobs(app)
                        start_scheduler()
                except Exception as exc:
                    logger.error("Application startup failed: %s", exc)

                logger.info(
                    "API started",
                    extra={
                        "event": "startup",
                        "env": settings.ENVIRONMENT,
                        "version": settings.APP_VERSION,
                        "mcp_servers": ["/mcp", "/mcp-admin"],
                        "serverless": settings.SERVERLESS_ENABLED,
                    },
                )

                yield

                # ---- Graceful shutdown ----
                if not testing:
                    shutdown_scheduler()
                    await _shutdown_ai_providers()
                    await _shutdown_shared_http_clients()
                    await close_all_http_clients()
                    _shutdown_notification_executor()
                    await _shutdown_cache()
                mark_engines_disposing()
                await engine.dispose()
                await bg_engine.dispose()
                logger.info("API shutdown", extra={"event": "shutdown"})

    return lifespan


async def _apply_pending_migrations() -> None:
    """Run lightweight one-off DDL that cannot be applied via Supabase CLI migrations."""
    from sqlalchemy import text

    async with engine.begin() as conn:
        for label, sql in (
            (
                "image_category: add floor_plan",
                "ALTER TYPE image_category ADD VALUE IF NOT EXISTS 'floor_plan'",
            ),
            (
                "leases: add termination_date",
                "ALTER TABLE public.leases ADD COLUMN IF NOT EXISTS termination_date date",
            ),
            (
                "leases: add termination_reason",
                "ALTER TABLE public.leases ADD COLUMN IF NOT EXISTS termination_reason text",
            ),
            (
                "tours: create visibility type",
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tour_visibility') THEN
                        CREATE TYPE tour_visibility AS ENUM ('private', 'unlisted', 'public');
                    END IF;
                END$$;
                """
            ),
            (
                "tours: add visibility column",
                "ALTER TABLE public.tours ADD COLUMN IF NOT EXISTS visibility public.tour_visibility NOT NULL DEFAULT 'private'"
            ),
            (
                "tours: migrate is_public to visibility",
                """
                UPDATE public.tours
                SET visibility = CASE
                    WHEN is_public = true THEN 'public'::public.tour_visibility
                    ELSE 'private'::public.tour_visibility
                END
                WHERE visibility = 'private' AND is_public = true
                """
            ),
            (
                "tours: create visibility index",
                "CREATE INDEX IF NOT EXISTS idx_tours_visibility ON public.tours(visibility)"
            ),
            (
                "tours: create status_visibility index",
                "CREATE INDEX IF NOT EXISTS idx_tours_status_visibility ON public.tours(status, visibility) WHERE deleted_at IS NULL"
            ),
            (
                "oauth_tokens: create table",
                """
                CREATE TABLE IF NOT EXISTS public.oauth_tokens (
                    id SERIAL PRIMARY KEY,
                    access_token VARCHAR(255) NOT NULL UNIQUE,
                    refresh_token VARCHAR(255) NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
                    supabase_user_id VARCHAR,
                    scope VARCHAR NOT NULL,
                    client_id VARCHAR,
                    resource VARCHAR,
                    token_type VARCHAR(50) DEFAULT 'Bearer',
                    access_token_expires_at TIMESTAMPTZ NOT NULL,
                    refresh_token_expires_at TIMESTAMPTZ NOT NULL,
                    is_revoked BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );
                CREATE INDEX IF NOT EXISTS idx_oauth_tokens_access_token ON public.oauth_tokens(access_token);
                CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh_token ON public.oauth_tokens(refresh_token);
                CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON public.oauth_tokens(user_id);
                """
            ),
            (
                "mcp_oauth_tokens: create table",
                """
                CREATE TABLE IF NOT EXISTS public.mcp_oauth_tokens (
                    id SERIAL PRIMARY KEY,
                    access_token VARCHAR(255) NOT NULL UNIQUE,
                    refresh_token VARCHAR(255) NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
                    supabase_user_id VARCHAR,
                    scope VARCHAR NOT NULL,
                    client_id VARCHAR,
                    resource VARCHAR,
                    token_type VARCHAR(50) DEFAULT 'Bearer',
                    access_token_expires_at TIMESTAMPTZ NOT NULL,
                    refresh_token_expires_at TIMESTAMPTZ NOT NULL,
                    is_revoked BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ
                );
                CREATE INDEX IF NOT EXISTS idx_mcp_oauth_tokens_access_token ON public.mcp_oauth_tokens(access_token);
                CREATE INDEX IF NOT EXISTS idx_mcp_oauth_tokens_refresh_token ON public.mcp_oauth_tokens(refresh_token);
                CREATE INDEX IF NOT EXISTS idx_mcp_oauth_tokens_user_id ON public.mcp_oauth_tokens(user_id);
                """
            ),
            (
                "mcp_oauth_tokens: add supabase_user_id column",
                """
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = 'public' AND table_name = 'mcp_oauth_tokens'
                    ) AND NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'public'
                          AND table_name = 'mcp_oauth_tokens'
                          AND column_name = 'supabase_user_id'
                    ) THEN
                        ALTER TABLE public.mcp_oauth_tokens ADD COLUMN supabase_user_id VARCHAR;
                    END IF;
                END $$;
                """
            ),
        ):
            try:
                await conn.execute(text(sql))
                logger.info("Startup migration applied: %s", label)
            except Exception as exc:
                logger.warning("Startup migration skipped (%s): %s", label, exc)


async def _initialize_cache() -> None:
    try:
        await initialize_cache()
    except Exception as cache_e:
        logger.warning("Cache connection skipped/failed: %s", cache_e)


def _validate_deeplink_config() -> None:
    """Run the deep-link startup validator.

    In production (``DEEPLINK_FAIL_ON_PLACEHOLDER=True``) this raises if
    ``DEEPLINK_APPLE_TEAM_ID`` is the placeholder or otherwise malformed.
    In dev/CI it just logs a warning. Imported lazily so the module is
    only loaded when startup actually runs (avoids a top-level import of
    ``app.services.deeplinks`` from the lifespan module).
    """
    from app.services.deeplinks.validation import validate_deeplink_config

    validate_deeplink_config()


async def _verify_database_ready() -> None:
    """Probe the database before accepting requests.

    Ensures the connection pool can check out a connection and execute a
    simple query. Logs a warning (but does not block startup) if the probe
    fails after retries, so the app can still start in degraded mode.
    """
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            async with asyncio.timeout(5):
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
            logger.info("Database readiness check passed (attempt %d)", attempt)
            return
        except Exception as exc:
            if attempt < max_attempts:
                logger.warning(
                    "Database readiness check failed (attempt %d/%d): %s",
                    attempt,
                    max_attempts,
                    exc,
                )
                await asyncio.sleep(1.0 * attempt)
            else:
                logger.error(
                    "Database readiness check failed after %d attempts: %s. "
                    "App will start but requests may fail.",
                    max_attempts,
                    exc,
                )


async def _prewarm_supabase_dns() -> None:
    """Resolve ``settings.SUPABASE_URL`` once at startup.

    Uses the running event loop's ``getaddrinfo`` (same resolver as
    httpx) so a misconfigured ``/etc/hosts`` or broken DNS surfaces in
    the startup log instead of only on the first authenticated request.
    Failures are logged at WARNING and do not block startup.
    """
    raw = settings.SUPABASE_URL
    if not raw:
        return
    host = raw.split("//", 1)[-1].split("/", 1)[0]
    if not host:
        return
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addrs = [info[4][0] for info in infos[:3]]
        logger.info(
            "Supabase DNS prewarm OK: %s -> %s",
            host,
            addrs,
            extra={"event": "supabase_dns_prewarm", "host": host, "addrs": addrs},
        )
    except (socket.gaierror, OSError) as exc:
        logger.warning(
            "Supabase DNS prewarm failed for %s: %s",
            host,
            exc,
            extra={"event": "supabase_dns_prewarm_failed", "host": host},
        )


async def _shutdown_cache() -> None:
    try:
        await shutdown_cache()
    except Exception as cache_e:
        logger.warning("Cache disconnect skipped/failed: %s", cache_e)


def _register_scheduler_jobs(app: FastAPI) -> None:
    """Register all scheduler jobs on the shared APScheduler, then start it."""
    if settings.SERVERLESS_ENABLED:
        logger.info(
            "Serverless mode enabled — skipping in-process schedulers "
            "to allow scale-to-zero. Move cron work to Railway cron jobs."
        )
        return

    _register_blog_publish_job(app)
    _register_notification_job(app)
    _register_vector_sync_job(app)
    _register_data_hub_jobs(app)


def _register_blog_publish_job(app: FastAPI) -> None:
    try:
        from app.services.blog_auto_publish_scheduler import start_auto_blog_publish_scheduler

        start_auto_blog_publish_scheduler(app)
    except Exception as sched_blog_e:
        logger.error("Failed to register blog publish scheduler: %s", sched_blog_e, exc_info=True)


def _register_notification_job(app: FastAPI) -> None:
    try:
        from app.services.notification_scheduler import start_notification_scheduler

        start_notification_scheduler(app)
    except Exception as sched_e:
        logger.error("Failed to register notification scheduler: %s", sched_e, exc_info=True)


def _register_vector_sync_job(app: FastAPI) -> None:
    try:
        from app.services.vector_sync_scheduler import start_vector_sync_scheduler

        start_vector_sync_scheduler(app)
    except Exception as sched_vec_e:
        logger.error("Failed to register vector sync scheduler: %s", sched_vec_e, exc_info=True)


def _register_data_hub_jobs(app: FastAPI) -> None:
    try:
        from app.services.data_hub_scheduler import start_data_hub_scheduler

        start_data_hub_scheduler(app)
    except Exception as sched_dh_e:
        logger.error("Failed to register data hub scheduler: %s", sched_dh_e, exc_info=True)


async def _shutdown_ai_providers() -> None:
    """Close cached AI provider HTTP clients."""
    try:
        from app.services.ai import close_all_providers
        await close_all_providers()
    except Exception as e:
        logger.warning("Failed to close AI providers: %s", e)


async def _shutdown_shared_http_clients() -> None:
    """Close reusable service HTTP clients (FCM, SMS)."""
    try:
        from app.services.notifications.fcm import close_fcm_client
        from app.services.sms import close_sms_client

        await close_fcm_client()
        await close_sms_client()
    except Exception as e:
        logger.warning("Failed to close shared HTTP clients: %s", e)


def _shutdown_notification_executor() -> None:
    """Shut down the notification thread pool."""
    try:
        from app.services.notifications.helpers import shutdown_executor
        shutdown_executor()
    except Exception as e:
        logger.warning("Failed to shutdown notification executor: %s", e)
