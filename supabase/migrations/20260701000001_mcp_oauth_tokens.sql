-- ============================================================
-- 360Ghar Schema — MCP OAuth Tokens
-- ============================================================
-- Stores OAuth 2.1 access and refresh tokens for MCP
-- authentication. Tokens are persisted in PostgreSQL so they
-- survive server restarts (cache-reset safety for auth codes,
-- sessions, and client registrations is handled separately).
-- ============================================================

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

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_tokens_access_token
    ON public.mcp_oauth_tokens(access_token);

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_tokens_refresh_token
    ON public.mcp_oauth_tokens(refresh_token);

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_tokens_user_id
    ON public.mcp_oauth_tokens(user_id);
