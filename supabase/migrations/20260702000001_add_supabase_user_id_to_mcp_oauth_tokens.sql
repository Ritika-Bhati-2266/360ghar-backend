-- ============================================================
-- 360Ghar Schema — Add supabase_user_id to mcp_oauth_tokens
-- ============================================================
-- Adds the supabase_user_id column to the existing
-- mcp_oauth_tokens table if it does not already exist.
-- ============================================================

ALTER TABLE IF EXISTS public.mcp_oauth_tokens
    ADD COLUMN IF NOT EXISTS supabase_user_id VARCHAR;
