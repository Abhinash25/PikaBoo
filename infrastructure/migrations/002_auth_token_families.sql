-- ============================================================================
-- PRIVACY GATEWAY — MIGRATION 002: AUTH TOKEN FAMILIES & IP REMOVAL
-- Phase 2 Foundation: Token Family Rotation, Replay Detection & IP Minimization
-- ============================================================================

-- 1. Add family_id and last_used_at to user_sessions
ALTER TABLE user_sessions 
    ADD COLUMN IF NOT EXISTS family_id UUID DEFAULT uuid_generate_v4() NOT NULL,
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL;

-- 2. Drop client_ip_anonymized to uphold complete IP minimization mandate
ALTER TABLE user_sessions 
    DROP COLUMN IF EXISTS client_ip_anonymized;

-- 3. Token rotation history table for detecting replayed/stolen refresh tokens
CREATE TABLE IF NOT EXISTS session_token_history (
    id SERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    token_hash VARCHAR(128) NOT NULL,
    rotated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 4. Optimized indexes
CREATE INDEX IF NOT EXISTS idx_user_sessions_family ON user_sessions(family_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active_hash ON user_sessions(refresh_token_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_token_history_hash ON session_token_history(token_hash);
