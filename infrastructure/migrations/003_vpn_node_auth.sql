-- ============================================================================
-- PRIVACY GATEWAY - MIGRATION 003: VPN SERVER AUTHENTICATION
-- Phase 3 Foundation: Authenticated Data Plane Nodes
-- ============================================================================

-- Add hashed authentication token to vpn_servers table
ALTER TABLE vpn_servers 
    ADD COLUMN IF NOT EXISTS node_api_token_hash VARCHAR(255);

-- In Phase 3 MVP, we have one pre-configured server. We'll populate its token hash if it doesn't exist.
-- (The actual token will be handled securely via ENV on the node).
