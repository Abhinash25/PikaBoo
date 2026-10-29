-- Fix application/database mismatch for WireGuard peer lifecycle
-- Intended lifecycle: active / inactive / revoked

ALTER TYPE peer_status RENAME VALUE 'dormant' TO 'inactive';
