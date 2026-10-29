-- ============================================================================
-- PRIVACY GATEWAY — INITIAL SCHEMA MIGRATION (001_initial_schema.sql)
-- Phase 1 Foundation: Core Relational Tables, Security Constraints, & Indexes
-- ============================================================================

-- Security Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Migration Tracking Table
CREATE TABLE IF NOT EXISTS _migrations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    checksum VARCHAR(64)
);

-- Enumerations
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('user', 'admin', 'auditor');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE auth_provider AS ENUM ('google', 'email_password', 'github', 'apple');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE subscription_tier AS ENUM ('free', 'premium', 'business');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE subscription_status AS ENUM ('active', 'past_due', 'canceled', 'trialing');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE peer_status AS ENUM ('active', 'revoked', 'dormant');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE leak_verdict AS ENUM ('safe', 'warning', 'leak_detected');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE risk_level AS ENUM ('low', 'medium', 'high');
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    avatar_url TEXT,
    role user_role DEFAULT 'user' NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    data_retention_days INTEGER DEFAULT 30 NOT NULL CHECK (data_retention_days BETWEEN 1 AND 365),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 2. Authentication Accounts (OIDC / OAuth identities)
CREATE TABLE IF NOT EXISTS authentication_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider auth_provider NOT NULL,
    provider_subject_id VARCHAR(255) NOT NULL,
    email_at_provider VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE(provider, provider_subject_id)
);

-- 3. User Sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(128) NOT NULL UNIQUE,
    user_agent TEXT,
    client_ip_anonymized INET,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 4. Registered Devices
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(100) NOT NULL,
    device_type VARCHAR(50) NOT NULL,
    client_version VARCHAR(20) NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE NOT NULL,
    last_active_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 5. VPN Server Infrastructure Nodes
CREATE TABLE IF NOT EXISTS vpn_servers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_name VARCHAR(100) NOT NULL,
    country_code VARCHAR(2) NOT NULL,
    city VARCHAR(100) NOT NULL,
    public_endpoint VARCHAR(255) NOT NULL,
    wireguard_public_key VARCHAR(44) NOT NULL,
    ipv4_subnet CIDR NOT NULL,
    ipv6_subnet CIDR,
    capacity_peers INTEGER DEFAULT 250 NOT NULL,
    current_active_peers INTEGER DEFAULT 0 NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_maintenance BOOLEAN DEFAULT FALSE NOT NULL,
    health_status VARCHAR(20) DEFAULT 'healthy' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 6. WireGuard Peers (Public keys strictly separated from private keys)
CREATE TABLE IF NOT EXISTS wireguard_peers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    vpn_server_id UUID NOT NULL REFERENCES vpn_servers(id) ON DELETE RESTRICT,
    public_key VARCHAR(44) UNIQUE NOT NULL,
    allocated_ipv4 INET UNIQUE NOT NULL,
    allocated_ipv6 INET UNIQUE,
    status peer_status DEFAULT 'active' NOT NULL,
    total_rx_bytes BIGINT DEFAULT 0 NOT NULL,
    total_tx_bytes BIGINT DEFAULT 0 NOT NULL,
    last_handshake_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 7. Subscriptions & Plan Tiers
CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tier subscription_tier DEFAULT 'free' NOT NULL,
    status subscription_status DEFAULT 'active' NOT NULL,
    payment_provider VARCHAR(50),
    external_subscription_id VARCHAR(255),
    max_devices INTEGER DEFAULT 2 NOT NULL,
    current_period_start TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    current_period_end TIMESTAMPTZ DEFAULT (CURRENT_TIMESTAMP + INTERVAL '30 days') NOT NULL,
    canceled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 8. Privacy Scans & Snapshots
CREATE TABLE IF NOT EXISTS privacy_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    overall_score INTEGER NOT NULL CHECK (overall_score BETWEEN 0 AND 100),
    network_privacy_score INTEGER NOT NULL CHECK (network_privacy_score BETWEEN 0 AND 100),
    tracking_exposure_score INTEGER NOT NULL CHECK (tracking_exposure_score BETWEEN 0 AND 100),
    fingerprint_risk_score INTEGER NOT NULL CHECK (fingerprint_risk_score BETWEEN 0 AND 100),
    leak_protection_score INTEGER NOT NULL CHECK (leak_protection_score BETWEEN 0 AND 100),
    dns_leak_verdict leak_verdict NOT NULL,
    webrtc_leak_verdict leak_verdict NOT NULL,
    trackers_blocked_total INTEGER DEFAULT 0 NOT NULL,
    scan_explanation JSONB DEFAULT '{}'::JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 9. Privacy Events
CREATE TABLE IF NOT EXISTS privacy_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'info' NOT NULL,
    description TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 10. Immutable Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    target_resource VARCHAR(100) NOT NULL,
    target_id UUID,
    ip_address_anonymized INET,
    metadata JSONB DEFAULT '{}'::JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_user_sessions_lookup ON user_sessions(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_wg_peers_server_active ON wireguard_peers(vpn_server_id, status);
CREATE INDEX IF NOT EXISTS idx_privacy_scans_user_time ON privacy_scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_privacy_events_user_time ON privacy_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_time ON audit_logs(actor_user_id, created_at DESC);
