/**
 * Privacy Gateway PostgreSQL Relational Entities
 * Phase 1 Database Model
 */

export type UserRole = 'user' | 'admin' | 'auditor';
export type AuthProvider = 'google' | 'email_password' | 'github' | 'apple';
export type SubscriptionTier = 'free' | 'premium' | 'business';
export type SubscriptionStatus = 'active' | 'past_due' | 'canceled' | 'trialing';
export type PeerStatus = 'active' | 'revoked' | 'dormant';
export type LeakVerdict = 'safe' | 'warning' | 'leak_detected';
export type RiskLevel = 'low' | 'medium' | 'high';

export interface UserEntity {
  id: string;
  email: string;
  display_name: string | null;
  avatar_url: string | null;
  role: UserRole;
  is_active: boolean;
  data_retention_days: number;
  created_at: string;
  updated_at: string;
}

export interface AuthenticationAccountEntity {
  id: string;
  user_id: string;
  provider: AuthProvider;
  provider_subject_id: string;
  email_at_provider: string | null;
  created_at: string;
}

export interface UserSessionEntity {
  id: string;
  user_id: string;
  refresh_token_hash: string;
  user_agent: string | null;
  client_ip_anonymized: string | null;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
}

export interface DeviceEntity {
  id: string;
  user_id: string;
  device_name: string;
  device_type: 'windows' | 'macos' | 'linux' | 'android' | 'ios';
  client_version: string;
  is_revoked: boolean;
  last_active_at: string;
  created_at: string;
}

export interface VpnServerEntity {
  id: string;
  node_name: string;
  country_code: string;
  city: string;
  public_endpoint: string;
  wireguard_public_key: string;
  ipv4_subnet: string;
  ipv6_subnet: string | null;
  capacity_peers: number;
  current_active_peers: number;
  is_active: boolean;
  is_maintenance: boolean;
  health_status: 'healthy' | 'degraded' | 'unhealthy' | 'maintenance';
  created_at: string;
}

export interface WireguardPeerEntity {
  id: string;
  user_id: string;
  device_id: string | null;
  vpn_server_id: string;
  public_key: string;
  allocated_ipv4: string;
  allocated_ipv6: string | null;
  status: PeerStatus;
  total_rx_bytes: number;
  total_tx_bytes: number;
  last_handshake_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SubscriptionEntity {
  id: string;
  user_id: string;
  tier: SubscriptionTier;
  status: SubscriptionStatus;
  payment_provider: string | null;
  external_subscription_id: string | null;
  max_devices: number;
  current_period_start: string;
  current_period_end: string;
  canceled_at: string | null;
  created_at: string;
}

export interface PrivacyScanEntity {
  id: string;
  user_id: string;
  device_id: string | null;
  overall_score: number;
  network_privacy_score: number;
  tracking_exposure_score: number;
  fingerprint_risk_score: number;
  leak_protection_score: number;
  dns_leak_verdict: LeakVerdict;
  webrtc_leak_verdict: LeakVerdict;
  trackers_blocked_total: number;
  scan_explanation: Record<string, unknown>;
  created_at: string;
}

export interface PrivacyEventEntity {
  id: string;
  user_id: string;
  device_id: string | null;
  event_type: string;
  severity: 'info' | 'warning' | 'critical';
  description: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface AuditLogEntity {
  id: string;
  actor_user_id: string | null;
  action: string;
  target_resource: string;
  target_id: string | null;
  ip_address_anonymized: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}
