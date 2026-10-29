/**
 * Privacy Gateway API Contracts & Shared DTOs
 * Phase 1 & Phase 2 Complete
 */

export interface ServiceHealthStatus {
  service: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latencyMs?: number;
  message?: string;
  details?: Record<string, unknown>;
}

export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  environment: string;
  version: string;
  uptimeSeconds: number;
  memoryUsageMb: {
    rss: number;
    heapTotal: number;
    heapUsed: number;
    external: number;
  };
  services: {
    database: ServiceHealthStatus;
    redis: ServiceHealthStatus;
    nodeRuntime: ServiceHealthStatus;
  };
}

import { UserRole } from './db';

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  timestamp: string;
  requestId: string;
}

export interface SystemInfoResponse {
  name: string;
  phase: string;
  architecture: {
    dataPlane: string;
    controlPlane: string;
    database: string;
    eventBus: string;
    privilegeModel: string;
  };
  securityBoundaries: {
    nonRootContainer: boolean;
    readOnlyFilesystem: boolean;
    capabilitiesDropped: string[];
  };
  migrations: {
    totalDefined: number;
    appliedCount: number;
    latestMigration: string | null;
  };
}

export interface UserProfileDto {
  id: string;
  email: string;
  displayName: string | null;
  avatarUrl: string | null;
  role: UserRole;
  isActive: boolean;
  dataRetentionDays: number;
  createdAt: string;
}

export interface SessionItemDto {
  id: string;
  familyId: string;
  userAgent: string | null;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

export interface AuthMeResponseDto {
  user: UserProfileDto;
  sessionsCount: number;
}

export interface AuthTokensDto {
  accessToken: string;
  refreshToken: string;
  user: UserProfileDto;
}
