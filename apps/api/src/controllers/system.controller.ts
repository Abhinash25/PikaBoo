import { Request, Response } from 'express';
import { getDatabasePool } from '../config/database';
import { ApiResponse, SystemInfoResponse } from '../../../../packages/shared-types/src/api';

export async function getSystemInfo(req: Request, res: Response): Promise<void> {
  const requestId = (req as any).requestId || 'unknown';

  let appliedMigrationsCount = 0;
  let latestMigration: string | null = null;

  try {
    const pool = getDatabasePool();
    const { rows } = await pool.query<{ name: string; count: string }>(
      'SELECT name FROM _migrations ORDER BY id DESC LIMIT 1'
    );
    const countRes = await pool.query<{ count: string }>('SELECT count(*) as count FROM _migrations');
    appliedMigrationsCount = Number(countRes.rows[0]?.count || 0);
    latestMigration = rows[0]?.name || null;
  } catch {
    // Database may be offline during preview boot
  }

  const systemInfo: SystemInfoResponse = {
    name: 'Privacy Gateway API',
    phase: 'Phase 1: Foundation & Monorepo Infrastructure',
    architecture: {
      dataPlane: 'WireGuard Kernel Module (Host-Level, Zero-Logging)',
      controlPlane: 'Decoupled Node/Express API + Privacy Intelligence Engine',
      database: 'PostgreSQL 16 Relational Schema with Row-Level Security',
      eventBus: 'Redis 7 Streams + Pub/Sub',
      privilegeModel: 'Non-Root Container (UID 10001) / Scoped CAP_NET_ADMIN Daemon',
    },
    securityBoundaries: {
      nonRootContainer: true,
      readOnlyFilesystem: true,
      capabilitiesDropped: ['ALL'],
    },
    migrations: {
      totalDefined: 1,
      appliedCount: appliedMigrationsCount,
      latestMigration: latestMigration || '001_initial_schema.sql (Defined)',
    },
  };

  const response: ApiResponse<SystemInfoResponse> = {
    success: true,
    data: systemInfo,
    timestamp: new Date().toISOString(),
    requestId,
  };

  res.json(response);
}

export async function getMigrationsStatus(req: Request, res: Response): Promise<void> {
  const requestId = (req as any).requestId || 'unknown';
  const definedMigrations = [
    {
      id: 1,
      name: '001_initial_schema.sql',
      description: 'Initial schema: users, accounts, sessions, devices, servers, peers, scans, events, audit_logs',
      tables: [
        'users',
        'authentication_accounts',
        'user_sessions',
        'devices',
        'vpn_servers',
        'wireguard_peers',
        'subscriptions',
        'privacy_scans',
        'privacy_events',
        'audit_logs',
      ],
    },
  ];

  let appliedMigrations: { id: number; name: string; applied_at: string }[] = [];

  try {
    const pool = getDatabasePool();
    const { rows } = await pool.query<{ id: number; name: string; applied_at: string }>(
      'SELECT id, name, applied_at FROM _migrations ORDER BY id ASC'
    );
    appliedMigrations = rows;
  } catch {
    // DB offline fallback
  }

  const response: ApiResponse<{
    defined: typeof definedMigrations;
    applied: typeof appliedMigrations;
  }> = {
    success: true,
    data: {
      defined: definedMigrations,
      applied: appliedMigrations,
    },
    timestamp: new Date().toISOString(),
    requestId,
  };

  res.json(response);
}
