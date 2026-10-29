import { Request, Response } from 'express';
import { checkDatabaseHealth } from '../config/database';
import { checkRedisHealth } from '../config/redis';
import { HealthCheckResponse } from '../../../../packages/shared-types/src/api';

export async function getHealthCheck(req: Request, res: Response): Promise<void> {
  const [dbHealth, redisHealth] = await Promise.all([
    checkDatabaseHealth(),
    checkRedisHealth(),
  ]);

  const mem = process.memoryUsage();
  const memoryUsageMb = {
    rss: Math.round((mem.rss / 1024 / 1024) * 100) / 100,
    heapTotal: Math.round((mem.heapTotal / 1024 / 1024) * 100) / 100,
    heapUsed: Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100,
    external: Math.round((mem.external / 1024 / 1024) * 100) / 100,
  };

  // Overall status evaluation
  const isHealthy = dbHealth.status === 'healthy' && redisHealth.status === 'healthy';
  const isDegraded = dbHealth.status === 'degraded' || redisHealth.status === 'degraded';
  const overallStatus = isHealthy ? 'healthy' : isDegraded ? 'degraded' : 'unhealthy';

  const response: HealthCheckResponse = {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '0.1.0-phase1',
    uptimeSeconds: Math.floor(process.uptime()),
    memoryUsageMb,
    services: {
      database: dbHealth,
      redis: redisHealth,
      nodeRuntime: {
        service: 'Node.js Runtime',
        status: 'healthy',
        latencyMs: 0,
        message: `Node ${process.version} on ${process.platform} (${process.arch})`,
      },
    },
  };

  // Return 200 even if degraded in development so preview continues
  res.status(overallStatus === 'unhealthy' ? 503 : 200).json(response);
}

export function getLiveness(req: Request, res: Response): void {
  // Simple check if node process is alive and event loop is responsive
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
  });
}

export async function getReadiness(req: Request, res: Response): Promise<void> {
  const [dbHealth, redisHealth] = await Promise.all([
    checkDatabaseHealth(),
    checkRedisHealth(),
  ]);

  const ready = dbHealth.status !== 'unhealthy';
  res.status(ready ? 200 : 503).json({
    status: ready ? 'ready' : 'not_ready',
    timestamp: new Date().toISOString(),
    checks: {
      database: dbHealth.status,
      redis: redisHealth.status,
    },
  });
}
