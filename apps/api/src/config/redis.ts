import Redis from 'ioredis';
import { getEnv } from './env';

let redisClient: Redis | null = null;

export function getRedisClient(): Redis {
  if (!redisClient) {
    const env = getEnv();
    if (env.REDIS_URL) {
      redisClient = new Redis(env.REDIS_URL, {
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        connectTimeout: 2000,
        retryStrategy: (times) => {
          if (times > 3) return null;
          return Math.min(times * 100, 1000);
        },
      });
    } else {
      redisClient = new Redis({
        host: env.REDIS_HOST,
        port: env.REDIS_PORT,
        password: env.REDIS_PASSWORD || undefined,
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        connectTimeout: 2000,
        retryStrategy: (times) => {
          if (times > 3) return null;
          return Math.min(times * 100, 1000);
        },
      });
    }

    redisClient.on('error', (err) => {
      // Suppress noisy uncaught errors in development when redis container is offline
      if (env.NODE_ENV === 'development') {
        // quiet debug log
      } else {
        console.error('Redis Client Error:', err);
      }
    });
  }
  return redisClient;
}

export async function checkRedisHealth(): Promise<{
  service: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latencyMs?: number;
  message?: string;
  details?: Record<string, unknown>;
}> {
  const start = Date.now();
  try {
    const client = getRedisClient();
    if (client.status !== 'ready') {
      await client.connect();
    }
    const pong = await client.ping();
    const latency = Date.now() - start;
    return {
      service: 'Redis Event Bus',
      status: pong === 'PONG' ? 'healthy' : 'degraded',
      latencyMs: latency,
      message: 'Redis event bus active',
      details: {
        status: client.status,
      },
    };
  } catch (error) {
    return {
      service: 'Redis Event Bus',
      status: 'degraded',
      latencyMs: Date.now() - start,
      message: `Redis unavailable or isolated: ${(error as Error).message}`,
      details: {
        targetHost: getEnv().REDIS_HOST,
        targetPort: getEnv().REDIS_PORT,
      },
    };
  }
}

export async function closeRedisClient(): Promise<void> {
  if (redisClient) {
    try {
      await redisClient.quit();
    } catch {
      redisClient.disconnect();
    }
    redisClient = null;
  }
}
