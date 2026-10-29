import pg from 'pg';
import { getEnv } from './env';

let pool: pg.Pool | null = null;

export function getDatabasePool(): pg.Pool {
  if (!pool) {
    const env = getEnv();
    const config: pg.PoolConfig = env.DATABASE_URL
      ? { connectionString: env.DATABASE_URL }
      : {
          host: env.POSTGRES_HOST,
          port: env.POSTGRES_PORT,
          database: env.POSTGRES_DB,
          user: env.POSTGRES_USER,
          password: env.POSTGRES_PASSWORD,
          max: 20,
          idleTimeoutMillis: 30000,
          connectionTimeoutMillis: 3000,
        };

    pool = new pg.Pool(config);

    pool.on('error', (err) => {
      console.error('Unexpected error on idle PostgreSQL client pool', err);
    });
  }
  return pool;
}

export async function checkDatabaseHealth(): Promise<{
  service: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latencyMs?: number;
  message?: string;
  details?: Record<string, unknown>;
}> {
  const start = Date.now();
  try {
    const p = getDatabasePool();
    const result = await p.query('SELECT NOW() as current_time, count(*) as tables_count FROM information_schema.tables WHERE table_schema = $1', ['public']);
    const latency = Date.now() - start;
    return {
      service: 'PostgreSQL Database',
      status: 'healthy',
      latencyMs: latency,
      message: 'PostgreSQL connection active',
      details: {
        serverTime: result.rows[0]?.current_time,
        publicTablesCount: Number(result.rows[0]?.tables_count || 0),
        totalCount: p.totalCount,
        idleCount: p.idleCount,
        waitingCount: p.waitingCount,
      },
    };
  } catch (error) {
    return {
      service: 'PostgreSQL Database',
      status: 'degraded',
      latencyMs: Date.now() - start,
      message: `Database uncontactable or running in isolated container: ${(error as Error).message}`,
      details: {
        targetHost: getEnv().POSTGRES_HOST,
        targetPort: getEnv().POSTGRES_PORT,
      },
    };
  }
}

export async function closeDatabasePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
