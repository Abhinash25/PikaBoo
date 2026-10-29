import { createApp } from './app';
import { getEnv } from './config/env';
import { closeDatabasePool } from './config/database';
import { closeRedisClient } from './config/redis';

export async function startApiServer() {
  const env = getEnv();
  const app = createApp();

  const server = app.listen(env.PORT, env.HOST, () => {
    console.log(`[Privacy Gateway API] Server running on http://${env.HOST}:${env.PORT}`);
    console.log(`[Privacy Gateway API] Environment: ${env.NODE_ENV}`);
    console.log(`[Privacy Gateway API] Health checks available at /health and /health/live`);
  });

  const gracefulShutdown = async (signal: string) => {
    console.log(`[Privacy Gateway API] Received ${signal}. Starting graceful shutdown...`);
    server.close(async () => {
      console.log('[Privacy Gateway API] HTTP server closed.');
      await Promise.all([closeDatabasePool(), closeRedisClient()]);
      console.log('[Privacy Gateway API] Database and Redis connections closed. Exiting process.');
      process.exit(0);
    });

    // Force exit after 10s if stuck
    setTimeout(() => {
      console.error('[Privacy Gateway API] Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  return server;
}

if (process.env.RUN_STANDALONE === 'true') {
  startApiServer().catch((err) => {
    console.error('[Privacy Gateway API] Fatal error starting server:', err);
    process.exit(1);
  });
}
