/**
 * Privacy Gateway — Unified Server Entry Point
 * Mounts Core API Routes & Vite Development Middleware on Port 3000
 */

import 'dotenv/config';
import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';
import { setupSecurityMiddleware } from './apps/api/src/middleware/security.middleware';
import { requestLogger } from './apps/api/src/middleware/logging.middleware';
import { errorHandler } from './apps/api/src/middleware/error.middleware';
import healthRoutes from './apps/api/src/routes/health.routes';
import systemRoutes from './apps/api/src/routes/system.routes';
import authRoutes from './apps/api/src/routes/auth.routes';
import adminRoutes from './apps/api/src/routes/admin.routes';
import vpnRoutes from './apps/api/src/routes/vpn.routes';
import { closeDatabasePool } from './apps/api/src/config/database';
import { closeRedisClient } from './apps/api/src/config/redis';

async function startUnifiedServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const HOST = process.env.HOST || 'localhost';

  // 1. Basic Body Parsers & Cookie Parser
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));
  app.use(cookieParser());

  // 2. Security Middleware
  setupSecurityMiddleware(app);

  // 3. Structured Logging (Zero PII)
  app.use(requestLogger);

  // 4. Mount API Routes FIRST
  app.use('/health', healthRoutes);
  app.use('/api/v1/health', healthRoutes);
  app.use('/api/v1/system', systemRoutes);
  app.use('/api/v1/auth', authRoutes);
  app.use('/api/v1/admin', adminRoutes);
  app.use('/api/v1/vpn', vpnRoutes);

  // 5. Mount Vite Middleware for Development / Static Fallback in Production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // 6. Central Error Handler
  app.use(errorHandler);

  const server = app.listen(PORT, HOST, () => {
    console.log(`[Privacy Gateway] Server running on http://${HOST}:${PORT}`);
    console.log(`[Privacy Gateway] Phase 1 Foundation: API, Health Probes & Web Dashboard Active`);
    console.log(`[Privacy Gateway] Health endpoints: http://${HOST}:${PORT}/health, http://${HOST}:${PORT}/health/live`);
  });

  const gracefulShutdown = async (signal: string) => {
    console.log(`[Privacy Gateway] Received ${signal}. Draining connections...`);
    server.close(async () => {
      await Promise.all([closeDatabasePool(), closeRedisClient()]);
      console.log('[Privacy Gateway] Clean shutdown complete.');
      process.exit(0);
    });

    setTimeout(() => {
      console.error('[Privacy Gateway] Shutdown timed out, forcing exit.');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}

startUnifiedServer().catch((err) => {
  console.error('[Privacy Gateway] Fatal error starting server:', err);
  process.exit(1);
});
