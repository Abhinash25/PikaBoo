import express from 'express';
import cookieParser from 'cookie-parser';
import { setupSecurityMiddleware } from './middleware/security.middleware';
import { requestLogger } from './middleware/logging.middleware';
import { errorHandler } from './middleware/error.middleware';
import healthRoutes from './routes/health.routes';
import systemRoutes from './routes/system.routes';
import authRoutes from './routes/auth.routes';
import adminRoutes from './routes/admin.routes';
import vpnRoutes from './routes/vpn.routes';

export function createApp() {
  const app = express();

  // Basic Body Parsers & Cookie Parser
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));
  app.use(cookieParser());

  // Security Middleware
  setupSecurityMiddleware(app);

  // Structured Logging (Zero PII)
  app.use(requestLogger);

  // Routes
  app.use('/health', healthRoutes);
  app.use('/api/v1/health', healthRoutes);
  app.use('/api/v1/system', systemRoutes);
  app.use('/api/v1/auth', authRoutes);
  app.use('/api/v1/admin', adminRoutes);
  app.use('/api/v1/vpn', vpnRoutes);

  // Central Error Handler
  app.use(errorHandler);

  return app;
}
