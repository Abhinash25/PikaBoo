import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import crypto from 'crypto';
import { getEnv } from '../config/env';

export function setupSecurityMiddleware(app: any) {
  const env = getEnv();

  // Helmet secure headers (CSP, HSTS, X-Frame-Options)
  app.use(
    helmet({
      contentSecurityPolicy: false, // Managed dynamically for Vite dev & production
      crossOriginEmbedderPolicy: false,
    })
  );

  // CORS restrictions
  app.use(
    cors({
      origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN.split(','),
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],
      credentials: true,
      maxAge: 86400,
    })
  );

  // Request ID Tagging
  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = (req.headers['x-request-id'] as string) || crypto.randomUUID();
    res.setHeader('X-Request-Id', requestId);
    (req as any).requestId = requestId;
    next();
  });
}
