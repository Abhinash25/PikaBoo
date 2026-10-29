import { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';

/**
 * Constant-time string equality check to prevent timing attacks
 */
function safeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Double-Submit Cookie CSRF Validator
 * Protects every state-changing endpoint (POST, PUT, PATCH, DELETE) authenticated via cookies.
 */
export function requireCsrf(req: Request, res: Response, next: NextFunction) {
  // Safe idempotent HTTP methods are exempt from CSRF
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    return next();
  }

  // If request uses Bearer token authorization header (non-browser or desktop client), bypass CSRF
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return next();
  }

  const cookieCsrfToken = req.cookies?.pg_csrf_token;
  const headerCsrfToken = req.headers['x-csrf-token'] as string | undefined;

  if (!cookieCsrfToken || !headerCsrfToken) {
    return res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_TOKEN_MISSING',
        message: 'A valid X-CSRF-Token header matching the pg_csrf_token cookie is required for this action.',
      },
      timestamp: new Date().toISOString(),
      requestId: (req as any).id || 'req-csrf',
    });
  }

  if (!safeCompare(cookieCsrfToken, headerCsrfToken)) {
    return res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_TOKEN_MISMATCH',
        message: 'Invalid or mismatched CSRF token provided.',
      },
      timestamp: new Date().toISOString(),
      requestId: (req as any).id || 'req-csrf',
    });
  }

  next();
}
