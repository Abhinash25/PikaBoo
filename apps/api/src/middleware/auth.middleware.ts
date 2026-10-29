import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, DecodedAccessToken } from '../services/token.service';
import { UserRole } from '@privacy-gateway/shared-types';

export interface AuthenticatedRequest extends Request {
  user?: DecodedAccessToken;
}

declare global {
  namespace Express {
    interface Request {
      user?: DecodedAccessToken;
    }
  }
}

/**
 * Extract token from Authorization header or pg_access_token cookie
 */
function extractToken(req: Request): string | null {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  if (req.cookies && req.cookies.pg_access_token) {
    return req.cookies.pg_access_token;
  }
  return null;
}

/**
 * Require valid RS256 JWT Access Token
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = extractToken(req);

  if (!token) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required. No valid token found.',
      },
      timestamp: new Date().toISOString(),
      requestId: (req as any).id || 'req-auth',
    });
  }

  try {
    const payload = verifyAccessToken(token);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'INVALID_TOKEN',
        message: `Token verification failed: ${(err as Error).message}`,
      },
      timestamp: new Date().toISOString(),
      requestId: (req as any).id || 'req-auth',
    });
  }
}

/**
 * Optional authentication: attaches user if valid token exists, proceeds regardless
 */
export function optionalAuth(req: Request, res: Response, next: NextFunction) {
  const token = extractToken(req);
  if (token) {
    try {
      req.user = verifyAccessToken(token);
    } catch {
      // ignore invalid optional token
    }
  }
  next();
}

/**
 * Require specific user role (e.g. 'admin')
 */
export function requireRole(allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required.',
        },
        timestamp: new Date().toISOString(),
        requestId: (req as any).id || 'req-role',
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: `Access denied. Requires one of roles: ${allowedRoles.join(', ')}`,
        },
        timestamp: new Date().toISOString(),
        requestId: (req as any).id || 'req-role',
      });
    }

    next();
  };
}
