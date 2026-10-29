import crypto from 'node:crypto';
import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';
import { getJwtKeyConfig } from '../config/keys';
import { UserRole } from '@privacy-gateway/shared-types';

export interface AccessTokenPayload {
  sub: string;
  email: string;
  role: UserRole;
  sessionId: string;
  familyId: string;
}

export interface DecodedAccessToken extends JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  sessionId: string;
  familyId: string;
}

/**
 * Mint RS256 JWT Access Token (15m validity)
 */
export function generateAccessToken(payload: AccessTokenPayload): string {
  const keys = getJwtKeyConfig();

  const options: SignOptions = {
    algorithm: 'RS256',
    keyid: keys.keyId,
    issuer: keys.issuer,
    audience: keys.audience,
    expiresIn: '15m',
    jwtid: crypto.randomUUID(),
  };

  return jwt.sign(
    {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
      sessionId: payload.sessionId,
      familyId: payload.familyId,
    },
    keys.privateKey,
    options
  );
}

/**
 * Verify RS256 JWT Access Token with strict algorithm, issuer, and audience assertions
 */
export function verifyAccessToken(token: string): DecodedAccessToken {
  const keys = getJwtKeyConfig();

  const decoded = jwt.verify(token, keys.publicKey, {
    algorithms: ['RS256'],
    issuer: keys.issuer,
    audience: keys.audience,
  });

  if (typeof decoded === 'string' || !decoded.sub) {
    throw new Error('Invalid JWT payload structure');
  }

  return decoded as DecodedAccessToken;
}

/**
 * Generate 256-bit CSPRNG Refresh Token string and its SHA-256 hash
 */
export function generateRefreshToken(): { rawToken: string; tokenHash: string } {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);
  return { rawToken, tokenHash };
}

/**
 * Compute SHA-256 hash of a raw token string
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Generate 256-bit CSPRNG CSRF token
 */
export function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('hex');
}
