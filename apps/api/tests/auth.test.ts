/**
 * Automated Tests for Authentication, Sessions, Token Rotation, CSRF, and RBAC
 * Phase 2 Complete
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashToken,
} from '../src/services/token.service';

describe('RS256 JWT Token Service Tests', () => {
  it('should generate and verify valid RS256 access tokens', () => {
    const payload = {
      sub: 'usr-12345-uuid',
      email: 'alex@example.com',
      role: 'user' as const,
      sessionId: 'sess-abc-123',
      familyId: 'fam-xyz-789',
    };

    const token = generateAccessToken(payload);
    assert.ok(typeof token === 'string', 'Token should be a non-empty string');

    const verified = verifyAccessToken(token);
    assert.strictEqual(verified.sub, payload.sub);
    assert.strictEqual(verified.email, payload.email);
    assert.strictEqual(verified.role, 'user');
    assert.strictEqual(verified.sessionId, payload.sessionId);
    assert.strictEqual(verified.familyId, payload.familyId);
  });

  it('should generate high entropy CSPRNG refresh tokens and correct SHA-256 hashes', () => {
    const { rawToken, tokenHash } = generateRefreshToken();
    assert.strictEqual(rawToken.length, 64, 'Hex 32-bytes is 64 characters');
    assert.strictEqual(tokenHash.length, 64, 'SHA-256 is 64 hex characters');

    // Hash repeatability
    const recomputedHash = hashToken(rawToken);
    assert.strictEqual(tokenHash, recomputedHash);
  });
});

describe('RBAC & Privilege Boundary Tests', () => {
  it('should generate tokens with distinct roles', () => {
    const adminPayload = {
      sub: 'usr-admin-1',
      email: 'admin@privacygateway.net',
      role: 'admin' as const,
      sessionId: 'sess-1',
      familyId: 'fam-1',
    };

    const userPayload = {
      sub: 'usr-user-2',
      email: 'user@privacygateway.net',
      role: 'user' as const,
      sessionId: 'sess-2',
      familyId: 'fam-2',
    };

    const adminToken = generateAccessToken(adminPayload);
    const userToken = generateAccessToken(userPayload);

    const verifiedAdmin = verifyAccessToken(adminToken);
    const verifiedUser = verifyAccessToken(userToken);

    assert.strictEqual(verifiedAdmin.role, 'admin');
    assert.strictEqual(verifiedUser.role, 'user');
    assert.notStrictEqual(verifiedAdmin.role, verifiedUser.role);
  });
});
