/**
 * Automated Unit Tests for Google OIDC & JWKS Token Verification
 * Phase 2 Authentication
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { verifyGoogleIdToken, jwkToPem } from '../src/services/oidc.service';

describe('OIDC ID Token Validation Unit Tests', () => {
  // Generate a test RSA keypair for simulating Google JWKS
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const testKeyObject = crypto.createPublicKey(publicKey);
  const jwk = testKeyObject.export({ format: 'jwk' });

  const mockGoogleJwks = [
    {
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      kid: 'google-test-key-1',
      n: jwk.n as string,
      e: jwk.e as string,
    },
  ];

  const testAudience = 'test-client-id.apps.googleusercontent.com';
  const testNonce = 'random-nonce-12345';

  it('should successfully verify a valid Google ID token with matching JWKS and claims', async () => {
    const payload = {
      iss: 'https://accounts.google.com',
      sub: 'google-sub-100200300',
      aud: testAudience,
      nonce: testNonce,
      email: 'user@example.com',
      email_verified: true,
      name: 'Test User',
      picture: 'https://example.com/avatar.png',
      iat: Math.floor(Date.now() / 1000) - 10,
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const token = jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
      keyid: 'google-test-key-1',
    });

    const claims = await verifyGoogleIdToken(token, testAudience, testNonce, mockGoogleJwks);
    assert.strictEqual(claims.sub, 'google-sub-100200300');
    assert.strictEqual(claims.email, 'user@example.com');
    assert.strictEqual(claims.email_verified, true);
  });

  it('should reject token signed with mismatched / unknown kid', async () => {
    const token = jwt.sign(
      {
        iss: 'https://accounts.google.com',
        sub: 'sub-123',
        aud: testAudience,
        email: 'user@example.com',
        email_verified: true,
      },
      privateKey,
      { algorithm: 'RS256', keyid: 'unknown-key-999' }
    );

    await assert.rejects(
      async () => {
        await verifyGoogleIdToken(token, testAudience, testNonce, mockGoogleJwks);
      },
      { message: /No matching Google public key found for kid/ }
    );
  });

  it('should reject token with incorrect issuer', async () => {
    const token = jwt.sign(
      {
        iss: 'https://evil-issuer.com',
        sub: 'sub-123',
        aud: testAudience,
        email: 'user@example.com',
        email_verified: true,
      },
      privateKey,
      { algorithm: 'RS256', keyid: 'google-test-key-1' }
    );

    await assert.rejects(
      async () => {
        await verifyGoogleIdToken(token, testAudience, testNonce, mockGoogleJwks);
      },
      { message: /Invalid ID token issuer/ }
    );
  });

  it('should reject token with mismatched audience', async () => {
    const token = jwt.sign(
      {
        iss: 'https://accounts.google.com',
        sub: 'sub-123',
        aud: 'other-app.apps.googleusercontent.com',
        email: 'user@example.com',
        email_verified: true,
      },
      privateKey,
      { algorithm: 'RS256', keyid: 'google-test-key-1' }
    );

    await assert.rejects(
      async () => {
        await verifyGoogleIdToken(token, testAudience, testNonce, mockGoogleJwks);
      },
      { message: /Invalid ID token audience/ }
    );
  });

  it('should reject token with unverified email (email_verified: false)', async () => {
    const token = jwt.sign(
      {
        iss: 'https://accounts.google.com',
        sub: 'sub-123',
        aud: testAudience,
        email: 'unverified@example.com',
        email_verified: false,
      },
      privateKey,
      { algorithm: 'RS256', keyid: 'google-test-key-1' }
    );

    await assert.rejects(
      async () => {
        await verifyGoogleIdToken(token, testAudience, testNonce, mockGoogleJwks);
      },
      { message: /Google account email is not verified/ }
    );
  });

  it('should reject token with mismatched nonce', async () => {
    const token = jwt.sign(
      {
        iss: 'https://accounts.google.com',
        sub: 'sub-123',
        aud: testAudience,
        nonce: 'attacker-nonce-999',
        email: 'user@example.com',
        email_verified: true,
      },
      privateKey,
      { algorithm: 'RS256', keyid: 'google-test-key-1' }
    );

    await assert.rejects(
      async () => {
        await verifyGoogleIdToken(token, testAudience, testNonce, mockGoogleJwks);
      },
      { message: /Mismatched OIDC nonce/ }
    );
  });

  it('should reject non-RS256 algorithms (e.g. HS256 / none)', async () => {
    const hs256Token = jwt.sign(
      {
        iss: 'https://accounts.google.com',
        sub: 'sub-123',
        aud: testAudience,
        email: 'user@example.com',
        email_verified: true,
      },
      'some-symmetric-secret',
      { algorithm: 'HS256', keyid: 'google-test-key-1' }
    );

    await assert.rejects(
      async () => {
        await verifyGoogleIdToken(hs256Token, testAudience, testNonce, mockGoogleJwks);
      },
      { message: /Unexpected JWT algorithm: HS256/ }
    );
  });
});
