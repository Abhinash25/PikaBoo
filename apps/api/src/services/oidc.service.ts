import crypto from 'node:crypto';
import jwt, { JwtHeader, JwtPayload } from 'jsonwebtoken';

export interface GoogleIdTokenClaims extends JwtPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  nonce?: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
}

interface GoogleJwkKey {
  kty: string;
  alg: string;
  use: string;
  kid: string;
  n: string;
  e: string;
}

interface GoogleJwksResponse {
  keys: GoogleJwkKey[];
}

let jwksCache: { keys: GoogleJwkKey[]; expiresAt: number } | null = null;

/**
 * Fetch Google JWKS public certificates with 1-hour cache
 */
export async function getGoogleJwks(): Promise<GoogleJwkKey[]> {
  const now = Date.now();
  if (jwksCache && jwksCache.expiresAt > now) {
    return jwksCache.keys;
  }

  try {
    const res = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    if (!res.ok) {
      throw new Error(`Failed to fetch Google JWKS: HTTP ${res.status}`);
    }
    const data = (await res.json()) as GoogleJwksResponse;
    jwksCache = {
      keys: data.keys,
      expiresAt: now + 3600 * 1000,
    };
    return data.keys;
  } catch (err) {
    if (jwksCache) {
      return jwksCache.keys; // fallback to stale cache on network failure
    }
    throw err;
  }
}

/**
 * Convert RSA modulus and exponent from JWK to PEM public key
 */
export function jwkToPem(jwk: GoogleJwkKey): string {
  const keyObject = crypto.createPublicKey({
    key: {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
    },
    format: 'jwk',
  });
  return keyObject.export({ type: 'spki', format: 'pem' }) as string;
}

/**
 * Validates Google OIDC ID Token claims & RS256 signature
 */
export async function verifyGoogleIdToken(
  idToken: string,
  expectedAudience: string,
  expectedNonce?: string,
  overrideJwks?: GoogleJwkKey[]
): Promise<GoogleIdTokenClaims> {
  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded || !decoded.header) {
    throw new Error('Invalid OIDC ID token structure');
  }

  const header = decoded.header as JwtHeader;
  if (header.alg !== 'RS256') {
    throw new Error(`Unexpected JWT algorithm: ${header.alg}. Only RS256 is accepted.`);
  }

  if (!header.kid) {
    throw new Error('ID Token header missing kid parameter');
  }

  const keys = overrideJwks ?? (await getGoogleJwks());
  const matchingJwk = keys.find((k) => k.kid === header.kid);
  if (!matchingJwk) {
    throw new Error(`No matching Google public key found for kid: ${header.kid}`);
  }

  const pem = jwkToPem(matchingJwk);

  const payload = jwt.verify(idToken, pem, {
    algorithms: ['RS256'],
  }) as GoogleIdTokenClaims;

  // 1. Assert issuer
  const validIssuers = ['https://accounts.google.com', 'accounts.google.com'];
  if (!validIssuers.includes(payload.iss)) {
    throw new Error(`Invalid ID token issuer: ${payload.iss}`);
  }

  // 2. Assert audience
  if (payload.aud !== expectedAudience) {
    throw new Error(`Invalid ID token audience: expected ${expectedAudience}, got ${payload.aud}`);
  }

  // 3. Assert email_verified === true
  if (payload.email_verified !== true) {
    throw new Error('Google account email is not verified');
  }

  // 4. Assert nonce
  if (expectedNonce && payload.nonce !== expectedNonce) {
    throw new Error(`Mismatched OIDC nonce: expected ${expectedNonce}, got ${payload.nonce}`);
  }

  // 5. Assert subject & email exist
  if (!payload.sub || !payload.email) {
    throw new Error('ID token missing sub or email claims');
  }

  return payload;
}
