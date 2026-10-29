import crypto from 'node:crypto';
import { getEnv } from './env';

export interface KeyPairConfig {
  privateKey: string;
  publicKey: string;
  keyId: string;
  issuer: string;
  audience: string;
}

let cachedKeyPair: KeyPairConfig | null = null;

export function getJwtKeyConfig(): KeyPairConfig {
  if (cachedKeyPair) {
    return cachedKeyPair;
  }

  const env = getEnv();

  if (env.JWT_PRIVATE_KEY_PEM && env.JWT_PUBLIC_KEY_PEM) {
    cachedKeyPair = {
      privateKey: env.JWT_PRIVATE_KEY_PEM.replace(/\\n/g, '\n'),
      publicKey: env.JWT_PUBLIC_KEY_PEM.replace(/\\n/g, '\n'),
      keyId: env.JWT_KEY_ID,
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
    };
    return cachedKeyPair;
  }

  if (env.NODE_ENV === 'production') {
    throw new Error('FATAL: JWT_PRIVATE_KEY_PEM and JWT_PUBLIC_KEY_PEM are strictly required in production');
  }

  // Development / Test only: generate ephemeral 2048-bit RSA keypair
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  cachedKeyPair = {
    privateKey,
    publicKey,
    keyId: 'pg-dev-ephemeral',
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
  };

  return cachedKeyPair;
}
