import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().optional(),
  POSTGRES_HOST: z.string().default('localhost'),
  POSTGRES_PORT: z.coerce.number().default(5432),
  POSTGRES_DB: z.string().default('privacy_gateway'),
  POSTGRES_USER: z.string().default('pgadmin'),
  POSTGRES_PASSWORD: z.string().default('pgsecret'),
  REDIS_URL: z.string().optional(),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().default(6379),
  REDIS_PASSWORD: z.string().optional(),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  RATE_LIMIT_MAX: z.coerce.number().default(100),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(60000),

  // Google OAuth 2.0 / OpenID Connect
  GOOGLE_CLIENT_ID: z.string().default('dev_google_client_id.apps.googleusercontent.com'),
  GOOGLE_CLIENT_SECRET: z.string().default('dev_google_client_secret'),
  GOOGLE_REDIRECT_URI: z.string().default('http://localhost:3000/api/v1/auth/google/callback'),
  GOOGLE_DESKTOP_CLIENT_ID: z.string().default('dev_google_desktop_client_id.apps.googleusercontent.com'),

  // RS256 JWT Keys
  JWT_PRIVATE_KEY_PEM: z.string().optional(),
  JWT_PUBLIC_KEY_PEM: z.string().optional(),
  JWT_KEY_ID: z.string().default('pg-auth-2026-v1'),
  JWT_ISSUER: z.string().default('https://api.privacygateway.net'),
  JWT_AUDIENCE: z.string().default('https://privacygateway.net'),
});

export type EnvConfig = z.infer<typeof envSchema>;

let validatedEnv: EnvConfig | null = null;

export function getEnv(): EnvConfig {
  if (!validatedEnv) {
    const parsed = envSchema.safeParse(process.env);
    if (!parsed.success) {
      console.warn('⚠️ Environment validation warnings:', parsed.error.format());
      if (process.env.NODE_ENV === 'production') {
        throw new Error('FATAL: Environment validation failed in production mode');
      }
      validatedEnv = envSchema.parse({});
    } else {
      validatedEnv = parsed.data;
    }
  }
  return validatedEnv;
}
