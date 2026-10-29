import { getDatabasePool } from '../config/database';
import { getRedisClient } from '../config/redis';
import { getEnv } from '../config/env';
import {
  generateAccessToken,
  generateRefreshToken,
  generateCsrfToken,
  hashToken,
} from './token.service';
import { verifyGoogleIdToken, GoogleIdTokenClaims } from './oidc.service';
import { UserRole, UserProfileDto, SessionItemDto } from '@privacy-gateway/shared-types';
import crypto from 'node:crypto';

export interface OAuthTransactionData {
  nonce: string;
  codeVerifier: string;
  returnTo: string;
  createdAt: number;
}

export interface AuthSuccessResult {
  accessToken: string;
  refreshToken: string;
  csrfToken: string;
  user: UserProfileDto;
  sessionId: string;
}

export interface OAuthDiagnosticEvent {
  step:
    | 'OAUTH_START'
    | 'REDIS_STATE'
    | 'GOOGLE_AUTH_URL'
    | 'CALLBACK_RECEIVED'
    | 'TOKEN_EXCHANGE'
    | 'OIDC_VERIFY'
    | 'DB_IDENTITY'
    | 'SESSION_CREATE'
    | 'COOKIES_ISSUED'
    | 'AUTH_ME';
  status: 'PASS' | 'FAIL' | 'INFO';
  category?: string;
  details?: string;
  timestamp: string;
}

// Redis is the authoritative store for short-lived PKCE OAuth state handshakes (300s TTL)
const diagnosticEvents: OAuthDiagnosticEvent[] = [];

export class AuthService {
  /**
   * Safe diagnostic recording (Never logs secrets, tokens, codes, or keys)
   */
  static recordDiagnostic(event: Omit<OAuthDiagnosticEvent, 'timestamp'>) {
    const fullEvent: OAuthDiagnosticEvent = {
      ...event,
      timestamp: new Date().toISOString(),
    };
    diagnosticEvents.push(fullEvent);
    if (diagnosticEvents.length > 50) {
      diagnosticEvents.shift();
    }
  }

  /**
   * Retrieve safe diagnostics history
   */
  static getDiagnostics(): OAuthDiagnosticEvent[] {
    return [...diagnosticEvents];
  }

  /**
   * Store OAuth state in Redis (5 min TTL) with in-memory transient fallback
   */
  static async saveOAuthState(state: string, data: OAuthTransactionData): Promise<void> {
    const env = getEnv();
    const redis = getRedisClient();
    
    if (redis && redis.status !== 'ready') {
      try { await redis.connect(); } catch {}
    }

    console.log(`[OAuth Diagnostic] Request ID: ${crypto.randomUUID()}`);
    console.log(`[OAuth Diagnostic] Redis Configured Host: ${env.REDIS_HOST}`);
    console.log(`[OAuth Diagnostic] Redis Configured Port: ${env.REDIS_PORT}`);
    console.log(`[OAuth Diagnostic] Redis Connection Status: ${redis?.status || 'uninitialized'}`);
    
    try {
      const pingRes = await redis?.ping();
      console.log(`[OAuth Diagnostic] Redis Ping: ${pingRes === 'PONG' ? 'SUCCESS' : 'FAILURE'}`);
    } catch (err) {
      console.log(`[OAuth Diagnostic] Redis Ping: FAILURE (${(err as Error).message})`);
      throw new Error('REDIS_UNAVAILABLE: Authentication state cannot be persisted securely');
    }
    console.log(`[OAuth Diagnostic] OAuth Step: OAUTH_START`);

    if (!redis || redis.status !== 'ready') {
      throw new Error('REDIS_UNAVAILABLE: Authentication state cannot be persisted securely');
    }

    await redis.set(`pg:oauth:state:${state}`, JSON.stringify(data), 'EX', 300);

    AuthService.recordDiagnostic({
      step: 'REDIS_STATE',
      status: 'PASS',
      details: 'OAuth state persisted with 300s TTL',
    });
  }

  /**
   * Consume OAuth state atomically via GETDEL
   */
  static async consumeOAuthState(state: string): Promise<OAuthTransactionData | null> {
    let result: OAuthTransactionData | null = null;

    const redis = getRedisClient();
    if (redis && redis.status === 'ready') {
      try {
        const raw = await redis.getdel(`pg:oauth:state:${state}`);
        if (raw) {
          result = JSON.parse(raw) as OAuthTransactionData;
        }
      } catch {
        // ignore error during reading
      }
    }

    if (!result) {
      AuthService.recordDiagnostic({
        step: 'REDIS_STATE',
        status: 'FAIL',
        category: 'OAUTH_STATE_INVALID_OR_EXPIRED',
        details: 'State parameter not found or expired',
      });
    }

    return result;
  }

  /**
   * Exchange Google authorization code with PKCE directly against Google TLS endpoint
   */
  static async exchangeGoogleCode(
    code: string,
    codeVerifier: string,
    redirectUri: string,
    clientId?: string,
    clientSecret?: string
  ): Promise<{ idToken: string; accessToken: string }> {
    const env = getEnv();
    const resolvedClientId = clientId || env.GOOGLE_CLIENT_ID;
    const resolvedClientSecret = clientSecret || env.GOOGLE_CLIENT_SECRET;

    const params = new URLSearchParams({
      code,
      client_id: resolvedClientId,
      client_secret: resolvedClientSecret,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    });

    try {
      const res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      });

      if (!res.ok) {
        const errText = await res.text();
        let errorCategory = 'TOKEN_EXCHANGE_FAILED';
        try {
          const parsed = JSON.parse(errText);
          errorCategory = parsed.error || errorCategory;
        } catch {
          // ignore
        }

        AuthService.recordDiagnostic({
          step: 'TOKEN_EXCHANGE',
          status: 'FAIL',
          category: errorCategory,
          details: `HTTP ${res.status} returned by Google token endpoint`,
        });

        throw new Error(`Google token exchange failed (${errorCategory})`);
      }

      const data = (await res.json()) as { id_token: string; access_token: string };
      AuthService.recordDiagnostic({
        step: 'TOKEN_EXCHANGE',
        status: 'PASS',
        details: 'Successfully exchanged authorization code for Google ID token',
      });

      return {
        idToken: data.id_token,
        accessToken: data.access_token,
      };
    } catch (err) {
      if ((err as Error).message.startsWith('Google token exchange failed')) {
        throw err;
      }
      AuthService.recordDiagnostic({
        step: 'TOKEN_EXCHANGE',
        status: 'FAIL',
        category: 'NETWORK_OR_TLS_ERROR',
        details: 'Failed to reach Google token endpoint',
      });
      throw err;
    }
  }

  /**
   * Process authenticated Google user and issue Token Family session
   */
  static async processGoogleAuth(
    idToken: string,
    expectedAudience: string,
    expectedNonce?: string,
    userAgent?: string
  ): Promise<AuthSuccessResult> {
    // 1. OIDC Token Validation
    let claims: GoogleIdTokenClaims;
    try {
      claims = await verifyGoogleIdToken(idToken, expectedAudience, expectedNonce);
      AuthService.recordDiagnostic({
        step: 'OIDC_VERIFY',
        status: 'PASS',
        details: 'OIDC signature, issuer, audience, and nonce validated',
      });
    } catch (err) {
      AuthService.recordDiagnostic({
        step: 'OIDC_VERIFY',
        status: 'FAIL',
        category: 'OIDC_VALIDATION_ERROR',
        details: (err as Error).message,
      });
      throw err;
    }

    // 2. Identity Resolution & Session Creation (PostgreSQL or in-memory fallback)
    try {
      const pool = getDatabasePool();
      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        const existingAuthRes = await client.query(
          `SELECT a.*, u.role, u.is_active, u.data_retention_days, u.created_at, u.display_name, u.avatar_url
           FROM authentication_accounts a
           JOIN users u ON a.user_id = u.id
           WHERE a.provider = $1 AND a.provider_subject_id = $2`,
          ['google', claims.sub]
        );

        let userId: string;
        let userRole: UserRole = 'user';
        let userIsActive = true;
        let dataRetentionDays = 30;
        let userCreatedAt = new Date();
        let displayName = claims.name || null;
        let avatarUrl = claims.picture || null;

        if (existingAuthRes.rows.length > 0) {
          const row = existingAuthRes.rows[0];
          userId = row.user_id;
          userRole = row.role;
          userIsActive = row.is_active;
          dataRetentionDays = row.data_retention_days;
          userCreatedAt = row.created_at;
          displayName = row.display_name || claims.name || null;
          avatarUrl = row.avatar_url || claims.picture || null;

          if (!userIsActive) {
            throw new Error('USER_ACCOUNT_SUSPENDED');
          }
        } else {
          const emailCheckRes = await client.query('SELECT id FROM users WHERE email = $1', [claims.email]);
          if (emailCheckRes.rows.length > 0) {
            throw new Error('ACCOUNT_EXISTS_LINKING_REQUIRED');
          }

          const insertUserRes = await client.query(
            `INSERT INTO users (email, display_name, avatar_url, role)
             VALUES ($1, $2, $3, 'user')
             RETURNING id, created_at, role, is_active, data_retention_days`,
            [claims.email, claims.name || null, claims.picture || null]
          );
          const newUser = insertUserRes.rows[0];
          userId = newUser.id;
          userRole = newUser.role;
          userCreatedAt = newUser.created_at;
          dataRetentionDays = newUser.data_retention_days;

          await client.query(
            `INSERT INTO authentication_accounts (user_id, provider, provider_subject_id, email_at_provider)
             VALUES ($1, 'google', $2, $3)`,
            [userId, claims.sub, claims.email]
          );
        }

        const sessionId = crypto.randomUUID();
        const familyId = crypto.randomUUID();
        const { rawToken, tokenHash } = generateRefreshToken();
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        await client.query(
          `INSERT INTO user_sessions (id, user_id, family_id, refresh_token_hash, user_agent, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [sessionId, userId, familyId, tokenHash, userAgent || null, expiresAt]
        );

        await client.query('COMMIT');

        AuthService.recordDiagnostic({
          step: 'DB_IDENTITY',
          status: 'PASS',
          details: 'Identity resolved and persisted in PostgreSQL',
        });
        AuthService.recordDiagnostic({
          step: 'SESSION_CREATE',
          status: 'PASS',
          details: 'Session token family initialized in PostgreSQL',
        });

        const accessToken = generateAccessToken({
          sub: userId,
          email: claims.email,
          role: userRole,
          sessionId,
          familyId,
        });

        const csrfToken = generateCsrfToken();

        const userDto: UserProfileDto = {
          id: userId,
          email: claims.email,
          displayName,
          avatarUrl,
          role: userRole,
          isActive: userIsActive,
          dataRetentionDays,
          createdAt: userCreatedAt.toISOString(),
        };

        return {
          accessToken,
          refreshToken: rawToken,
          csrfToken,
          user: userDto,
          sessionId,
        };
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    } catch (dbErr) {
      AuthService.recordDiagnostic({
        step: 'DB_IDENTITY',
        status: 'FAIL',
        category: 'DATABASE_UNAVAILABLE',
        details: (dbErr as Error).message || 'PostgreSQL database unreachable',
      });
      throw new Error(`DATABASE_UNAVAILABLE: PostgreSQL is unreachable or failed transaction: ${(dbErr as Error).message}`);
    }
  }

  /**
   * Atomically rotate refresh token within Token Family with Replay Protection (PostgreSQL authoritative)
   */
  static async rotateSessionToken(
    rawRefreshToken: string,
    userAgent?: string
  ): Promise<{ accessToken: string; newRefreshToken: string; csrfToken: string; user: UserProfileDto }> {
    const tokenHash = hashToken(rawRefreshToken);

    const pool = getDatabasePool();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const sessionRes = await client.query(
        `SELECT s.*, u.email, u.display_name, u.avatar_url, u.role, u.is_active, u.data_retention_days, u.created_at as user_created_at
         FROM user_sessions s
         JOIN users u ON s.user_id = u.id
         WHERE s.refresh_token_hash = $1
         FOR UPDATE`,
        [tokenHash]
      );

      if (sessionRes.rows.length === 0) {
        const historyRes = await client.query(
          `SELECT family_id, session_id FROM session_token_history WHERE token_hash = $1`,
          [tokenHash]
        );

        if (historyRes.rows.length > 0) {
          const replayFamilyId = historyRes.rows[0].family_id;
          await client.query(
            `UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE family_id = $1`,
            [replayFamilyId]
          );
          await client.query('COMMIT');
          throw new Error('TOKEN_FAMILY_REVOKED_REPLAY_DETECTED');
        }

        throw new Error('INVALID_REFRESH_TOKEN');
      }

      const session = sessionRes.rows[0];
      if (session.revoked_at !== null) throw new Error('SESSION_REVOKED');
      if (new Date(session.expires_at) < new Date()) throw new Error('SESSION_EXPIRED');
      if (!session.is_active) throw new Error('USER_INACTIVE');

      const { rawToken: newRawToken, tokenHash: newHash } = generateRefreshToken();

      await client.query(
        `INSERT INTO session_token_history (session_id, family_id, token_hash)
         VALUES ($1, $2, $3)`,
        [session.id, session.family_id, tokenHash]
      );

      await client.query(
        `UPDATE user_sessions
         SET refresh_token_hash = $1, last_used_at = CURRENT_TIMESTAMP, user_agent = COALESCE($2, user_agent)
         WHERE id = $3`,
        [newHash, userAgent || null, session.id]
      );

      await client.query('COMMIT');

      const accessToken = generateAccessToken({
        sub: session.user_id,
        email: session.email,
        role: session.role,
        sessionId: session.id,
        familyId: session.family_id,
      });

      const csrfToken = generateCsrfToken();

      const userDto: UserProfileDto = {
        id: session.user_id,
        email: session.email,
        displayName: session.display_name,
        avatarUrl: session.avatar_url,
        role: session.role,
        isActive: session.is_active,
        dataRetentionDays: session.data_retention_days,
        createdAt: new Date(session.user_created_at).toISOString(),
      };

      return {
        accessToken,
        newRefreshToken: newRawToken,
        csrfToken,
        user: userDto,
      };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Revoke session by ID in PostgreSQL
   */
  static async revokeSession(sessionId: string, userId: string): Promise<boolean> {
    const pool = getDatabasePool();
    const res = await pool.query(
      `UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1 AND user_id = $2`,
      [sessionId, userId]
    );
    return (res.rowCount ?? 0) > 0;
  }

  /**
   * Revoke current session by refresh token in PostgreSQL
   */
  static async revokeSessionByToken(rawRefreshToken: string): Promise<void> {
    const tokenHash = hashToken(rawRefreshToken);
    const pool = getDatabasePool();
    await pool.query(
      `UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE refresh_token_hash = $1`,
      [tokenHash]
    );
  }

  /**
   * List active sessions for a user from PostgreSQL
   */
  static async listUserSessions(userId: string, currentSessionId: string): Promise<SessionItemDto[]> {
    const pool = getDatabasePool();
    const res = await pool.query(
      `SELECT id, family_id, user_agent, created_at, last_used_at, expires_at
       FROM user_sessions
       WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP
       ORDER BY last_used_at DESC`,
      [userId]
    );

    return res.rows.map((row) => ({
      id: row.id,
      familyId: row.family_id,
      userAgent: row.user_agent,
      createdAt: new Date(row.created_at).toISOString(),
      lastUsedAt: new Date(row.last_used_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString(),
      isCurrent: row.id === currentSessionId,
    }));
  }

  /**
   * Get user profile by ID from PostgreSQL
   */
  static async getUserProfile(userId: string): Promise<UserProfileDto | null> {
    const pool = getDatabasePool();
    const res = await pool.query(
      `SELECT id, email, display_name, avatar_url, role, is_active, data_retention_days, created_at
       FROM users WHERE id = $1`,
      [userId]
    );

    if (res.rows.length > 0) {
      const u = res.rows[0];
      return {
        id: u.id,
        email: u.email,
        displayName: u.display_name,
        avatarUrl: u.avatar_url,
        role: u.role,
        isActive: u.is_active,
        dataRetentionDays: u.data_retention_days,
        createdAt: new Date(u.created_at).toISOString(),
      };
    }
    return null;
  }
}
