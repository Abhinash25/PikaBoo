import { Request, Response } from 'express';
import crypto from 'node:crypto';
import { getEnv } from '../config/env';
import { AuthService } from '../services/auth.service';
import { AuthenticatedRequest } from '../middleware/auth.middleware';
import { checkDatabaseHealth } from '../config/database';
import { checkRedisHealth } from '../config/redis';

/**
 * Compute S256 PKCE code challenge
 */
function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Determine dynamic redirect URI matching runtime container or localhost
 */
export function getResolvedRedirectUri(req: Request): string {
  const env = getEnv();
  // If explicitly configured in environment, use it
  if (process.env.GOOGLE_REDIRECT_URI && process.env.GOOGLE_REDIRECT_URI.trim().length > 0) {
    return process.env.GOOGLE_REDIRECT_URI.trim();
  }
  // Otherwise in development default to dynamic request origin
  const proto = (req.headers['x-forwarded-proto'] as string) || req.protocol || 'http';
  const host = req.get('host') || 'localhost:3000';
  return `${proto}://${host}/api/v1/auth/google/callback`;
}

/**
 * Configure standard HTTP authentication cookies with iframe compatibility
 */
function setAuthCookies(
  req: Request,
  res: Response,
  accessToken: string,
  refreshToken: string,
  csrfToken: string
) {
  const isHttpsOrIframe =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    process.env.NODE_ENV === 'production' ||
    Boolean(req.headers['sec-fetch-dest'] === 'iframe');

  const sameSite = isHttpsOrIframe ? ('none' as const) : ('lax' as const);
  const secure = isHttpsOrIframe;

  // 15-minute access token
  res.cookie('pg_access_token', accessToken, {
    httpOnly: true,
    secure,
    sameSite,
    path: '/',
    maxAge: 15 * 60 * 1000,
  });

  // 30-day refresh token restricted to /api/v1/auth path
  res.cookie('pg_refresh_token', refreshToken, {
    httpOnly: true,
    secure,
    sameSite,
    path: '/api/v1/auth',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });

  // CSRF Double-Submit token (accessible to client JS)
  res.cookie('pg_csrf_token', csrfToken, {
    httpOnly: false,
    secure,
    sameSite,
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

/**
 * Clear authentication cookies on logout
 */
function clearAuthCookies(req: Request, res: Response) {
  const isHttpsOrIframe =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    process.env.NODE_ENV === 'production';

  const sameSite = isHttpsOrIframe ? ('none' as const) : ('lax' as const);
  const secure = isHttpsOrIframe;

  res.clearCookie('pg_access_token', { httpOnly: true, secure, sameSite, path: '/' });
  res.clearCookie('pg_refresh_token', { httpOnly: true, secure, sameSite, path: '/api/v1/auth' });
  res.clearCookie('pg_csrf_token', { httpOnly: false, secure, sameSite, path: '/' });
}

export class AuthController {
  /**
   * GET /api/v1/auth/google/start
   * Initiates Google OIDC flow, stores transaction in Redis, and returns URL or 302
   */
  static async startGoogleAuth(req: Request, res: Response) {
    const env = getEnv();
    const state = crypto.randomBytes(32).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const redirectUri = getResolvedRedirectUri(req);

    const returnTo =
      typeof req.query.return_to === 'string' && req.query.return_to.startsWith('/')
        ? req.query.return_to
        : '/';

    try {
      // Store in Redis with 5 min TTL
      await AuthService.saveOAuthState(state, {
        nonce,
        codeVerifier,
        returnTo,
        createdAt: Date.now(),
      });
    } catch (err) {
      AuthService.recordDiagnostic({
        step: 'OAUTH_START',
        status: 'FAIL',
        category: 'REDIS_ERROR',
        details: (err as Error).message,
      });

      if (req.query.mode === 'json' || req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(503).json({
          success: false,
          error: { code: 'OAUTH_STATE_ERROR', message: 'Authentication service temporarily unavailable' },
          timestamp: new Date().toISOString(),
        });
      }

      return res.status(503).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Authentication Error - Privacy Gateway</title>
          <style>
            body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 16px; }
            .card { background: #1e293b; border: 1px solid #ef4444; border-radius: 12px; max-width: 480px; width: 100%; padding: 24px; }
            .badge { display: inline-block; padding: 4px 8px; background: rgba(239, 68, 68, 0.2); color: #ef4444; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 12px; }
            h2 { margin: 0 0 8px 0; font-size: 18px; color: #f1f5f9; }
            p { color: #94a3b8; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }
            .btn { display: inline-block; padding: 10px 18px; background: #3b82f6; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 500; font-size: 14px; border: none; cursor: pointer; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="badge">AUTH_SERVICE_UNAVAILABLE</div>
            <h2>Service Unavailable</h2>
            <p>The authentication state service (Redis) is currently unreachable. Please try again later.</p>
            <button class="btn" onclick="window.location.href='/'">Return to Dashboard</button>
          </div>
        </body>
        </html>
      `);
    }

    const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    googleAuthUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
    googleAuthUrl.searchParams.set('response_type', 'code');
    googleAuthUrl.searchParams.set('scope', 'openid email profile');
    googleAuthUrl.searchParams.set('redirect_uri', redirectUri);
    googleAuthUrl.searchParams.set('state', state);
    googleAuthUrl.searchParams.set('nonce', nonce);
    googleAuthUrl.searchParams.set('code_challenge', codeChallenge);
    googleAuthUrl.searchParams.set('code_challenge_method', 'S256');
    googleAuthUrl.searchParams.set('prompt', 'select_account');

    AuthService.recordDiagnostic({
      step: 'OAUTH_START',
      status: 'PASS',
      details: `Generated PKCE S256 parameters. Redirect URI: ${redirectUri}`,
    });

    // If caller requested JSON (e.g. for popup window flow in iframe)
    if (req.query.mode === 'json' || req.xhr || req.headers.accept?.includes('application/json')) {
      const isPlaceholder =
        env.GOOGLE_CLIENT_ID.startsWith('dev_') ||
        env.GOOGLE_CLIENT_ID.includes('placeholder');

      return res.json({
        success: true,
        url: googleAuthUrl.toString(),
        redirectUri,
        isPlaceholderClientId: isPlaceholder,
        clientId: env.GOOGLE_CLIENT_ID,
      });
    }

    return res.redirect(googleAuthUrl.toString());
  }

  /**
   * GET /api/v1/auth/google/callback
   * Atomic state consumption via GETDEL, Google token exchange, user resolution, and session creation
   */
  static async handleGoogleCallback(req: Request, res: Response) {
    const env = getEnv();
    const { code, state, error } = req.query;
    const redirectUri = getResolvedRedirectUri(req);

    let clientOrigin = 'http://localhost:3000';
    if (env.CORS_ORIGIN && env.CORS_ORIGIN !== '*') {
      clientOrigin = env.CORS_ORIGIN.split(',')[0].trim();
    }

    // Explicit Google Callback Error Handling
    if (error) {
      const sanitizedError = String(error).replace(/[^a-zA-Z0-9_-]/g, '');
      AuthService.recordDiagnostic({
        step: 'GOOGLE_AUTH_URL',
        status: 'FAIL',
        category: sanitizedError,
        details: 'Google OAuth authorization cancelled or returned error',
      });

      return res.status(400).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Google Sign-In Cancelled - Privacy Gateway</title>
          <style>
            body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 16px; }
            .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; max-width: 480px; width: 100%; padding: 24px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
            .badge { display: inline-block; padding: 4px 8px; background: rgba(239, 68, 68, 0.2); color: #ef4444; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 12px; }
            h2 { margin: 0 0 8px 0; font-size: 18px; color: #f1f5f9; }
            p { color: #94a3b8; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }
            .btn { display: inline-block; padding: 10px 18px; background: #3b82f6; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 500; font-size: 14px; border: none; cursor: pointer; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="badge">OAUTH_ERROR: ${sanitizedError}</div>
            <h2>Google Authentication Cancelled</h2>
            <p>Google authentication was cancelled or rejected (${sanitizedError}). No credentials or sessions were stored.</p>
            <button class="btn" onclick="if(window.opener){window.opener.postMessage({type:'OAUTH_AUTH_ERROR',error:'${sanitizedError}'},'${clientOrigin}');window.close();}else{window.location.href='/';}">Return to Dashboard</button>
          </div>
          <script>
            if (window.opener) {
              window.opener.postMessage({ type: 'OAUTH_AUTH_ERROR', error: '${sanitizedError}' }, '${clientOrigin}');
            }
          </script>
        </body>
        </html>
      `);
    }

    if (typeof code !== 'string' || typeof state !== 'string') {
      AuthService.recordDiagnostic({
        step: 'CALLBACK_RECEIVED',
        status: 'FAIL',
        category: 'MISSING_PARAMETERS',
        details: 'Callback invoked without code or state parameters',
      });
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_OAUTH_CALLBACK', message: 'Missing code or state in callback' },
        timestamp: new Date().toISOString(),
      });
    }

    AuthService.recordDiagnostic({
      step: 'CALLBACK_RECEIVED',
      status: 'PASS',
      details: 'Received callback parameters from authorization server',
    });

    // Atomic consumption from Redis (GETDEL)
    const transaction = await AuthService.consumeOAuthState(state);
    if (!transaction) {
      return res.status(400).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>OAuth State Expired - Privacy Gateway</title>
          <style>
            body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 16px; }
            .card { background: #1e293b; border: 1px solid #ef4444; border-radius: 12px; max-width: 480px; width: 100%; padding: 24px; }
            .badge { display: inline-block; padding: 4px 8px; background: rgba(239, 68, 68, 0.2); color: #ef4444; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 12px; }
            h2 { margin: 0 0 8px 0; font-size: 18px; color: #f1f5f9; }
            p { color: #94a3b8; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }
            .btn { display: inline-block; padding: 10px 18px; background: #3b82f6; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 500; font-size: 14px; border: none; cursor: pointer; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="badge">OAUTH_STATE_INVALID_OR_EXPIRED</div>
            <h2>Authentication State Invalid or Expired</h2>
            <p>OAuth state was not found or already consumed. Please restart the sign-in flow.</p>
            <button class="btn" onclick="if(window.opener){window.opener.postMessage({type:'OAUTH_AUTH_ERROR',error:'OAUTH_STATE_INVALID_OR_EXPIRED'},'${clientOrigin}');window.close();}else{window.location.href='/';}">Restart Sign-In</button>
          </div>
        </body>
        </html>
      `);
    }

    try {
      // Server-to-server TLS token exchange with Google
      const { idToken } = await AuthService.exchangeGoogleCode(
        code,
        transaction.codeVerifier,
        redirectUri
      );

      // Verify claims and issue session
      const userAgent = req.headers['user-agent'] || 'Unknown Browser';
      const authResult = await AuthService.processGoogleAuth(
        idToken,
        env.GOOGLE_CLIENT_ID,
        transaction.nonce,
        userAgent
      );

      // Issue HTTPOnly Cookies
      setAuthCookies(
        req,
        res,
        authResult.accessToken,
        authResult.refreshToken,
        authResult.csrfToken
      );

      AuthService.recordDiagnostic({
        step: 'COOKIES_ISSUED',
        status: 'PASS',
        details: 'Issued pg_access_token, pg_refresh_token, and pg_csrf_token cookies',
      });

      // Deliver popup postMessage bridge or redirect with strict origin targeting
      return res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Authentication Complete - Privacy Gateway</title>
          <style>
            body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 16px; }
            .card { background: #1e293b; border: 1px solid #10b981; border-radius: 12px; max-width: 480px; width: 100%; padding: 24px; text-align: center; }
            .badge { display: inline-block; padding: 4px 8px; background: rgba(16, 185, 129, 0.2); color: #10b981; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 12px; }
            h2 { margin: 0 0 8px 0; font-size: 18px; color: #f1f5f9; }
            p { color: #94a3b8; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="badge">AUTHENTICATION_SUCCESS</div>
            <h2>Sign-In Complete</h2>
            <p>Your session has been established. Closing window...</p>
          </div>
          <script>
            if (window.opener) {
              window.opener.postMessage({ type: 'OAUTH_AUTH_SUCCESS' }, '${clientOrigin}');
              window.close();
            } else {
              window.location.href = '${transaction.returnTo || '/'}';
            }
          </script>
        </body>
        </html>
      `);
    } catch (err) {
      const errMsg = (err as Error).message;
      const sanitizedMsg = errMsg.replace(/[^a-zA-Z0-9_:\s-]/g, '');

      return res.status(400).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Authentication Error - Privacy Gateway</title>
          <style>
            body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 16px; }
            .card { background: #1e293b; border: 1px solid #ef4444; border-radius: 12px; max-width: 480px; width: 100%; padding: 24px; }
            .badge { display: inline-block; padding: 4px 8px; background: rgba(239, 68, 68, 0.2); color: #ef4444; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 12px; }
            h2 { margin: 0 0 8px 0; font-size: 18px; color: #f1f5f9; }
            p { color: #94a3b8; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }
            .btn { display: inline-block; padding: 10px 18px; background: #3b82f6; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 500; font-size: 14px; border: none; cursor: pointer; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="badge">AUTH_FAILED</div>
            <h2>Authentication Processing Failed</h2>
            <p>${sanitizedMsg}</p>
            <button class="btn" onclick="if(window.opener){window.opener.postMessage({type:'OAUTH_AUTH_ERROR',error:'${sanitizedMsg}'},'${clientOrigin}');window.close();}else{window.location.href='/';}">Return to Dashboard</button>
          </div>
          <script>
            if (window.opener) {
              window.opener.postMessage({ type: 'OAUTH_AUTH_ERROR', error: '${sanitizedMsg}' }, '${clientOrigin}');
            }
          </script>
        </body>
        </html>
      `);
    }
  }

  /**
   * GET /api/v1/auth/diagnostics
   * Development-only safe OAuth diagnostic metadata (Never exposes secrets or tokens)
   */
  static async getDiagnostics(req: Request, res: Response) {
    const env = getEnv();
    if (env.NODE_ENV === 'production') {
      return res.status(403).json({
        success: false,
        error: { code: 'FORBIDDEN', message: 'Diagnostic endpoint disabled in production mode' },
      });
    }

    const resolvedRedirectUri = getResolvedRedirectUri(req);
    let currentOrigin = 'http://localhost:3000';
    if (env.CORS_ORIGIN && env.CORS_ORIGIN !== '*') {
      currentOrigin = env.CORS_ORIGIN.split(',')[0].trim();
    }

    const isPlaceholder =
      env.GOOGLE_CLIENT_ID.startsWith('dev_') ||
      env.GOOGLE_CLIENT_ID.includes('placeholder');

    const [dbHealth, redisHealth] = await Promise.all([
      checkDatabaseHealth(),
      checkRedisHealth(),
    ]);

    const events = AuthService.getDiagnostics();

    return res.json({
      success: true,
      data: {
        oauthConfiguration: {
          googleClientIdConfigured: !isPlaceholder && env.GOOGLE_CLIENT_ID.length > 20,
          googleClientSecretConfigured: !env.GOOGLE_CLIENT_SECRET.startsWith('dev_'),
          isPlaceholderClientId: isPlaceholder,
          resolvedRedirectUri,
          currentOrigin,
        },
        services: {
          database: dbHealth.status,
          redis: redisHealth.status,
        },
        history: events,
      },
    });
  }

  /**
   * POST /api/v1/auth/desktop/google/exchange
   * RFC 8252 Native Desktop client PKCE exchange endpoint
   */
  static async desktopGoogleExchange(req: Request, res: Response) {
    const env = getEnv();
    const { code, code_verifier, redirect_uri } = req.body;

    if (!code || !code_verifier || !redirect_uri) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'MISSING_PARAMETERS',
          message: 'code, code_verifier, and redirect_uri are required',
        },
        timestamp: new Date().toISOString(),
      });
    }

    try {
      const url = new URL(redirect_uri);
      const isLoopback =
        url.hostname === '127.0.0.1' ||
        url.hostname === 'localhost' ||
        url.hostname === '[::1]';
      if (!isLoopback) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_REDIRECT_URI',
            message: 'Desktop OAuth redirect URI must target loopback address (RFC 8252)',
          },
          timestamp: new Date().toISOString(),
        });
      }
    } catch {
      return res.status(400).json({
        success: false,
        error: { code: 'MALFORMED_REDIRECT_URI', message: 'redirect_uri is not a valid URL' },
        timestamp: new Date().toISOString(),
      });
    }

    try {
      const { idToken } = await AuthService.exchangeGoogleCode(
        code,
        code_verifier,
        redirect_uri,
        env.GOOGLE_DESKTOP_CLIENT_ID || env.GOOGLE_CLIENT_ID,
        ''
      );

      const userAgent = req.headers['user-agent'] || 'PrivacyGateway-DesktopNative';
      const authResult = await AuthService.processGoogleAuth(
        idToken,
        env.GOOGLE_DESKTOP_CLIENT_ID || env.GOOGLE_CLIENT_ID,
        undefined,
        userAgent
      );

      return res.json({
        success: true,
        data: {
          accessToken: authResult.accessToken,
          refreshToken: authResult.refreshToken,
          user: authResult.user,
          sessionId: authResult.sessionId,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      return res.status(400).json({
        success: false,
        error: { code: 'NATIVE_AUTH_FAILED', message: (err as Error).message },
        timestamp: new Date().toISOString(),
      });
    }
  }

  /**
   * POST /api/v1/auth/refresh
   * Rotates refresh token within family with CSRF and Replay protection
   */
  static async refreshSession(req: Request, res: Response) {
    const rawRefreshToken =
      req.cookies?.pg_refresh_token ||
      (req.headers['x-refresh-token'] as string | undefined);

    if (!rawRefreshToken) {
      return res.status(401).json({
        success: false,
        error: { code: 'MISSING_REFRESH_TOKEN', message: 'Refresh token cookie or header missing' },
        timestamp: new Date().toISOString(),
      });
    }

    try {
      const userAgent = req.headers['user-agent'] || 'Unknown Browser';
      const result = await AuthService.rotateSessionToken(rawRefreshToken, userAgent);

      setAuthCookies(
        req,
        res,
        result.accessToken,
        result.newRefreshToken,
        result.csrfToken
      );

      return res.json({
        success: true,
        data: {
          user: result.user,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      const msg = (err as Error).message;
      clearAuthCookies(req, res);

      if (msg === 'TOKEN_FAMILY_REVOKED_REPLAY_DETECTED') {
        return res.status(401).json({
          success: false,
          error: {
            code: 'TOKEN_FAMILY_REVOKED_REPLAY_DETECTED',
            message: 'Suspicious session replay detected. All active sessions in this family have been revoked.',
          },
          timestamp: new Date().toISOString(),
        });
      }

      return res.status(401).json({
        success: false,
        error: { code: 'REFRESH_FAILED', message: msg },
        timestamp: new Date().toISOString(),
      });
    }
  }

  /**
   * POST /api/v1/auth/logout
   * Revokes current session and destroys cookies
   */
  static async logout(req: Request, res: Response) {
    const rawRefreshToken = req.cookies?.pg_refresh_token;
    if (rawRefreshToken) {
      try {
        await AuthService.revokeSessionByToken(rawRefreshToken);
      } catch {
        // quiet
      }
    }

    clearAuthCookies(req, res);

    return res.json({
      success: true,
      data: { message: 'Logged out successfully' },
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * GET /api/v1/auth/me
   * Stateless user profile inspection
   */
  static async getMe(req: AuthenticatedRequest, res: Response) {
    if (!req.user) {
      AuthService.recordDiagnostic({
        step: 'AUTH_ME',
        status: 'FAIL',
        category: 'UNAUTHENTICATED',
        details: 'No verified access token in request context',
      });
      return res.status(401).json({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
        timestamp: new Date().toISOString(),
      });
    }

    const userProfile = await AuthService.getUserProfile(req.user.sub);
    if (!userProfile) {
      AuthService.recordDiagnostic({
        step: 'AUTH_ME',
        status: 'FAIL',
        category: 'USER_NOT_FOUND',
        details: 'Identity not found in database',
      });
      return res.status(404).json({
        success: false,
        error: { code: 'USER_NOT_FOUND', message: 'User record not found' },
        timestamp: new Date().toISOString(),
      });
    }

    AuthService.recordDiagnostic({
      step: 'AUTH_ME',
      status: 'PASS',
      details: 'User authenticated via RS256 token',
    });

    return res.json({
      success: true,
      data: {
        user: userProfile,
        sessionId: req.user.sessionId,
      },
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * GET /api/v1/auth/sessions
   * List active sessions for authenticated user
   */
  static async listSessions(req: AuthenticatedRequest, res: Response) {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
        timestamp: new Date().toISOString(),
      });
    }

    const sessions = await AuthService.listUserSessions(req.user.sub, req.user.sessionId);

    return res.json({
      success: true,
      data: sessions,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * DELETE /api/v1/auth/sessions/:id
   * Revoke individual session by ID
   */
  static async revokeSession(req: AuthenticatedRequest, res: Response) {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
        timestamp: new Date().toISOString(),
      });
    }

    const { id } = req.params;
    const success = await AuthService.revokeSession(id, req.user.sub);

    if (!success) {
      return res.status(404).json({
        success: false,
        error: { code: 'SESSION_NOT_FOUND', message: 'Session not found or already revoked' },
        timestamp: new Date().toISOString(),
      });
    }

    return res.json({
      success: true,
      data: { message: 'Session revoked successfully' },
      timestamp: new Date().toISOString(),
    });
  }
}
