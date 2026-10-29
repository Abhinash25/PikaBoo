import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { requireAuth } from '../middleware/auth.middleware';
import { requireCsrf } from '../middleware/csrf.middleware';

const router = Router();

// 1. Google OAuth Web Flow
router.get('/google/start', AuthController.startGoogleAuth);
router.get('/google/callback', AuthController.handleGoogleCallback);

// 2. Native Desktop PKCE Exchange (RFC 8252)
router.post('/desktop/google/exchange', AuthController.desktopGoogleExchange);

// 3. Token Family Refresh (CSRF Protected by default for cookie auth)
router.post('/refresh', requireCsrf, AuthController.refreshSession);

// 4. Logout (CSRF Protected)
router.post('/logout', requireCsrf, AuthController.logout);

// 5. Authenticated User Profile & Sessions
router.get('/me', requireAuth, AuthController.getMe);
router.get('/sessions', requireAuth, AuthController.listSessions);
router.delete('/sessions/:id', requireAuth, requireCsrf, AuthController.revokeSession);

// 6. Safe OAuth Diagnostics & Environment Status (Zero Secret Exposure)
router.get('/diagnostics', AuthController.getDiagnostics);

export default router;
