import { Router } from 'express';
import { AdminController } from '../controllers/admin.controller';
import { requireAuth, requireRole } from '../middleware/auth.middleware';

const router = Router();

// Strict RBAC boundary: requires valid RS256 token AND role === 'admin'
router.get('/users', requireAuth, requireRole(['admin']), AdminController.listUsers);

export default router;
