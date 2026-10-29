import { Router } from 'express';
import { VpnController } from '../controllers/vpn.controller';
import { requireAuth } from '../middleware/auth.middleware';

const router = Router();

router.get('/servers', requireAuth, VpnController.getServers);
router.post('/devices', requireAuth, VpnController.provisionPeer);
router.delete('/devices/:publicKey', requireAuth, VpnController.revokePeer);
router.get('/status', requireAuth, VpnController.getStats);

export default router;

