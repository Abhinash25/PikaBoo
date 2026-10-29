import { Router } from 'express';
import { getHealthCheck, getLiveness, getReadiness } from '../controllers/health.controller';

const router = Router();

router.get('/', getHealthCheck);
router.get('/live', getLiveness);
router.get('/ready', getReadiness);

export default router;
