import { Router } from 'express';
import { getSystemInfo, getMigrationsStatus } from '../controllers/system.controller';

const router = Router();

router.get('/info', getSystemInfo);
router.get('/migrations', getMigrationsStatus);

export default router;
