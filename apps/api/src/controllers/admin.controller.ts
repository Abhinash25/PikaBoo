import { Request, Response } from 'express';
import { getDatabasePool } from '../config/database';

export class AdminController {
  /**
   * GET /api/v1/admin/users
   * Strict RBAC Test Endpoint: lists users (Admin role only)
   */
  static async listUsers(req: Request, res: Response) {
    const pool = getDatabasePool();
    try {
      const result = await pool.query(
        `SELECT id, email, display_name, role, is_active, data_retention_days, created_at
         FROM users
         ORDER BY created_at DESC
         LIMIT 50`
      );

      return res.json({
        success: true,
        data: {
          users: result.rows,
          total: result.rowCount,
          requestedBy: {
            id: req.user?.sub,
            role: req.user?.role,
          },
        },
        timestamp: new Date().toISOString(),
        requestId: (req as any).id || 'req-admin',
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        error: { code: 'DATABASE_ERROR', message: (err as Error).message },
        timestamp: new Date().toISOString(),
        requestId: (req as any).id || 'req-admin',
      });
    }
  }
}
