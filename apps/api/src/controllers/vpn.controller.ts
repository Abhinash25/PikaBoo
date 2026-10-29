import { Request, Response } from 'express';
import { VpnService } from '../services/vpn.service';

export class VpnController {
  
  public static async getServers(req: Request, res: Response): Promise<void> {
    try {
      const pool = require('../config/database').getDatabasePool();
      const result = await pool.query(`
        SELECT id, node_name, country_code, city, capacity_peers, current_active_peers, is_active, health_status
        FROM vpn_servers
        WHERE is_maintenance = false
      `);
      res.status(200).json({ success: true, data: result.rows });
    } catch (error: any) {
      console.error('[VpnController] getServers error:', error);
      res.status(500).json({ error: error.message || 'Failed to fetch servers' });
    }
  }

  public static async provisionPeer(req: Request, res: Response): Promise<void> {
    try {
      // In a real app, userId comes from the JWT/session middleware.
      // For MVP testing, we assume the middleware sets req.user
      const user = (req as any).user;
      if (!user || !user.sub) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      
      const { publicKey, deviceId } = req.body;
      if (!publicKey) {
        res.status(400).json({ error: 'Missing public key' });
        return;
      }
      
      if (deviceId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(deviceId)) {
        res.status(400).json({ error: 'Invalid deviceId format' });
        return;
      }

      const config = await VpnService.provisionPeer(user.sub, deviceId || null, publicKey);
      
      res.status(201).json({
        success: true,
        data: config
      });
    } catch (error: any) {
      console.error('[VpnController] provisionPeer error:', error);
      res.status(500).json({ error: error.message || 'Failed to provision peer' });
    }
  }

  public static async revokePeer(req: Request, res: Response): Promise<void> {
    try {
      const user = (req as any).user;
      if (!user || !user.sub) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      const { publicKey } = req.params;
      if (!publicKey) {
        res.status(400).json({ error: 'Missing public key param' });
        return;
      }

      await VpnService.revokePeer(user.sub, decodeURIComponent(publicKey));
      
      res.status(200).json({ success: true, message: 'Peer revoked successfully' });
    } catch (error: any) {
      console.error('[VpnController] revokePeer error:', error);
      res.status(500).json({ error: error.message || 'Failed to revoke peer' });
    }
  }

  public static async getStats(req: Request, res: Response): Promise<void> {
    try {
      const user = (req as any).user;
      if (!user || !user.sub) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      // Fetch ALL real stats directly from the VPN node
      const stats = await VpnService.fetchRealStats();
      
      res.status(200).json({ success: true, data: stats });
    } catch (error: any) {
      console.error('[VpnController] getStats error:', error);
      res.status(500).json({ error: error.message || 'Failed to fetch stats' });
    }
  }
}
