import { getDatabasePool } from '../config/database';
import crypto from 'crypto';

export class VpnService {
  // Utility: Convert IPv4 to number
  private static ipToNum(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }

  // Utility: Convert number to IPv4
  private static numToIp(num: number): string {
    return [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255
    ].join('.');
  }

  // Utility: parse CIDR (e.g. 10.8.0.0/24) to min/max IP numbers
  private static parseCidr(cidr: string): { min: number, max: number } {
    const [ip, mask] = cidr.split('/');
    const bitMask = -1 << (32 - parseInt(mask, 10));
    const ipNum = this.ipToNum(ip);
    const networkNum = ipNum & bitMask;
    const broadcastNum = networkNum | (~bitMask);
    // Usually .0 is network and .255 is broadcast. So usable IPs are between networkNum + 1 and broadcastNum - 1.
    // However, for wg we can technically use .0 and .255 if /32, but standard practice is +1 to -1.
    // We will reserve .1 for the VPN server itself. So usable starts at .2.
    return {
      min: networkNum + 2,
      max: broadcastNum - 1
    };
  }

  public static async provisionPeer(userId: string, deviceId: string | null, publicKey: string): Promise<{
    serverPublicKey: string,
    serverEndpoint: string,
    allocatedIp: string
  }> {
    const pool = getDatabasePool();
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      // 1. Lock the vpn_servers table to prevent concurrent IP allocation race conditions
      // In a multi-region setup, we'd pick the best server. For MVP, just get the active one.
      const serverRes = await client.query(`
        SELECT id, public_endpoint, wireguard_public_key, ipv4_subnet, node_api_token_hash 
        FROM vpn_servers 
        WHERE is_active = true AND health_status = 'healthy'
        LIMIT 1 
        FOR UPDATE
      `);

      if (serverRes.rows.length === 0) {
        throw new Error('No available VPN servers');
      }

      const server = serverRes.rows[0];
      const { min: minIp, max: maxIp } = this.parseCidr(server.ipv4_subnet);

      // 2. Find all currently allocated IPs for this server
      const peersRes = await client.query(`
        SELECT allocated_ipv4 FROM wireguard_peers 
        WHERE vpn_server_id = $1 AND status != 'revoked'
      `, [server.id]);

      const allocatedIps = new Set(peersRes.rows.map(row => this.ipToNum(row.allocated_ipv4.split('/')[0])));

      // 3. Find the lowest available IP
      let assignedIpNum: number | null = null;
      for (let ipNum = minIp; ipNum <= maxIp; ipNum++) {
        if (!allocatedIps.has(ipNum)) {
          assignedIpNum = ipNum;
          break;
        }
      }

      if (assignedIpNum === null) {
        throw new Error('IP address exhaustion on selected VPN server');
      }

      const allocatedIpv4 = this.numToIp(assignedIpNum);

      // 4. Insert the peer into the database
      const insertRes = await client.query(`
        INSERT INTO wireguard_peers (user_id, device_id, vpn_server_id, public_key, allocated_ipv4, status)
        VALUES ($1, $2, $3, $4, $5, 'active')
        RETURNING id
      `, [userId, deviceId, server.id, publicKey, allocatedIpv4]);

      // 5. Send RPC command to the VPN Node Controller
      // The API knows the endpoint to reach the internal VPN controller (e.g. pg_vpn:4000)
      // In MVP, we hardcode the internal docker hostname `vpn:4000` or read from ENV
      const vpnRpcUrl = process.env.VPN_RPC_URL || 'http://vpn:4000';
      const vpnRpcToken = process.env.VPN_NODE_API_TOKEN || 'dev_secret_token_123'; 

      const rpcResponse = await fetch(`${vpnRpcUrl}/peers`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${vpnRpcToken}`
        },
        body: JSON.stringify({
          publicKey,
          allowedIp: allocatedIpv4
        })
      });

      if (!rpcResponse.ok) {
        const errData = await rpcResponse.text();
        throw new Error(`VPN Node RPC failed: ${errData}`);
      }

      await client.query('COMMIT');

      return {
        serverPublicKey: server.wireguard_public_key,
        serverEndpoint: server.public_endpoint,
        allocatedIp: allocatedIpv4
      };

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  public static async revokePeer(userId: string, publicKey: string): Promise<void> {
    const pool = getDatabasePool();
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');
      
      const peerRes = await client.query(`
        UPDATE wireguard_peers SET status = 'revoked', updated_at = CURRENT_TIMESTAMP
        WHERE user_id = $1 AND public_key = $2 AND status IN ('active', 'inactive')
        RETURNING id
      `, [userId, publicKey]);

      if (peerRes.rows.length === 0) {
        throw new Error('Peer not found or already revoked');
      }

      const vpnRpcUrl = process.env.VPN_RPC_URL || 'http://vpn:4000';
      const vpnRpcToken = process.env.VPN_NODE_API_TOKEN || 'dev_secret_token_123'; 

      const encodedPubKey = encodeURIComponent(publicKey);
      const rpcResponse = await fetch(`${vpnRpcUrl}/peers/${encodedPubKey}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${vpnRpcToken}`
        }
      });

      if (!rpcResponse.ok) {
        const errData = await rpcResponse.text();
        throw new Error(`VPN Node RPC failed: ${errData}`);
      }

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  public static async fetchRealStats(): Promise<Record<string, any>> {
    const vpnRpcUrl = process.env.VPN_RPC_URL || 'http://vpn:4000';
    const vpnRpcToken = process.env.VPN_NODE_API_TOKEN || 'dev_secret_token_123'; 

    const rpcResponse = await fetch(`${vpnRpcUrl}/peers/stats`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${vpnRpcToken}`
      }
    });

    if (!rpcResponse.ok) {
        throw new Error(`VPN Node RPC stats failed`);
    }

    return await rpcResponse.json();
  }
}
