import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);
const app = express();
app.use(helmet());
app.use(express.json());

const NODE_API_TOKEN = process.env.NODE_API_TOKEN;
const WG_INTERFACE = process.env.WG_INTERFACE || 'wg0';

if (!NODE_API_TOKEN) {
  console.error('FATAL: NODE_API_TOKEN must be set');
  process.exit(1);
}

// Authentication middleware
const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${NODE_API_TOKEN}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// Public health endpoint
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use(requireAuth);

const isValidPublicKey = (key: string) => /^[A-Za-z0-9+/]{43}=$/.test(key);
const isValidIpv4 = (ip: string) => /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(\/32)?$/.test(ip);

// Add a new peer
app.post('/peers', async (req: Request, res: Response) => {
  const { publicKey, allowedIp } = req.body;

  if (!publicKey || !isValidPublicKey(publicKey)) {
    return res.status(400).json({ error: 'Invalid public key' });
  }
  if (!allowedIp || !isValidIpv4(allowedIp)) {
    return res.status(400).json({ error: 'Invalid IPv4' });
  }

  // Format: 10.8.0.2/32
  const ipWithCidr = allowedIp.includes('/') ? allowedIp : `${allowedIp}/32`;

  try {
    // wg set wg0 peer <pubkey> allowed-ips <ip>/32
    await execFileAsync('wg', ['set', WG_INTERFACE, 'peer', publicKey, 'allowed-ips', ipWithCidr]);
    console.log(`[WG] Added peer ${publicKey} with IP ${ipWithCidr}`);
    return res.status(200).json({ success: true, message: 'Peer added' });
  } catch (error: any) {
    console.error(`[WG ERROR] Failed to add peer:`, error.message);
    return res.status(500).json({ error: 'Failed to add peer to interface' });
  }
});

// Remove a peer
app.delete('/peers/:publicKey', async (req: Request, res: Response) => {
  const publicKey = decodeURIComponent(req.params.publicKey);

  if (!isValidPublicKey(publicKey)) {
    return res.status(400).json({ error: 'Invalid public key' });
  }

  try {
    // wg set wg0 peer <pubkey> remove
    await execFileAsync('wg', ['set', WG_INTERFACE, 'peer', publicKey, 'remove']);
    console.log(`[WG] Removed peer ${publicKey}`);
    return res.status(200).json({ success: true, message: 'Peer removed' });
  } catch (error: any) {
    console.error(`[WG ERROR] Failed to remove peer:`, error.message);
    return res.status(500).json({ error: 'Failed to remove peer from interface' });
  }
});

// Get peer statistics
app.get('/peers/stats', async (req: Request, res: Response) => {
  try {
    // Output format for 'wg show <intf> dump':
    // private-key, public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive
    const { stdout } = await execFileAsync('wg', ['show', WG_INTERFACE, 'dump']);
    const lines = stdout.trim().split('\n');
    
    // First line is the interface info, skip it
    const peerLines = lines.slice(1);
    
    const stats: Record<string, any> = {};
    
    for (const line of peerLines) {
      if (!line) continue;
      const parts = line.split('\t');
      if (parts.length >= 8) {
        const pubKey = parts[1];
        stats[pubKey] = {
          endpoint: parts[3] === '(none)' ? null : parts[3],
          allowedIps: parts[4],
          latestHandshake: parseInt(parts[5], 10),
          rxBytes: parseInt(parts[6], 10),
          txBytes: parseInt(parts[7], 10)
        };
      }
    }
    
    return res.status(200).json(stats);
  } catch (error: any) {
    console.error(`[WG ERROR] Failed to fetch stats:`, error.message);
    return res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});


const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`[Node Controller] Listening on port ${PORT}`);
  console.log(`[Node Controller] Managing WireGuard interface: ${WG_INTERFACE}`);
});
