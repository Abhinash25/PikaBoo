import React, { useState, useEffect } from 'react';
import { Shield, Download, AlertTriangle, Activity, Trash2, Server } from 'lucide-react';
import nacl from 'tweetnacl';

// Base64 encoding/decoding utilities since Buffer is not available in browser
function encodeBase64(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (byte) =>
    String.fromCharCode(byte)
  ).join("");
  return btoa(binString);
}

export function VpnManager() {
  const [loading, setLoading] = useState(false);
  const [configContent, setConfigContent] = useState<string | null>(null);
  const [stats, setStats] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [myPublicKey, setMyPublicKey] = useState<string | null>(null);

  const generateConfig = async () => {
    try {
      setLoading(true);
      setError(null);

      // 1. In-browser Key Generation (Zero storage)
      // tweetnacl generates X25519 keypair which is perfectly compatible with WireGuard
      const keyPair = nacl.box.keyPair();
      const privateKeyBase64 = encodeBase64(keyPair.secretKey);
      const publicKeyBase64 = encodeBase64(keyPair.publicKey);
      
      setMyPublicKey(publicKeyBase64);

      // 2. Send only the public key to the API
      const res = await fetch('/api/v1/vpn/devices', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          publicKey: publicKeyBase64
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to provision peer');
      }

      const { data } = await res.json();

      // 3. Construct the WireGuard .conf file
      const conf = `[Interface]
PrivateKey = ${privateKeyBase64}
Address = ${data.allocatedIp}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${data.serverPublicKey}
Endpoint = ${data.serverEndpoint}:51820
AllowedIPs = 0.0.0.0/0
`;
      
      setConfigContent(conf);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const downloadConf = () => {
    if (!configContent) return;
    const blob = new Blob([configContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'PrivacyGateway.conf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const fetchStats = async () => {
    if (!myPublicKey) return;
    try {
      const res = await fetch('/api/v1/vpn/status');
      if (res.ok) {
        const result = await res.json();
        if (result.data && result.data[myPublicKey]) {
          setStats(result.data[myPublicKey]);
        } else {
          setStats(null);
        }
      }
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  const revokeDevice = async () => {
    if (!myPublicKey) return;
    try {
      setLoading(true);
      await fetch(`/api/v1/vpn/devices/${encodeURIComponent(myPublicKey)}`, {
        method: 'DELETE'
      });
      setConfigContent(null);
      setStats(null);
      setMyPublicKey(null);
    } catch (err) {
      console.error('Failed to revoke:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (myPublicKey) {
      const interval = setInterval(fetchStats, 3000);
      return () => clearInterval(interval);
    }
  }, [myPublicKey]);

  return (
    <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-3 bg-emerald-500/10 rounded-xl">
          <Shield className="w-6 h-6 text-emerald-400" />
        </div>
        <div>
          <h2 className="text-xl font-semibold text-white">WireGuard VPN</h2>
          <p className="text-gray-400 text-sm">Real VPN Data Plane Configuration</p>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center gap-3 text-red-400">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <p className="text-sm">{error}</p>
        </div>
      )}

      {!configContent ? (
        <div className="space-y-4">
          <p className="text-sm text-gray-400">
            Generate a secure WireGuard configuration. The private key will be generated securely in your browser's memory and will <strong>never</strong> be sent to the server.
          </p>
          <button
            onClick={generateConfig}
            disabled={loading}
            className="w-full sm:w-auto px-6 py-3 bg-emerald-500 hover:bg-emerald-600 text-white font-medium rounded-xl transition-all disabled:opacity-50"
          >
            {loading ? 'Provisioning...' : 'Generate VPN Configuration'}
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl">
            <div className="flex gap-3 mb-2">
              <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0" />
              <h3 className="font-medium text-amber-500">Extremely Sensitive File</h3>
            </div>
            <p className="text-sm text-amber-400/80 pl-8">
              The downloaded file contains your WireGuard Private Key. It is the only copy. Do not share it. Import it into the official WireGuard client to connect.
            </p>
          </div>

          <div className="flex flex-wrap gap-4">
            <button
              onClick={downloadConf}
              className="flex items-center gap-2 px-6 py-3 bg-blue-500 hover:bg-blue-600 text-white font-medium rounded-xl transition-all"
            >
              <Download className="w-5 h-5" />
              Download PrivacyGateway.conf
            </button>
            <button
              onClick={revokeDevice}
              className="flex items-center gap-2 px-6 py-3 bg-red-500/10 hover:bg-red-500/20 text-red-400 font-medium rounded-xl transition-all border border-red-500/20"
            >
              <Trash2 className="w-5 h-5" />
              Revoke Access
            </button>
          </div>

          {/* Real VPN Status Panel */}
          <div className="mt-8 pt-8 border-t border-white/10">
            <h3 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
              <Activity className="w-5 h-5 text-emerald-400" />
              Real Connection Status
            </h3>
            
            {!stats ? (
              <div className="p-4 bg-white/5 rounded-xl border border-white/5 text-gray-400 text-sm flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-gray-500 animate-pulse"></div>
                Waiting for real handshake. Import the configuration and connect via WireGuard.
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 bg-white/5 rounded-xl border border-white/10">
                  <p className="text-sm text-gray-400 mb-1">Status</p>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></div>
                    <p className="font-medium text-emerald-400">VPN CONNECTED</p>
                  </div>
                </div>
                <div className="p-4 bg-white/5 rounded-xl border border-white/10">
                  <p className="text-sm text-gray-400 mb-1">Handshake</p>
                  <p className="font-medium text-white">
                    {stats.latestHandshake > 0 
                      ? new Date(stats.latestHandshake * 1000).toLocaleTimeString()
                      : 'None yet'}
                  </p>
                </div>
                <div className="p-4 bg-white/5 rounded-xl border border-white/10">
                  <p className="text-sm text-gray-400 mb-1">Tx Data</p>
                  <p className="font-medium text-white">{(stats.txBytes / 1024 / 1024).toFixed(2)} MB</p>
                </div>
                <div className="p-4 bg-white/5 rounded-xl border border-white/10">
                  <p className="text-sm text-gray-400 mb-1">Rx Data</p>
                  <p className="font-medium text-white">{(stats.rxBytes / 1024 / 1024).toFixed(2)} MB</p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
