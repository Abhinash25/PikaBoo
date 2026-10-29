
-- Migration 004: Update VPN Server to Kali Bridged VM Endpoint

UPDATE vpn_servers 
SET 
    public_endpoint = '10.112.219.83',
    wireguard_public_key = 'FrlKmTQkFUab7rCzeFRgQ5amVb5Jfo/UwfADjC8qkGo=',
    node_api_token_hash = 'c8f3605cb3f2852e892c25ace792c339fdafac94d4b777803d8101822c42781b'
WHERE id = (SELECT id FROM vpn_servers LIMIT 1);
