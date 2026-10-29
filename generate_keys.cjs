const crypto = require('crypto');
const fs = require('fs');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const formattedPrivateKey = privateKey.replace(/\n/g, '\\n');
const formattedPublicKey = publicKey.replace(/\n/g, '\\n');

const envContent = `\nJWT_PRIVATE_KEY_PEM="${formattedPrivateKey}"\nJWT_PUBLIC_KEY_PEM="${formattedPublicKey}"\nJWT_KEY_ID=pg-prod-1\nJWT_ISSUER=privacy-gateway\nJWT_AUDIENCE=privacy-gateway-client\n`;

fs.appendFileSync('.env', envContent);
console.log('JWT keys appended to .env');
