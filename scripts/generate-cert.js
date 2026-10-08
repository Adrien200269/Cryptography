/**
 * Cross-platform TLS Certificate Generator
 * Uses OpenSSL (via system PATH or Git for Windows location) to generate
 * self-signed certificate (cert.pem) and RSA private key (key.pem) with SAN.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');
const keyPath = path.join(rootDir, 'key.pem');
const certPath = path.join(rootDir, 'cert.pem');

function findOpenSSL() {
  try {
    execSync('openssl version', { stdio: 'ignore' });
    return 'openssl';
  } catch (e) {
    // Check Git for Windows default paths
    const gitPaths = [
      'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
      'C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe',
      'C:\\Git\\usr\\bin\\openssl.exe'
    ];
    for (const p of gitPaths) {
      if (fs.existsSync(p)) {
        return `"${p}"`;
      }
    }
  }
  return null;
}

const opensslCmd = findOpenSSL();

if (!opensslCmd) {
  console.error('Error: OpenSSL executable was not found on your system.');
  console.error('Please install OpenSSL or Git for Windows, or add OpenSSL to your PATH.');
  process.exit(1);
}

console.log(`Using OpenSSL binary: ${opensslCmd}`);
console.log('Generating 2048-bit RSA private key and self-signed certificate (CN=localhost, SAN=localhost, 127.0.0.1)...');

try {
  const cmd = `${opensslCmd} req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "${keyPath}" -out "${certPath}" -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"`;
  execSync(cmd, { stdio: 'inherit' });

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    console.log(' Successfully generated:');
    console.log(`  - Private Key: ${keyPath}`);
    console.log(`  - Certificate: ${certPath}`);
  } else {
    throw new Error('Key or certificate file was not created.');
  }
} catch (error) {
  console.error('Failed to generate certificates:', error.message);
  process.exit(1);
}
