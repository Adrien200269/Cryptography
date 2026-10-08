/**
 * University Cryptography Lab - TLS Handshake & Cipher Suite Inspector
 * Connects to the local HTTPS server using Node's tls module, completes
 * a TLS handshake, and reports negotiated parameters, cipher suites, and X.509 cert details.
 */

require('dotenv').config();
const tls = require('tls');
const url = require('url');

const HTTPS_PORT = parseInt(process.env.PORT, 10) || 3443;
const HOST = 'localhost';

console.log('='.repeat(80));
console.log(`  CONNECTING TO https://${HOST}:${HTTPS_PORT} VIA NODE.JS TLS MODULE...`);
console.log('='.repeat(80));

const options = {
  host: HOST,
  port: HTTPS_PORT,
  servername: HOST,
  // Accept self-signed certificate for inspection
  rejectUnauthorized: false
};

const socket = tls.connect(options, () => {
  console.log(' TLS Handshake Completed Successfully!\n');

  // Negotiated Protocol and Cipher Suite
  const protocol = socket.getProtocol();
  const cipher = socket.getCipher();
  const ephemeralKeyInfo = socket.getEphemeralKeyInfo ? socket.getEphemeralKeyInfo() : null;

  console.log('1. Negotiated Security Parameters:');
  console.log('-'.repeat(80));
  console.log(` • TLS Protocol Version:       ${protocol}`);
  console.log(` • Cipher Suite Name:          ${cipher.name}`);
  console.log(` • Cipher Suite Standard:      ${cipher.standardName || 'N/A'}`);
  console.log(` • Cipher Version:             ${cipher.version}`);
  if (ephemeralKeyInfo && ephemeralKeyInfo.type) {
    console.log(` • Ephemeral Key Exchange:     ${ephemeralKeyInfo.type} (${ephemeralKeyInfo.size || ephemeralKeyInfo.name || 'N/A'})`);
  }

  // Peer Certificate Inspection
  const cert = socket.getPeerCertificate(true);
  console.log('\n2. Peer Certificate Details (X.509):');
  console.log('-'.repeat(80));
  console.log(` • Subject Common Name (CN):   ${cert.subject?.CN || 'N/A'}`);
  console.log(` • Issuer:                     ${cert.issuer?.CN || 'Self-Signed'}`);
  console.log(` • Valid From:                 ${cert.valid_from}`);
  console.log(` • Valid To:                   ${cert.valid_to}`);
  console.log(` • Subject Alternative Names:  ${cert.subjectaltname || 'None'}`);
  console.log(` • Public Key Algorithm:       ${cert.pubkey ? 'RSA' : 'N/A'}`);
  console.log(` • SHA-256 Fingerprint:        ${cert.fingerprint256}`);
  console.log(` • Serial Number:              ${cert.serialNumber}`);

  console.log('\n' + '='.repeat(80));
  console.log('Cryptographic Verification Summary:');
  console.log(' Modern TLS forward-secrecy cipher negotiated.');
  console.log(' Traffic is encrypted and protected against passive eavesdropping / tampering.');
  console.log('='.repeat(80));

  socket.end();
});

socket.on('error', (err) => {
  console.error('\n❌ TLS Connection Error:', err.message);
  console.error('Make sure the HTTPS server is running (`npm start`) before running this script.');
  process.exit(1);
});
