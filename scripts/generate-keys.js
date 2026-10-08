/**
 * University Cryptography Lab - Key Generation Utility
 * Generates cryptographically secure random keys (CSPRNG) using Node.js crypto.randomBytes.
 * Produces:
 *  - AES_KEY: 256-bit (32 bytes) hex key for AES-256-GCM authenticated encryption
 *  - HMAC_KEY: 256-bit (32 bytes) hex key for HMAC-SHA256 blind indexing
 *  - SESSION_SECRET: 256-bit (32 bytes) hex key for express-session signing
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const envPath = path.join(__dirname, '..', '.env');
const envExamplePath = path.join(__dirname, '..', '.env.example');

const aesKey = crypto.randomBytes(32).toString('hex');
const hmacKey = crypto.randomBytes(32).toString('hex');
const sessionSecret = crypto.randomBytes(32).toString('hex');

const envContent = `# Server Network Configuration
PORT=3443
HTTP_PORT=3000

# Database Connection (MongoDB)
# Local instance or Atlas (e.g. mongodb+srv://<user>:<password>@cluster0.example.mongodb.net/secure_auth_lab)
MONGODB_URI=mongodb://127.0.0.1:27017/secure_auth_lab

# Cryptographic Keys (CSPRNG 256-bit hex)
# AES-256-GCM symmetric key for authenticated data encryption
AES_KEY=${aesKey}

# HMAC-SHA256 secret key for deterministic blind indexing
HMAC_KEY=${hmacKey}

# Session signature secret for tamper-proof cookie validation
SESSION_SECRET=${sessionSecret}

# Environment
NODE_ENV=development
`;

fs.writeFileSync(envPath, envContent, { encoding: 'utf8' });
console.log(' Successfully generated cryptographically secure keys and created .env file.');
console.log('--------------------------------------------------------------------------------');
console.log('AES_KEY (256-bit hex):       ', aesKey);
console.log('HMAC_KEY (256-bit hex):      ', hmacKey);
console.log('SESSION_SECRET (256-bit hex):', sessionSecret);
console.log('--------------------------------------------------------------------------------');
