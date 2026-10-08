/**
 * University Cryptography Lab - Cryptographic Utilities
 * 
 * 1. AES-256-GCM Authenticated Encryption:
 *    Provides both Confidentiality and Authenticity (AEAD).
 *    Uses a fresh, cryptographically random 12-byte (96-bit) Initialization Vector (IV)
 *    for every encryption operation. This ensures semantic security (ciphertext indistinguishability).
 *    Output format: iv:authTag:ciphertext (all hex-encoded).
 * 
 * 2. HMAC-SHA256 Blind Indexing:
 *    Because AES with random IVs produces different ciphertexts for identical plaintexts,
 *    we cannot perform database lookups (e.g. find user by email) on the ciphertext.
 *    A blind index is a deterministic, keyed cryptographic hash of the normalized email.
 *    Using HMAC-SHA256 with an independent secret key prevents offline rainbow table attacks
 *    while permitting exact-match indexing and uniqueness enforcement in MongoDB.
 * 
 * 3. Constant-Time Timing Attack Mitigation (Dummy bcrypt comparison):
 *    When a login attempt provides an unknown email, running a dummy bcrypt comparison
 *    with cost factor 12 equalizes server response times between "user does not exist"
 *    and "incorrect password", preventing user enumeration via timing analysis.
 */

const crypto = require('crypto');
const bcrypt = require('bcrypt');

// Precomputed cost-12 bcrypt hash for dummy comparisons
// Generated once at startup so dummy comparisons perform real cost-12 work without recalculating salt
const DUMMY_BCRYPT_HASH = bcrypt.hashSync('dummy_timing_mitigation_password', 12);

/**
 * Validates and retrieves a 32-byte (256-bit) cryptographic key from hex string.
 * @param {string} hexKey 
 * @param {string} keyName 
 * @returns {Buffer}
 */
function getKeyBuffer(hexKey, keyName) {
  if (!hexKey) {
    throw new Error(`Critical Security Error: ${keyName} is missing in environment variables.`);
  }
  const buf = Buffer.from(hexKey, 'hex');
  if (buf.length !== 32) {
    throw new Error(`Critical Security Error: ${keyName} must be exactly 32 bytes (64 hex characters).`);
  }
  return buf;
}

/**
 * Encrypts plaintext using AES-256-GCM authenticated symmetric encryption.
 * @param {string} plaintext - The UTF-8 string to encrypt
 * @param {string} hexKey - 32-byte hexadecimal key
 * @returns {string} Encrypted bundle formatted as "iv:authTag:ciphertext" (hex)
 */
function encryptAES256GCM(plaintext, hexKey) {
  const key = getKeyBuffer(hexKey, 'AES_KEY');
  
  // NIST SP 800-38D recommends a 12-byte (96-bit) IV for GCM
  const iv = crypto.randomBytes(12);
  
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  
  // 16-byte (128-bit) authentication tag for integrity & authenticity verification
  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypts an AES-256-GCM encrypted bundle and verifies authentication tag.
 * @param {string} encryptedBundle - "iv:authTag:ciphertext" in hex
 * @param {string} hexKey - 32-byte hexadecimal key
 * @returns {string} Decrypted plaintext string
 */
function decryptAES256GCM(encryptedBundle, hexKey) {
  const key = getKeyBuffer(hexKey, 'AES_KEY');
  
  const parts = encryptedBundle.split(':');
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted payload format. Expected iv:authTag:ciphertext');
  }

  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const ciphertext = Buffer.from(parts[2], 'hex');

  if (iv.length !== 12) {
    throw new Error('Invalid IV length. Expected 12 bytes.');
  }
  if (authTag.length !== 16) {
    throw new Error('Invalid authentication tag length. Expected 16 bytes.');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final() // Will throw if ciphertext or authTag has been tampered with
  ]);

  return decrypted.toString('utf8');
}

/**
 * Computes a keyed HMAC-SHA256 blind index for deterministic lookups and uniqueness.
 * Email is lowercased and trimmed to guarantee consistent indexing.
 * @param {string} email 
 * @param {string} hexKey 
 * @returns {string} 64-character hex blind index
 */
function computeBlindIndex(email, hexKey) {
  const key = getKeyBuffer(hexKey, 'HMAC_KEY');
  const normalized = String(email).trim().toLowerCase();
  return crypto.createHmac('sha256', key).update(normalized).digest('hex');
}

/**
 * Hashes a plaintext password using bcrypt with cost factor 12.
 * @param {string} password 
 * @returns {Promise<string>}
 */
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

/**
 * Verifies a password against a bcrypt hash.
 * @param {string} password 
 * @param {string} hash 
 * @returns {Promise<boolean>}
 */
async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

/**
 * Performs a dummy bcrypt comparison against a dummy cost-12 hash
 * to prevent user enumeration via response timing differences.
 * @param {string} password 
 * @returns {Promise<boolean>}
 */
async function dummyPasswordCompare(password) {
  await bcrypt.compare(password || 'dummy', DUMMY_BCRYPT_HASH);
  return false;
}

module.exports = {
  encryptAES256GCM,
  decryptAES256GCM,
  computeBlindIndex,
  hashPassword,
  comparePassword,
  dummyPasswordCompare
};
