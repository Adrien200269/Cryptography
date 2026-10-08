/**
 * University Cryptography Lab - User Model (Mongoose)
 * 
 * Cryptographic Data Protection Principles:
 * 1. Zero Plaintext Storage:
 *    Neither the user's plaintext email address nor their plaintext password
 *    is ever stored in the database.
 * 
 * 2. Why Blind Indexing is Essential with AES-256-GCM:
 *    AES-256-GCM requires a cryptographically random Initialization Vector (IV)
 *    for every encryption to achieve semantic security (IND-CPA/IND-CCA).
 *    Consequently, encrypting the identical email address twice results in two
 *    entirely different ciphertexts. A standard database query (`find({ email: 'user@example.com' })`)
 *    is impossible on randomized ciphertexts without decrypting every document in the table (O(N) full scan).
 *    
 *    To solve this, we compute an HMAC-SHA256 "blind index" (`emailIndex`) using a separate
 *    secret key (`HMAC_KEY`). The blind index is deterministic: the same email always produces
 *    the exact same 256-bit hash under that key.
 * 
 *    By placing a UNIQUE index on `emailIndex`, MongoDB:
 *    - Guarantees account uniqueness and prevents duplicate registrations.
 *    - Enables efficient O(log N) indexed lookups at authentication time.
 *    - Prevents frequency analysis and offline rainbow table attacks because attackers
 *      lacking `HMAC_KEY` cannot guess or reverse the index values.
 */

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  // AES-256-GCM authenticated ciphertext stored as "iv:authTag:ciphertext" (hex encoded)
  emailEncrypted: {
    type: String,
    required: [true, 'Encrypted email is required']
  },

  // HMAC-SHA256 blind index of lowercase email
  // The unique index prevents duplicate accounts and allows lookup despite AES's random IV
  emailIndex: {
    type: String,
    required: [true, 'Blind index is required'],
    unique: true,
    index: true
  },

  // bcrypt password hash (cost factor 12)
  passwordHash: {
    type: String,
    required: [true, 'Password hash is required']
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  // Prevent versionKey and ensure lean serialization
  versionKey: false
});

module.exports = mongoose.model('User', userSchema);
