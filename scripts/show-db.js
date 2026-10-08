/**
 * University Cryptography Lab - Database Evidence Helper
 * Queries and displays user documents from MongoDB.
 * Demonstrates:
 *  1. Zero plaintext email storage (AES-256-GCM iv:authTag:ciphertext)
 *  2. HMAC-SHA256 blind index (emailIndex)
 *  3. bcrypt password hash with cost factor 12 ($2b$12$...)
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');

const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URI;

if (!mongoUri) {
  console.error('Error: MONGODB_URI is not set in .env');
  process.exit(1);
}

async function showDatabase() {
  try {
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB:', mongoUri.replace(/:([^:@]{1,})@/, ':****@'));
    console.log('='.repeat(90));
    console.log('                      STORED USERS COLLECTION EVIDENCE');
    console.log('='.repeat(90));

    const users = await User.find({}).lean();

    if (users.length === 0) {
      console.log('No user records found in the database.');
      console.log('Register a user first via the web form or curl to view stored records.');
    } else {
      users.forEach((u, idx) => {
        console.log(`\n[Record #${idx + 1}] User ID: ${u._id}`);
        console.log('-'.repeat(90));
        console.log(' emailEncrypted (AES-256-GCM hex):');
        console.log(`   ${u.emailEncrypted}`);
        
        const parts = (u.emailEncrypted || '').split(':');
        if (parts.length === 3) {
          console.log(`   └─ IV (12 bytes/24 hex):        ${parts[0]}`);
          console.log(`   └─ AuthTag (16 bytes/32 hex):   ${parts[1]}`);
          console.log(`   └─ Ciphertext (variable hex):   ${parts[2]}`);
        }

        console.log(' emailIndex (HMAC-SHA256 Blind Index):');
        console.log(`   ${u.emailIndex}`);

        console.log(' passwordHash (bcrypt cost 12):');
        console.log(`   ${u.passwordHash}`);

        console.log(` Created At: ${u.createdAt}`);
      });
    }

    console.log('\n' + '='.repeat(90));
    console.log('Notice: Neither plaintext email nor plaintext password exists in this collection.');
    console.log('='.repeat(90));
  } catch (err) {
    console.error('Database query error:', err.message);
  } finally {
    await mongoose.disconnect();
  }
}

showDatabase();
