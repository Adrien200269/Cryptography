/**
 * University Cryptography Lab - Index Evidence Helper
 * Prints MongoDB collection indexes for the User model,
 * demonstrating the unique index on emailIndex.
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');

const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URI;

if (!mongoUri) {
  console.error('Error: MONGODB_URI is not set in .env');
  process.exit(1);
}

async function showIndexes() {
  try {
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB:', mongoUri.replace(/:([^:@]{1,})@/, ':****@'));
    console.log('='.repeat(80));
    console.log('                  MONGODB COLLECTION INDEX EVIDENCE');
    console.log('='.repeat(80));

    // Ensure model indexes are synchronized with MongoDB
    await User.init();

    const indexes = await User.collection.indexes();
    console.log(JSON.stringify(indexes, null, 2));

    console.log('\n' + '-'.repeat(80));
    console.log('Index Summary Analysis:');
    indexes.forEach(idx => {
      const keys = Object.keys(idx.key).map(k => `${k}: ${idx.key[k]}`).join(', ');
      console.log(` • Name: "${idx.name}"`);
      console.log(`   Keys:   { ${keys} }`);
      console.log(`   Unique: ${idx.unique ? 'YES (Enforces account uniqueness)' : 'NO'}`);
      if (idx.name.includes('emailIndex')) {
        console.log('   Security Role: Enables deterministic O(log N) lookup on HMAC-SHA256');
        console.log('                  blind index and prevents duplicate user registrations.');
      }
      console.log('');
    });
    console.log('='.repeat(80));
  } catch (err) {
    console.error('Failed to inspect collection indexes:', err.message);
  } finally {
    await mongoose.disconnect();
  }
}

showIndexes();
