/**
 * University Cryptography Lab - Authentication Routes
 * Implements secure registration, login with dummy timing mitigation, session management,
 * and authenticated identity retrieval with server-side decryption.
 */

const express = require('express');
const router = express.Router();
const validator = require('validator');
const User = require('../models/User');
const {
  encryptAES256GCM,
  decryptAES256GCM,
  computeBlindIndex,
  hashPassword,
  comparePassword,
  dummyPasswordCompare
} = require('../utils/crypto');

/**
 * Middleware: Strict String Input Validation (NoSQL Injection Defense Layer 1)
 * Rejects any non-string or nested payload objects (e.g. {"$ne": ""}, {"$gt": ""})
 */
function requireStringInputs(fields) {
  return (req, res, next) => {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'Invalid request body format.' });
    }

    for (const field of fields) {
      const val = req.body[field];
      if (typeof val !== 'string') {
        return res.status(400).json({
          error: `Invalid input: '${field}' must be a string.`
        });
      }
    }
    next();
  };
}

/**
 * Validates password complexity:
 * Min 10 chars, uppercase, lowercase, digit, and symbol.
 */
function isStrongPassword(password) {
  if (typeof password !== 'string' || password.length < 10) {
    return false;
  }
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  return hasUpper && hasLower && hasDigit && hasSymbol;
}

/**
 * POST /api/signup
 * Register a new user with AES-256-GCM email encryption and HMAC-SHA256 blind index.
 */
router.post('/signup', requireStringInputs(['email', 'password']), async (req, res, next) => {
  try {
    const rawEmail = req.body.email.trim();
    const rawPassword = req.body.password;

    // 1. Email format validation
    if (!validator.isEmail(rawEmail)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }

    // 2. Password complexity validation (min 10 chars, upper, lower, number, symbol)
    if (!isStrongPassword(rawPassword)) {
      return res.status(400).json({
        error: 'Password must be at least 10 characters long and include uppercase, lowercase, a number, and a symbol.'
      });
    }

    const aesKey = process.env.AES_KEY;
    const hmacKey = process.env.HMAC_KEY;

    // 3. Compute HMAC-SHA256 blind index on normalized lowercase email
    const emailIndex = computeBlindIndex(rawEmail, hmacKey);

    // 4. Check for duplicate account via blind index
    const existingUser = await User.findOne({ emailIndex });
    if (existingUser) {
      return res.status(409).json({ error: 'Unable to register with these details.' });
    }

    // 5. Encrypt email with AES-256-GCM (fresh random IV inside utility)
    const emailEncrypted = encryptAES256GCM(rawEmail, aesKey);

    // 6. Hash password with bcrypt cost factor 12
    const passwordHash = await hashPassword(rawPassword);

    // 7. Store user in MongoDB
    const newUser = new User({
      emailEncrypted,
      emailIndex,
      passwordHash
    });

    await newUser.save();

    return res.status(201).json({
      message: 'Account successfully created. Please log in.'
    });

  } catch (error) {
    // Handle MongoDB duplicate key collision (E11000) race conditions
    if (error.code === 11000) {
      return res.status(409).json({ error: 'Unable to register with these details.' });
    }
    return next(error);
  }
});

/**
 * POST /api/login
 * Authenticate using blind index lookup and bcrypt verification with timing attack mitigation.
 */
router.post('/login', requireStringInputs(['email', 'password']), async (req, res, next) => {
  try {
    const rawEmail = req.body.email.trim();
    const rawPassword = req.body.password;

    if (!rawEmail || !rawPassword) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const hmacKey = process.env.HMAC_KEY;
    const emailIndex = computeBlindIndex(rawEmail, hmacKey);

    // Look up user by deterministic blind index
    const user = await User.findOne({ emailIndex });

    if (!user) {
      // User not found: run dummy cost-12 bcrypt comparison to prevent timing-based user enumeration
      await dummyPasswordCompare(rawPassword);
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // User found: compare password against stored bcrypt hash
    const passwordMatches = await comparePassword(rawPassword, user.passwordHash);

    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Regenerate session to prevent Session Fixation attacks
    req.session.regenerate((err) => {
      if (err) return next(err);

      // Store only internal identifier in session
      req.session.userId = user._id.toString();

      return res.status(200).json({
        message: 'Login successful.',
        redirectTo: '/welcome.html'
      });
    });

  } catch (error) {
    return next(error);
  }
});

/**
 * GET /api/me
 * Protected endpoint: returns decrypted email for the authenticated session.
 */
router.get('/me', async (req, res, next) => {
  try {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: 'Unauthorized: Session missing or expired.' });
    }

    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized: Account not found.' });
    }

    // Decrypt AES-256-GCM email server-side
    const aesKey = process.env.AES_KEY;
    const decryptedEmail = decryptAES256GCM(user.emailEncrypted, aesKey);

    return res.status(200).json({
      email: decryptedEmail,
      createdAt: user.createdAt
    });
  } catch (error) {
    return next(error);
  }
});

/**
 * POST /api/logout
 * Destroys session in MongoDB store and clears session cookie.
 */
router.post('/logout', (req, res, next) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        return next(err);
      }
      res.clearCookie('connect.sid', { path: '/' });
      return res.status(200).json({ message: 'Logged out successfully.' });
    });
  } else {
    return res.status(200).json({ message: 'No active session.' });
  }
});

module.exports = router;
