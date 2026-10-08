/**
 * University Cryptography Lab - Production-Grade Secure HTTPS Server
 * 
 * Key Architectural Decisions & Cryptographic Defenses:
 * 1. Mandatory TLS/HTTPS:
 *    Served exclusively over HTTPS on port 3443 with TLS 1.2+ minimum version
 *    and strong forward-secrecy cipher suites (ECDHE/DHE).
 * 2. HTTP-to-HTTPS Redirection:
 *    A dedicated minimal HTTP server on port 3000 issues 301 Moved Permanently redirects.
 * 3. HTTP Strict Transport Security (HSTS):
 *    Helmet enforces 1-year HSTS with includeSubDomains and preload to eliminate SSL stripping.
 * 4. Pre-Start MongoDB Dependency Enforcement:
 *    Refuses to start if MONGODB_URI is absent and blocks server startup until
 *    database connection and indexes are verified.
 * 5. MongoDB Session Storage:
 *    Sessions persisted in MongoDB with connect-mongo, tagged httpOnly, secure, and sameSite=strict.
 * 6. Rate Limiting:
 *    Brute-force protection applied to authentication endpoints (5 attempts / 15 min).
 * 7. Multi-Layer NoSQL Injection Defense:
 *    express-mongo-sanitize strips operator keys ($ and .), paired with route-level type validation.
 * 8. Zero Leakage Error Handling:
 *    Centralized error boundary hides internal stack traces and server internals.
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const session = require('express-session');
const connectMongo = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');

const authRoutes = require('./routes/auth');
const User = require('./models/User');

// ==========================================
// 1. CONFIGURATION & SECRETS VALIDATION
// ==========================================
const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URI;
if (!mongoUri) {
  console.error(' [FATAL] Server cannot start: MONGODB_URI environment variable is missing.');
  console.error('Please configure MONGODB_URI in your .env file or run `npm run generate-keys`.');
  process.exit(1);
}

const aesKey = process.env.AES_KEY;
const hmacKey = process.env.HMAC_KEY;
const sessionSecret = process.env.SESSION_SECRET;

if (!aesKey || Buffer.from(aesKey, 'hex').length !== 32) {
  console.error(' [FATAL] Server cannot start: AES_KEY must be a 64-character hex string (32 bytes).');
  process.exit(1);
}

if (!hmacKey || Buffer.from(hmacKey, 'hex').length !== 32) {
  console.error(' [FATAL] Server cannot start: HMAC_KEY must be a 64-character hex string (32 bytes).');
  process.exit(1);
}

if (!sessionSecret) {
  console.error(' [FATAL] Server cannot start: SESSION_SECRET is missing.');
  process.exit(1);
}

const HTTPS_PORT = parseInt(process.env.PORT, 10) || 3443;
const HTTP_PORT = parseInt(process.env.HTTP_PORT, 10) || 3000;

// Verify TLS certificates exist
const certPath = path.join(__dirname, 'cert.pem');
const keyPath = path.join(__dirname, 'key.pem');

if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
  console.error(' [FATAL] TLS Certificate or Private Key not found.');
  console.error('Please run `npm run generate-cert` or `./generate-cert.sh` before starting the server.');
  process.exit(1);
}

const tlsOptions = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
  minVersion: 'TLSv1.2',
  ciphers: [
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES256-GCM-SHA384'
  ].join(':'),
  honorCipherOrder: true
};

// ==========================================
// 2. EXPRESS APPLICATION SETUP
// ==========================================
const app = express();

// Trust reverse proxy if needed (for accurate IP in rate limiting)
app.set('trust proxy', 1);

// Security Headers with Helmet
app.use(helmet({
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));

// Body Parsers
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// NoSQL Injection Mitigation (strip Mongo operator keys $, .)
app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    mongoSanitize.sanitize(req.body);
  }
  if (req.params && typeof req.params === 'object') {
    mongoSanitize.sanitize(req.params);
  }
  if (req.query && typeof req.query === 'object') {
    mongoSanitize.sanitize(req.query);
  }
  next();
});

// Resolve MongoStore constructor
const MongoStore = connectMongo.default || connectMongo.MongoStore;

// MongoDB Session Management
app.use(session({
  name: 'secure_auth_sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: mongoUri,
    collectionName: 'sessions',
    ttl: 30 * 60, // 30 minutes in seconds
    autoRemove: 'native'
  }),
  cookie: {
    httpOnly: true, // Inaccessible to client-side scripts (mitigates XSS cookie theft)
    secure: true,   // Transmitted exclusively over encrypted HTTPS connections
    sameSite: 'strict', // Mitigates Cross-Site Request Forgery (CSRF)
    maxAge: 30 * 60 * 1000 // 30 minutes
  }
}));

// Rate Limiting for Authentication Endpoints (Brute-force defense)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes window
  max: 5,                   // Max 5 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return res.status(429).json({
      error: 'Too many authentication attempts. Please try again after 15 minutes.'
    });
  }
});

// Mount Routes
app.use('/api/signup', authLimiter);
app.use('/api/login', authLimiter);
app.use('/api', authRoutes);

// Serve Frontend Static Assets
app.use(express.static(path.join(__dirname, 'public')));

// Root route redirect to /login.html
app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect('/welcome.html');
  }
  return res.redirect('/login.html');
});

// Centralized 404 handler for API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found.' });
});

// Centralized Error Handling Middleware (No stack trace leakage)
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Malformed JSON payload.' });
  }
  // Log internal error safely on the server side without user-supplied plaintext
  console.error(' [INTERNAL ERROR]:', err.message || err);
  
  // Return generic error message to client
  res.status(err.status || 500).json({
    error: 'An internal server error occurred. Please try again later.'
  });
});

// ==========================================
// 3. DATABASE CONNECTION & SERVER STARTUP
// ==========================================
async function startServers() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUri);
    console.log(` Connected to MongoDB at: ${mongoUri.replace(/:([^:@]{1,})@/, ':****@')}`);

    // Ensure User indexes (especially the unique blind index) are initialized
    await User.init();
    console.log(' User schema unique indexes verified.');

    // Start HTTPS Server (Primary Application)
    const httpsServer = https.createServer(tlsOptions, app);
    httpsServer.listen(HTTPS_PORT, () => {
      console.log(` [SECURE] Primary HTTPS Server running on https://localhost:${HTTPS_PORT}`);
    });

    // Start HTTP Redirection Server (Port 3000 -> HTTPS 3443)
    const redirectServer = http.createServer((req, res) => {
      const host = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';
      const redirectLocation = `https://${host}:${HTTPS_PORT}${req.url}`;
      res.writeHead(301, {
        'Location': redirectLocation,
        'Content-Type': 'text/plain'
      });
      res.end(`301 Moved Permanently: Redirecting to ${redirectLocation}`);
    });

    redirectServer.listen(HTTP_PORT, () => {
      console.log(` [REDIRECT] HTTP Redirection Server listening on http://localhost:${HTTP_PORT} (Redirects -> https://localhost:${HTTPS_PORT})`);
    });

  } catch (error) {
    console.error(' [FATAL] Failed to connect to MongoDB or initialize servers:', error.message);
    process.exit(1);
  }
}

startServers();
