# University Cryptography Lab - Cryptographic Design & Report Notes

This document provides theoretical rationale, cryptographic justifications, and defense-in-depth analysis for your university lab report.

---

## 1. MongoDB Schema Design & Zero Plaintext Storage

### A. Schema Architecture
```javascript
{
  emailEncrypted: String, // "iv:authTag:ciphertext" (Hex encoded)
  emailIndex: String,     // HMAC-SHA256 blind index (64-character hex, UNIQUE)
  passwordHash: String,   // bcrypt hash with cost factor 12 ($2b$12$...)
  createdAt: Date         // Timestamp
}
```

### B. Core Security Guarantees
1. **Confidentiality at Rest:** A total dump or compromise of the database yields zero plaintext email addresses or plaintext passwords.
2. **Authenticity & Integrity:** Data tampering is immediately detected by the GCM authentication tag before any decrypted data is returned.
3. **No Frequency Leakage:** Because AES encryption uses a fresh 12-byte Initialization Vector (IV) for every record, identical plaintexts yield entirely distinct ciphertexts.

---

## 2. Why the Unique Blind Index is Essential with AES-256-GCM

### The Cryptographic Dilemma:
Under modern authenticated symmetric encryption (AES-256-GCM):
$$C = \text{AES-GCM-Encrypt}(K_{\text{AES}}, IV, P)$$
Where $IV$ is a cryptographically random 96-bit (12-byte) value generated via a CSPRNG (`crypto.randomBytes(12)`).

Because the IV changes with every single encryption, encrypting `"alice@example.com"` three times generates three completely different ciphertexts:
- Encryption 1: `a1f0...:9b2c...:48e1...`
- Encryption 2: `d3e8...:710a...:62bf...`
- Encryption 3: `09c1...:54fe...:17a9...`

### The Resulting Database Challenge:
1. **Lookup Impasse:** A database query such as `User.findOne({ emailEncrypted: targetCiphertext })` is impossible because the query cannot predict the random IV used at registration.
2. **Performance Degradation ($O(N)$):** Without an index, the server would have to load every record in the collection and decrypt each one until a match was found. This causes extreme CPU exhaustion and denial-of-service vulnerability at scale.
3. **Loss of Unique Constraints:** Standard database unique constraints cannot prevent duplicate registrations because different random IVs make each ciphertext string distinct.

### The Cryptographic Solution: Keyed HMAC-SHA256 Blind Index
We compute an HMAC-SHA256 keyed hash over the canonical (lowercased and trimmed) email:
$$I = \text{HMAC-SHA256}(K_{\text{HMAC}}, \text{normalize}(P))$$

- **Deterministic:** The same email address always maps to the same 256-bit hash under key $K_{\text{HMAC}}$.
- **Key-Dependent & Reversal Resistant:** Unlike a plain unsalted SHA-256 hash, an adversary who dumps the database cannot conduct offline dictionary or rainbow table attacks without possessing $K_{\text{HMAC}}$.
- **Fast Indexed Retrieval ($O(\log N)$):** MongoDB builds a B-Tree index over `emailIndex`. Authentication lookups require only an index seek.
- **Enforced Uniqueness:** Marking `emailIndex` as `{ unique: true, index: true }` in Mongoose enforces account uniqueness at the database engine level, preventing race-condition duplicate registrations.

---

## 3. Defense-in-Depth Against NoSQL Injection

### Attack Mechanism:
In Node.js/Express applications using MongoDB, attackers exploit endpoints that accept JSON payloads by sending query selector objects instead of strings:
```json
{
  "email": { "$ne": "" },
  "password": { "$ne": "" }
}
```
If passed directly into `User.findOne({ email: req.body.email })`, MongoDB interprets `$ne` as the "not equal" operator. The query translates to: *"Find the first user whose email is not blank"*, allowing an attacker to bypass authentication without knowing credentials.

### Our Multi-Layered Mitigation:

1. **Layer 1 - Strict Type Enforcement Middleware (`requireStringInputs`):**
   ```javascript
   if (typeof req.body[field] !== 'string') {
     return res.status(400).json({ error: `Invalid input: '${field}' must be a string.` });
   }
   ```
   Rejects non-string payloads before they reach business logic or cryptographic routines.

2. **Layer 2 - Express Mongo Sanitize (`express-mongo-sanitize`):**
   ```javascript
   app.use(mongoSanitize());
   ```
   Recursively inspects `req.body`, `req.query`, and `req.params`, completely stripping any keys containing prohibited characters (`$` and `.`).

3. **Layer 3 - Keyed Hashing Isolation:**
   Even if an object were somehow processed, passing an object into `computeBlindIndex` converts the object to a string literal `"[object Object]"`, preventing database operators from reaching MongoDB.

---

## 4. Mitigating Timing Side-Channel Attacks

### The Vulnerability:
Password verification using bcrypt is computationally expensive by design (cost 12 requires ~250–350 ms on modern hardware).
- If a user exists: The server executes `User.findOne()` followed by `bcrypt.compare()` $\to$ Response time $\approx 300\text{ ms}$.
- If a user does NOT exist: The server returns immediately after `User.findOne()` $\to$ Response time $\approx 5\text{ ms}$.

An attacker measuring network round-trip latency can easily differentiate between valid and invalid email addresses, enabling automated user enumeration.

### Our Mitigation (Dummy bcrypt Comparison):
```javascript
if (!user) {
  // Execute dummy cost-12 comparison against a precomputed hash
  await dummyPasswordCompare(rawPassword);
  return res.status(401).json({ error: 'Invalid credentials.' });
}
```
By performing an equivalent cost-12 bcrypt operation when the user is not found, both execution paths take the exact same amount of time (~300 ms), completely closing the timing side-channel.

---

## 5. Session Security Architecture

| Feature | Configuration | Cryptographic Rationale |
|---------|---------------|-------------------------|
| **Store** | `connect-mongo` (MongoDB) | Session data stored server-side in MongoDB, preventing client tampering |
| **HttpOnly** | `cookie.httpOnly = true` | Prevents malicious JavaScript from reading the cookie via XSS (`document.cookie`) |
| **Secure** | `cookie.secure = true` | Browser only sends the cookie over encrypted HTTPS; never over plaintext HTTP |
| **SameSite** | `cookie.sameSite = 'strict'` | Browser never attaches cookie on cross-site requests, completely preventing CSRF |
| **Expiration** | `maxAge = 30 * 60 * 1000` | Limits the window of vulnerability if a device is left unattended (30-minute TTL) |
| **Fixation Defense** | `req.session.regenerate()` | Generates a new random session ID upon successful login to prevent session fixation |

---

## 6. TLS & Transport Layer Hardening

1. **Protocol Constraint:** `minVersion: 'TLSv1.2'` prohibits vulnerable legacy protocols (SSLv3, TLS 1.0, TLS 1.1).
2. **Forward Secrecy (PFS):** Prioritizes ECDHE (`ECDHE-RSA-AES128-GCM-SHA256`, etc.). Even if the server's RSA private key is compromised in the future, past captured sessions cannot be decrypted.
3. **HSTS:** `max-age=31536000; includeSubDomains; preload` forces compliant browsers to always use HTTPS, protecting users against SSL stripping / downgrade attacks.
4. **HTTP 301 Redirect:** Automatically upgrades any accidental cleartext HTTP connection on port 3000 to HTTPS on port 3443.

---

## 7. Report Screenshot Checklist

Use this checklist when compiling your laboratory submission:

- [ ] **Screenshot 1: MongoDB Compass / mongosh User Document**
  - Open MongoDB Compass, connect to `mongodb://127.0.0.1:27017`.
  - Navigate to database `secure_auth_lab` $\to$ collection `users`.
  - Screenshot showing the document fields: `emailEncrypted`, `emailIndex`, `passwordHash`.
  - Highlight that the email is stored as `iv:authTag:ciphertext` and password is `$2b$12$...`.

- [ ] **Screenshot 2: MongoDB Compass Collection Indexes**
  - In Compass, select the **Indexes** tab on the `users` collection (or terminal output of `npm run show-indexes`).
  - Highlight the unique index on `emailIndex`.

- [ ] **Screenshot 3: TLS Cipher Negotiation via Node.js**
  - Run `npm run tls-info`.
  - Screenshot the terminal output highlighting TLS Protocol Version (`TLSv1.2`/`TLSv1.3`), Cipher Suite, and Subject Alternative Names.

- [ ] **Screenshot 4: Wireshark Insecure HTTP Packet Capture (Port 8080)**
  - Start `npm run demo:insecure`.
  - Submit credentials on `http://localhost:8080`.
  - Capture in Wireshark (`tcp.port == 8080`).
  - Right-click packet $\to$ **Follow TCP Stream**.
  - Highlight plaintext credentials in the HTTP body.

- [ ] **Screenshot 5: Wireshark Encrypted HTTPS Packet Capture (Port 3443)**
  - Start `npm start`.
  - Capture on Loopback adapter with filter `tcp port 3443`.
  - Filter by `tls.record.content_type == 23`.
  - Show that application data is encrypted and string search for `"password"` finds 0 results.

- [ ] **Screenshot 6: Curl Terminal Verification**
  - Screenshot running `curl -k` tests for:
    1. Signup (`POST /api/signup`)
    2. Duplicate signup rejection (`409 Conflict`)
    3. Wrong password login (`401 Unauthorized`)
    4. Successful login with cookie capture (`200 OK`)
    5. NoSQL injection rejection (`400 Bad Request`)
