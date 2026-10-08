# Secure Authentication System - University Cryptography Lab

A production-grade, cryptographically hardened authentication system built with **Node.js**, **Express**, and **MongoDB (Mongoose)**. Demonstrates defense-in-depth against data breaches, eavesdropping, timing side-channels, and injection attacks.

---

## Table of Contents
1. [Architectural Overview](#architectural-overview)
2. [Cryptographic Principles & Design](#cryptographic-principles--design)
3. [Project Structure](#project-structure)
4. [Prerequisites & MongoDB Setup](#prerequisites--mongodb-setup)
5. [Installation & Setup](#installation--setup)
6. [Running the Application](#running-the-application)
7. [Wireshark Traffic Analysis Guide](#wireshark-traffic-analysis-guide)
8. [Evidence & Verification Scripts](#evidence--verification-scripts)
9. [Required Lab Report Screenshots](#required-lab-report-screenshots)

---

## Architectural Overview

```
                      +-----------------------------+
                      |   HTTP Request (Port 3000)  |
                      +--------------+--------------+
                                     |
                               301 Redirect
                                     v
                      +-----------------------------+
                      |   HTTPS Client (Browser)    |
                      +--------------+--------------+
                                     |
                          TLS 1.2+ (Port 3443)
                      (ECDHE/DHE Forward Secrecy)
                                     v
                      +-----------------------------+
                      |       Express Server        |
                      |   - Helmet & HSTS (1 Year)  |
                      |   - Rate Limiter (5 / 15m)  |
                      |   - Mongo Sanitize & Types  |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                                                       |
         v                                                       v
+------------------+                                   +-------------------+
|  POST /signup    |                                   |   POST /login     |
| 1. Validate Types|                                   | 1. Blind Index    |
| 2. HMAC Blind Idx|                                   | 2. MongoDB Lookup |
| 3. AES-256-GCM   |                                   | 3. bcrypt Verify  |
| 4. bcrypt Hash   |                                   | 4. Dummy Timing   |
+--------+---------+                                   +---------+---------+
         |                                                       |
         +---------------------------+---------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |      MongoDB Database       |
                      |  - emailEncrypted (AES GCM) |
                      |  - emailIndex (UNIQUE)      |
                      |  - passwordHash ($2b$12$)   |
                      |  - sessions (connect-mongo) |
                      +-----------------------------+
```

---

## Cryptographic Principles & Design

### 1. Zero Plaintext Storage
- **Plaintext Emails:** Never stored on disk. Encrypted using **AES-256-GCM** (Galois/Counter Mode) with an unpredictable, cryptographically random 12-byte IV generated per encryption. The document stores `iv:authTag:ciphertext` in hexadecimal.
- **Plaintext Passwords:** Never stored or logged. Hashed using **bcrypt** with a **cost factor of 12** (~$2^{12} = 4096$ key expansion iterations).

### 2. HMAC-SHA256 Blind Indexing
Because AES-256-GCM uses a random IV, identical email addresses produce completely different ciphertexts. To enable account uniqueness checks and $O(\log N)$ database lookups without decrypting all database records or introducing deterministic AES (which leaks frequency patterns), an **HMAC-SHA256 blind index** (`emailIndex`) is computed over the normalized email using an independent secret key (`HMAC_KEY`). A `unique: true` index on `emailIndex` prevents duplicate registrations.

### 3. Timing Attack Mitigation
When a user attempts to log in with an email address that does not exist in the database, the server runs a **dummy cost-12 bcrypt comparison** before returning an identical generic error (`"Invalid credentials"`). This eliminates response time discrepancies that attackers could otherwise measure to enumerate valid registered emails.

### 4. Transport Layer Security (TLS)
- Server requires **TLSv1.2** minimum with strong ephemeral Diffie-Hellman cipher suites (`ECDHE-RSA`, `ECDHE-ECDSA`) ensuring **Perfect Forward Secrecy (PFS)**.
- **HSTS** is enabled for 1 year (`max-age=31536000; includeSubDomains; preload`).
- Automatic HTTP (Port 3000) $\to$ HTTPS (Port 3443) 301 redirection.

### 5. Multi-Layer NoSQL Injection Defense
- Strict type validation middleware: Rejects any object payloads such as `{"$ne": ""}` or `{"$gt": ""}`.
- `express-mongo-sanitize`: Sanitizes all inputs by stripping MongoDB operator keys (`$` and `.`).

---

## Project Structure

```
Cryptography/
├── .env                  # Generated runtime secrets (gitignored)
├── .env.example          # Environment variable template
├── .gitignore            # Git exclusion rules
├── package.json          # Node.js project manifest & scripts
├── cert.pem              # Self-signed TLS certificate (gitignored)
├── key.pem               # 2048-bit RSA private key (gitignored)
├── server.js             # Main HTTPS server & HTTP 301 redirect
├── demo-insecure-server.js # Plain HTTP demo on port 8080 for Wireshark
├── generate-cert.sh      # Bash TLS certificate generator (Linux/macOS)
├── generate-cert.ps1     # PowerShell TLS certificate generator (Windows)
├── models/
│   └── User.js           # Mongoose model (emailEncrypted, emailIndex, passwordHash)
├── routes/
│   └── auth.js           # Signup, login, me, logout endpoints
├── utils/
│   └── crypto.js         # AES-256-GCM, HMAC-SHA256, bcrypt & dummy compare
├── public/               # Static frontend files (Vanilla HTML/CSS/JS)
│   ├── css/style.css     # Clean lab UI styles
│   ├── js/
│   │   ├── signup.js     # Signup form handler
│   │   ├── login.js      # Login form handler
│   │   └── welcome.js    # Protected dashboard handler
│   ├── signup.html       # Signup page
│   ├── login.html        # Login page
│   ├── welcome.html      # Protected authenticated view
│   └── index.html        # Auto-redirect router
├── scripts/
│   ├── generate-keys.js  # CSPRNG secret key generator
│   ├── generate-cert.js  # Cross-platform TLS cert generator
│   ├── show-db.js        # Report evidence: prints stored documents
│   ├── show-indexes.js   # Report evidence: prints collection indexes
│   └── tls-info.js       # Report evidence: inspects TLS handshake & ciphers
├── README.md             # Lab documentation & Wireshark guide
└── REPORT_NOTES.md       # Cryptographic design & report analysis notes
```

---

## Prerequisites & MongoDB Setup

### Option A: Local MongoDB (Recommended for Offline Lab)
1. Ensure the MongoDB Windows Service or `mongod` daemon is running.
   - On Windows: Run `Get-Service MongoDB` in PowerShell. If stopped, start via `Start-Service MongoDB` or Services app.
   - On Linux/macOS: Run `sudo systemctl status mongod` or `brew services start mongodb-community`.
2. The default local URI is:
   ```env
   MONGODB_URI=mongodb://127.0.0.1:27017/secure_auth_lab
   ```

### Option B: MongoDB Atlas (Cloud)
1. Create a free cluster at [cloud.mongodb.com](https://cloud.mongodb.com).
2. Create a database user and allow your IP address in **Network Access**.
3. Under **Database** $\to$ **Connect** $\to$ **Drivers**, copy your connection string:
   ```env
   MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.example.mongodb.net/secure_auth_lab?retryWrites=true&w=majority
   ```
   *Note: In MongoDB Atlas (`mongodb+srv://`), TLS/SSL encryption is mandatory and enforced by default.*

---

## Installation & Setup

### 1. Install Dependencies
```bash
npm install
```

### 2. Generate Cryptographic Secret Keys
Generates three 256-bit cryptographically secure pseudorandom keys (`crypto.randomBytes(32)`) and writes them to `.env`:
```bash
npm run generate-keys
```

### 3. Generate TLS Certificate and Private Key
Creates `cert.pem` and `key.pem` with Subject Alternative Names (SAN) for `localhost` and `127.0.0.1`:
- **Cross-platform:**
  ```bash
  npm run generate-cert
  ```
- **Windows PowerShell:**
  ```powershell
  .\generate-cert.ps1
  ```
- **Linux/macOS Bash:**
  ```bash
  chmod +x generate-cert.sh
  ./generate-cert.sh
  ```

---

## Running the Application

### 1. Start the Secure System
```bash
npm start
```
This launches:
- **Primary HTTPS Application:** `https://localhost:3443`
- **HTTP 301 Redirect Server:** `http://localhost:3000`

Open your browser to `https://localhost:3443`. (Accept the self-signed certificate warning: *Advanced $\to$ Proceed to localhost*).

### 2. Start the Insecure Wireshark Comparison Server
In a separate terminal:
```bash
npm run demo:insecure
```
This launches a cleartext HTTP server on `http://localhost:8080` displaying a prominent warning banner.

---

## Wireshark Traffic Analysis Guide

### A. Capturing Encrypted HTTPS Traffic (Port 3443)

1. Open **Wireshark**.
2. Select the capture interface:
   - **Windows:** Select **`Npcap Loopback Adapter`** (or `Adapter for loopback traffic capture`).
   - **Linux:** Select **`lo`**.
   - **macOS:** Select **`Loopback: lo0`**.
3. In the Wireshark **Capture Filter** field (before starting capture), enter:
   ```
   tcp port 3443
   ```
4. Start the capture.
5. In your browser or with `curl`, register or log in at `https://localhost:3443`.
6. Apply **Display Filters** to examine the TLS protocol:
   - To inspect the TLS handshake (Client Hello, Server Hello, Key Exchange):
     ```
     tls.handshake
     ```
   - To isolate encrypted application payloads:
     ```
     tls.record.content_type == 23
     ```
7. **Attempting String Search on Encrypted Traffic:**
   - Press `Ctrl + F` (Edit $\to$ Find Packet).
   - Select **Packet bytes**, change display format to **String**, search for `"password"` or `"email"`.
   - Result: **0 packets found**. The payload is fully encrypted by AES-GCM under the negotiated TLS session keys.

---

### B. Capturing Cleartext Insecure HTTP Traffic (Port 8080)

1. Ensure `npm run demo:insecure` is running.
2. In Wireshark, set capture interface to the Loopback adapter.
3. Set the Wireshark **Display Filter**:
   ```
   tcp.port == 8080 and http
   ```
4. Navigate to `http://localhost:8080` and submit credentials.
5. In Wireshark, find the `POST /demo-login` packet.
6. Right-click the packet $\to$ **Follow** $\to$ **TCP Stream** (or **HTTP Stream**).
7. Notice the cleartext exposure:
   ```http
   POST /demo-login HTTP/1.1
   Host: localhost:8080
   ...
   email=alice.insecure%40example.com&password=SuperSecretCleartext123%21
   ```

---

## Evidence & Verification Scripts

### 1. View Encrypted Database Records
```bash
npm run show-db
```
Outputs the stored user documents, displaying:
- `emailEncrypted`: `iv:authTag:ciphertext`
- `emailIndex`: 64-character HMAC-SHA256 blind index
- `passwordHash`: `$2b$12$...` bcrypt hash

### 2. Verify Unique Blind Index
```bash
npm run show-indexes
```
Displays MongoDB indexes confirming `emailIndex` is unique.

### 3. Inspect TLS Handshake & Cipher Suite
```bash
npm run tls-info
```
Connects via Node.js TLS module and prints:
- Protocol version (`TLSv1.2` / `TLSv1.3`)
- Negotiated Cipher Suite (e.g. `ECDHE-RSA-AES128-GCM-SHA256`)
- X.509 Certificate details, SAN, and validity period

---

## Required Lab Report Screenshots

| # | Item to Capture | Command / Tool | What to Highlight |
|---|-----------------|----------------|-------------------|
| 1 | **Database Encrypted Records** | `npm run show-db` or MongoDB Compass | AES-256-GCM hex (`iv:tag:ct`), HMAC blind index, and `$2b$12$` bcrypt hash |
| 2 | **Unique Index Enforcement** | `npm run show-indexes` or Compass Indexes tab | Unique constraint on `emailIndex` |
| 3 | **TLS Handshake & Cipher Suite** | `npm run tls-info` | Protocol (`TLSv1.2`+), Cipher suite, and X.509 SAN |
| 4 | **Wireshark: Insecure Plaintext HTTP** | Wireshark $\to$ Follow TCP Stream on port 8080 | Cleartext email and password visible in HTTP body |
| 5 | **Wireshark: Secure Encrypted TLS** | Wireshark $\to$ `tls.record.content_type == 23` | High-entropy encrypted bytes, 0 occurrences on string search for credentials |
| 6 | **HTTP to HTTPS 301 Redirect** | `curl -i http://localhost:3000/` | HTTP/1.1 301 Moved Permanently with Location header |
| 7 | **NoSQL Injection Blocked** | `curl` with object payload | HTTP 400 Bad Request rejection |
