/**
 * University Cryptography Lab - INSECURE DEMO HTTP SERVER
 * 
 * !!! WARNING: FOR DEMO AND WIRESHARK TRAFFIC COMPARISON ONLY !!!
 * 
 * This server runs over plain HTTP on port 8080.
 * Its purpose is strictly educational: to demonstrate what happens when
 * credentials are submitted over cleartext HTTP without TLS encryption.
 * In Wireshark, capturing port 8080 clearly exposes the submitted email
 * and password in plaintext within the HTTP POST request body.
 * 
 * Security Guardrails:
 * - Runs strictly on port 8080
 * - Does NOT connect to any database
 * - Does NOT store, log, or persist any submitted data
 * - Displays prominent warning banners
 * - Is completely independent and never started by the secure server
 */

const http = require('http');

const PORT = 8080;

const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>[INSECURE DEMO] Cleartext HTTP Authentication</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #fff1f0;
      color: #333;
      margin: 0;
      padding: 40px 20px;
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .warning-banner {
      max-width: 600px;
      background: #ff4d4f;
      color: #ffffff;
      padding: 16px 20px;
      border-radius: 8px;
      font-weight: bold;
      text-align: center;
      margin-bottom: 24px;
      box-shadow: 0 4px 12px rgba(255, 77, 79, 0.3);
    }
    .card {
      background: #ffffff;
      border: 2px solid #ffccc7;
      border-radius: 8px;
      padding: 32px;
      max-width: 440px;
      width: 100%;
      box-shadow: 0 4px 16px rgba(0,0,0,0.06);
    }
    h2 {
      margin-top: 0;
      color: #cf1322;
      font-size: 20px;
    }
    .form-group {
      margin-bottom: 16px;
    }
    label {
      display: block;
      margin-bottom: 6px;
      font-size: 14px;
      font-weight: 600;
    }
    input[type="text"], input[type="password"] {
      width: 100%;
      box-sizing: border-box;
      padding: 10px 12px;
      border: 1px solid #d9d9d9;
      border-radius: 4px;
      font-size: 14px;
    }
    button {
      width: 100%;
      padding: 12px;
      background-color: #cf1322;
      color: #fff;
      border: none;
      border-radius: 4px;
      font-size: 15px;
      font-weight: bold;
      cursor: pointer;
    }
    button:hover {
      background-color: #a8071a;
    }
    .status-box {
      margin-top: 18px;
      padding: 12px;
      background: #fafafa;
      border-left: 4px solid #1890ff;
      font-size: 13px;
      line-height: 1.5;
    }
  </style>
</head>
<body>
  <div class="warning-banner">
    ⚠️ DEMO ONLY — CLEARTEXT HTTP TRANSMISSION (INSECURE) ⚠️<br>
    All credentials submitted here are transmitted unencrypted over port 8080.<br>
    This endpoint does NOT store any data. Capture this request in Wireshark to observe plaintext exposure!
  </div>

  <div class="card">
    <h2>Insecure Login Demonstration</h2>
    <form method="POST" action="/demo-login">
      <div class="form-group">
        <label for="email">Demo Email:</label>
        <input type="text" id="email" name="email" value="alice.insecure@example.com" required>
      </div>
      <div class="form-group">
        <label for="password">Demo Password:</label>
        <input type="password" id="password" name="password" value="SuperSecretCleartext123!" required>
      </div>
      <button type="submit">Submit Plaintext POST Request</button>
    </form>

    <div class="status-box">
      <strong>Wireshark Lab Instructions:</strong><br>
      1. Filter by <code>tcp.port == 8080 and http</code>.<br>
      2. Click "Submit Plaintext POST Request".<br>
      3. Right-click the packet in Wireshark -> <em>Follow -> TCP Stream</em>.<br>
      4. Observe how your email and password appear in plain ASCII text.
    </div>
  </div>
</body>
</html>`;

const server = http.createServer((req, res) => {
  if (req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(htmlContent);
    return;
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', () => {
      // Intentionally do NOT log or store the credentials to maintain student privacy
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>Request Received</title></head>
        <body style="font-family: sans-serif; padding: 40px; text-align: center; background: #fff1f0;">
          <h2 style="color: #cf1322;">⚠️ Plaintext POST Received!</h2>
          <p>The unencrypted request was received by the insecure server on port 8080.</p>
          <p><strong>Check your Wireshark capture window now to see the unencrypted payload!</strong></p>
          <p><a href="/" style="color: #1890ff;">Back to Demo Form</a></p>
        </body>
        </html>
      `);
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log('================================================================================');
  console.log(` ⚠️ INSECURE DEMO SERVER running on HTTP http://localhost:${PORT}`);
  console.log(' Purpose: Capture unencrypted plaintext HTTP traffic in Wireshark for comparison');
  console.log(' Note: This server does NOT persist any data and is strictly for educational demo.');
  console.log('================================================================================');
});
