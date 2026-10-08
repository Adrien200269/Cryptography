#!/usr/bin/env bash
# University Cryptography Lab - Generate Self-Signed TLS Certificate
# Creates key.pem and cert.pem with Subject Alternative Names (SAN) for localhost and 127.0.0.1

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Generating 2048-bit RSA private key and self-signed X.509 certificate..."

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -subj "/C=US/ST=Lab/L=Lab/O=CryptographyLab/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Certificate generation complete:"
echo " - Private Key: key.pem"
echo " - Certificate: cert.pem"
