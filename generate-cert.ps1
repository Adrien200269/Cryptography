<#
.SYNOPSIS
    Generates a self-signed TLS certificate (key.pem, cert.pem) for CN=localhost with SAN localhost/127.0.0.1.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Try locating openssl in PATH or Git installation
$openSslPath = (Get-Command openssl -ErrorAction SilentlyContinue)?.Source

if (-not $openSslPath) {
    $gitOpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe"
    if (Test-Path $gitOpenSsl) {
        $openSslPath = $gitOpenSsl
    }
}

if (-not $openSslPath) {
    Write-Error "OpenSSL was not found in PATH or at '$gitOpenSsl'. Please install OpenSSL or Git for Windows."
    exit 1
}

Write-Host "Using OpenSSL at: $openSslPath"
Write-Host "Generating 2048-bit RSA key and self-signed certificate with SAN..."

& $openSslPath req -x509 -newkey rsa:2048 -nodes -sha256 `
    -keyout key.pem `
    -out cert.pem `
    -days 365 `
    -subj "/C=US/ST=Lab/L=Lab/O=CryptographyLab/CN=localhost" `
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

if ($LASTEXITCODE -eq 0 -and (Test-Path key.pem) -and (Test-Path cert.pem)) {
    Write-Host "TLS Certificate and Private Key successfully generated:" -ForegroundColor Green
    Write-Host " - Private Key: key.pem" -ForegroundColor Cyan
    Write-Host " - Certificate: cert.pem" -ForegroundColor Cyan
} else {
    Write-Error "Failed to generate TLS certificate."
    exit 1
}
