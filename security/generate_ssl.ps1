# Generate self-signed SSL certificates for development (Windows PowerShell)

Write-Host "Generating SSL certificates for development..." -ForegroundColor Green

# Create SSL directory if it doesn't exist
if (!(Test-Path "ssl")) {
    New-Item -ItemType Directory -Path "ssl"
}

# Check if OpenSSL is available
try {
    openssl version
} catch {
    Write-Host "OpenSSL not found. Installing using Chocolatey..." -ForegroundColor Yellow

    # Check if Chocolatey is installed
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Please install Chocolatey first: https://chocolatey.org/install" -ForegroundColor Red
        Write-Host "Or install OpenSSL manually and add it to PATH" -ForegroundColor Red
        exit 1
    }

    choco install openssl -y
}

# Generate private key
openssl genrsa -out ssl/key.pem 2048

# Generate certificate signing request
openssl req -new -key ssl/key.pem -out ssl/cert.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in ssl/cert.csr -signkey ssl/key.pem -out ssl/cert.pem

# Clean up
Remove-Item ssl/cert.csr

Write-Host "SSL certificates generated in ssl/ directory" -ForegroundColor Green
Write-Host "Update your .env file with:" -ForegroundColor Yellow
Write-Host "SSL_CERT_PATH=ssl/cert.pem" -ForegroundColor Cyan
Write-Host "SSL_KEY_PATH=ssl/key.pem" -ForegroundColor Cyan
Write-Host "FLASK_ENV=production" -ForegroundColor Cyan
