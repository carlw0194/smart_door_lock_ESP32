#!/bin/bash
# Generate self-signed SSL certificates for development

echo "Generating SSL certificates for development..."

# Create SSL directory if it doesn't exist
mkdir -p ssl

# Generate private key
openssl genrsa -out ssl/key.pem 2048

# Generate certificate signing request
openssl req -new -key ssl/key.pem -out ssl/cert.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in ssl/cert.csr -signkey ssl/key.pem -out ssl/cert.pem

# Clean up
rm ssl/cert.csr

echo "SSL certificates generated in ssl/ directory"
echo "Update your .env file with:"
echo "SSL_CERT_PATH=ssl/cert.pem"
echo "SSL_KEY_PATH=ssl/key.pem"
echo "FLASK_ENV=production"
