#!/usr/bin/env python3
"""
Python-based SSL Certificate Generator
Alternative to OpenSSL for Windows environments
"""

import os
import ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_ssl_certificates():
    """Generate self-signed SSL certificates using Python cryptography library"""
    
    print("🔐 Generating SSL certificates using Python cryptography...")
    
    # Create SSL directory
    ssl_dir = "ssl"
    os.makedirs(ssl_dir, exist_ok=True)
    
    # Generate private key
    print("🔑 Generating private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Generate certificate
    print("📜 Generating self-signed certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Smart Door Lock"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now()
    ).not_valid_after(
        datetime.now() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Write private key to file
    key_path = os.path.join(ssl_dir, "key.pem")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✅ Private key saved to: {key_path}")
    
    # Write certificate to file
    cert_path = os.path.join(ssl_dir, "cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"✅ Certificate saved to: {cert_path}")
    
    print("\n🎉 SSL certificates generated successfully!")
    print("\n📋 Next steps:")
    print("1. Update your .env file with:")
    print("   SSL_CERT_PATH=ssl/cert.pem")
    print("   SSL_KEY_PATH=ssl/key.pem")
    print("   FLASK_ENV=production")
    print("\n2. Restart your Flask application to use HTTPS")
    
    return True

if __name__ == "__main__":
    try:
        generate_ssl_certificates()
    except Exception as e:
        print(f"❌ Error generating SSL certificates: {e}")
        print("💡 Make sure the cryptography package is installed:")
        print("   pip install cryptography")
