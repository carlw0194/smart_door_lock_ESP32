# Security Implementation Guide

## Overview
This document outlines the security enhancements implemented in the Smart Door Lock system.

## 🔐 Security Features Implemented

### 1. **HTTPS/TLS Support**
- Self-signed certificates for development
- Production-ready SSL configuration
- Automatic HTTP to HTTPS redirection in production

### 2. **API Authentication**
- API key-based authentication for ESP32 devices
- Secure key generation and storage (SHA-256 hashed)
- API key management interface
- Rate limiting per API key

### 3. **Rate Limiting**
- Login attempts: 10 per minute
- API endpoints: 60-100 per minute depending on endpoint
- Configurable rate limits via environment variables

### 4. **Account Security**
- Account lockout after 5 failed login attempts (15-minute lockout)
- Password hashing with Werkzeug security
- Session management with Flask-Login

### 5. **Security Headers**
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options protection
- XSS protection headers

### 6. **Input Validation**
- JSON input validation for API endpoints
- Required field validation
- Data sanitization

### 7. **Security Logging**
- Comprehensive security event logging
- Failed login attempts tracking
- API access monitoring
- Administrative action logging

## 🚀 Quick Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Environment Configuration
Copy `.env.example` to `.env` and update:
```env
SECRET_KEY=your-super-secret-key-change-this-in-production
API_SECRET_KEY=your-api-secret-key-for-esp32
JWT_SECRET_KEY=your-jwt-secret-key
FLASK_ENV=development
DEBUG=False
```

### 3. Generate SSL Certificates (Optional)
For development:
```bash
# Linux/Mac
./generate_ssl.sh

# Windows PowerShell
./generate_ssl.ps1
```

### 4. Run the Application
```bash
python app.py
```

## 🔑 API Key Management

### Creating API Keys
1. Login to admin dashboard
2. Navigate to "API Keys" section
3. Click "Create API Key"
4. Enter device name (e.g., "ESP32-MainDoor")
5. **Important**: Copy the API key immediately (shown only once)

### Using API Keys
Include the API key in requests:

**Header method (recommended):**
```
X-API-Key: your_api_key_here
```

**Query parameter method:**
```
GET /api/users?api_key=your_api_key_here
```

### ESP32 Integration Example
```cpp
#include <HTTPClient.h>
#include <ArduinoJson.h>

String apiKey = "your_api_key_here";
String serverURL = "https://your-server.com";

void checkAccess(String method, String uid) {
    HTTPClient http;
    http.begin(serverURL + "/api/check_access");
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-API-Key", apiKey);
    
    DynamicJsonDocument doc(1024);
    doc["method"] = method;
    doc["rfid_uid"] = uid;
    
    String jsonString;
    serializeJson(doc, jsonString);
    
    int httpResponseCode = http.POST(jsonString);
    // Handle response...
}
```

## 📊 Security Monitoring

### Access the Security Dashboard
- **Security Events**: Monitor failed logins, API abuse, etc.
- **Access Logs**: Track all door access attempts
- **API Key Usage**: Monitor API key activity

### Key Metrics to Monitor
- Failed login attempts per IP
- API requests per minute
- Unusual access patterns
- Account lockouts

## 🛡️ Security Best Practices

### Production Deployment
1. **Change Default Credentials**
   - Default admin: `admin/admin123`
   - Change immediately after first login

2. **Use Strong Secrets**
   - Generate random SECRET_KEY (32+ characters)
   - Use unique API keys for each device
   - Rotate keys regularly

3. **Enable HTTPS**
   - Use valid SSL certificates in production
   - Set `FLASK_ENV=production` in .env
   - Configure reverse proxy (nginx/Apache)

4. **Database Security**
   - Use strong database passwords
   - Enable database encryption
   - Regular backups

5. **Network Security**
   - Use VPN for remote access
   - Firewall rules for API endpoints
   - Network segmentation

### Regular Maintenance
- Review security events weekly
- Rotate API keys monthly
- Update dependencies regularly
- Monitor for suspicious patterns

## 🚨 Incident Response

### Suspicious Activity Detection
The system automatically logs:
- Multiple failed login attempts
- Invalid API key usage
- Unusual access patterns
- Administrative changes

### Response Actions
1. **Check Security Events** dashboard
2. **Review Access Logs** for patterns
3. **Revoke compromised API keys**
4. **Reset affected user accounts**
5. **Update security policies** if needed

## 📋 Compliance Notes

### Data Protection
- User data is stored securely
- Access logs include minimal PII
- Admin actions are audited
- API access is rate-limited

### GDPR Considerations
- Implement data export functionality
- Add data deletion capabilities
- Document data retention policies
- Ensure consent mechanisms

## 🔧 Troubleshooting

### Common Issues

**SSL Certificate Errors**
- Ensure certificates are in correct path
- Check certificate permissions
- Verify certificate validity

**API Authentication Failures**
- Verify API key is active
- Check rate limiting status
- Confirm correct headers

**Account Lockouts**
- Wait 15 minutes for auto-unlock
- Check security events for details
- Reset via admin if needed

### Debug Mode
For development only:
```env
DEBUG=True
FLASK_ENV=development
```

**Never use debug mode in production!**

## 📞 Support

For security issues or questions:
1. Check this documentation
2. Review security events dashboard
3. Contact system administrator
4. Document incident details

---

**Last Updated**: August 2025
**Version**: 1.0
**Security Level**: Enhanced
