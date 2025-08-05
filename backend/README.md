# Backend

Flask API server for the smart door lock system.

## Contents

- `app.py` - Main Flask application with API endpoints
- `mqtt_handler.py` - MQTT communication handler
- `requirements.txt` - Python dependencies
- `.env` - Environment configuration (not in repo)
- `.env.example` - Environment template

## Team Responsibility

- Backend developers
- API developers
- Database designers

## Features

- **REST API** - Endpoints for ESP32 communication
- **Authentication** - API key management and validation
- **Database** - SQLAlchemy with SQLite/PostgreSQL
- **Security** - Rate limiting, input validation, audit logging
- **MQTT** - Real-time communication with ESP32
- **ML Integration** - Anomaly detection system

## API Endpoints

### ESP32 Communication

- `POST /api/check_access` - Validate access credentials
- `POST /api/register_rfid` - Register RFID to user
- `POST /api/register_fingerprint` - Register fingerprint
- `POST /api/door_state` - Update door status
- `GET /api/users` - Sync user database

### Web Interface

- `GET /dashboard` - Main dashboard
- `GET /users` - User management
- `GET /access_logs` - Access history
- `GET /analytics` - ML insights
- `GET /security_events` - Security audit
- `GET /api_keys` - Device management

### Analytics API

- `GET /api/analytics/insights` - Security insights
- `POST /ml/train` - Trigger model retraining

## Technology Stack

- **Framework**: Flask 2.3+
- **Database**: SQLAlchemy with SQLite (dev) / PostgreSQL (prod)
- **Authentication**: Flask-Login + API keys
- **Security**: Flask-Talisman, Flask-Limiter
- **Communication**: MQTT (Paho)
- **ML**: Scikit-learn for anomaly detection

## Setup

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your configuration
python app.py
```

## Configuration

Environment variables in `.env`:

- Database URL
- Secret keys
- MQTT broker settings
- SSL certificate paths
- Rate limiting settings

## Security Features

- API key authentication for ESP32
- Rate limiting on all endpoints
- Input validation and sanitization
- Security event logging
- Account lockout protection
- HTTPS/TLS support
