# Smart Door Lock ESP32 - Clean Project Structure

## 📁 Core Project Files

### Backend (Flask Application)
```
backend/
├── app.py                    # Main Flask application server
├── mqtt_handler.py           # MQTT communication handler
├── security_integration.py   # Security features integration
├── serial_handler.py         # ESP32 serial communication
├── requirements.txt          # Python dependencies
└── .env.example             # Environment variables template
```

### Frontend (Web Interface)
```
frontend/
├── templates/               # Jinja2 HTML templates
│   ├── base.html           # Base template
│   ├── dashboard.html      # Main dashboard
│   ├── login.html          # Login page
│   ├── users.html          # User management
│   ├── access_logs.html    # Access logs
│   ├── analytics.html      # ML analytics
│   ├── security_dashboard.html  # Security monitoring
│   └── security_events.html    # Security events
└── static/                 # CSS, JS, images (if any)
```

### ESP32 Firmware
```
esp32/
├── smart_door_lock_complete.ino  # Main Arduino sketch
├── config.h                      # Configuration file
└── README.md                     # ESP32 setup instructions
```

### Security & AI
```
security/
├── anomaly_detection.py         # ML anomaly detection core
├── generate_ssl_python.py       # SSL certificate generator
├── generate_ssl.ps1             # PowerShell SSL generator
├── models/                      # Trained ML models
│   ├── anomaly_model.joblib
│   └── scaler.joblib
├── SECURITY.md                  # Security documentation
└── README.md                    # Security features guide
```

### Hardware & Documentation
```
hardware/
├── circuit_diagram.png         # Hardware wiring diagram
├── components_list.md          # Required components
└── README.md                   # Hardware setup guide

docs/
├── README.md                   # Project documentation
├── ai_sec.md                   # AI & Security details
└── team_roles.md              # Team responsibilities
```

### Testing & Utilities
```
tests/
└── integration_test.py         # Comprehensive system tests

hardware_simulator.py           # Hardware simulation tool
ssl/                           # SSL certificates
├── cert.pem
└── key.pem
```

## 🚀 Quick Start Commands

### Start the System
```bash
# 1. Start backend server
cd backend
python app.py

# 2. Access web interface
# Open: http://localhost:5000
# Login: admin / admin123

# 3. Test hardware simulation
python hardware_simulator.py
```

### Run Tests
```bash
# Comprehensive integration test
python tests/integration_test.py
```

### Generate SSL Certificates
```bash
# Using Python script
python security/generate_ssl_python.py

# Using PowerShell (Windows)
powershell -ExecutionPolicy Bypass -File security/generate_ssl.ps1
```

## 📋 File Purposes

| File | Purpose | Essential |
|------|---------|-----------|
| `backend/app.py` | Main Flask server with all routes | ✅ |
| `backend/mqtt_handler.py` | MQTT communication with ESP32 | ✅ |
| `backend/security_integration.py` | Security dashboard & ML integration | ✅ |
| `backend/serial_handler.py` | Serial communication handler | ✅ |
| `security/anomaly_detection.py` | ML anomaly detection engine | ✅ |
| `security/generate_ssl_python.py` | SSL certificate generation | ✅ |
| `hardware_simulator.py` | Hardware testing without ESP32 | ✅ |
| `esp32/smart_door_lock_complete.ino` | ESP32 firmware | ✅ |
| `tests/integration_test.py` | System testing | 🔧 |

## 🧹 Cleaned Up Files

The following redundant files were removed for a cleaner codebase:
- ❌ `App.py` (duplicate)
- ❌ `backend/access_control.py` (empty)
- ❌ `demo_hardware_simulation.py` (redundant)
- ❌ `final_security_demo.py` (testing)
- ❌ `live_demo.py` (redundant)
- ❌ `quick_security_test.py` (testing)
- ❌ `security/demo_anomaly_detection.py` (demo)
- ❌ `security/standalone_security_test.py` (testing)
- ❌ `security/test_security.py` (testing)
- ❌ `frontend/templates/security_dashboard_backup.html` (backup)

## 🎯 Production Ready

The codebase is now clean and production-ready with:
- ✅ Essential files only
- ✅ Clear structure
- ✅ Comprehensive documentation
- ✅ Testing framework
- ✅ Security features
- ✅ Hardware simulation capabilities
