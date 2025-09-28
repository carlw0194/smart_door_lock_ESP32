# Smart Door Lock System (ESP32)

IoT internship project featuring RFID and fingerprint authentication with ESP32.

## 🏗️ Project Structure

```text
smart_door_lock_ESP32/
├── backend/                    # Flask API server
│   ├── app.py                  # Main Flask application (27KB)
│   ├── mqtt_handler.py         # MQTT communication (9KB)
│   ├── security_integration.py # Security features integration (14KB)
│   ├── serial_handler.py       # Serial communication handler
│   ├── requirements.txt        # Python dependencies
│   ├── .env                    # Environment configuration
│   └── .env.example           # Environment template
├── frontend/                   # Web interface & UI
│   ├── templates/              # HTML templates (8 files)
│   │   ├── base.html           # Base template
│   │   ├── dashboard.html      # Main dashboard
│   │   ├── security_dashboard.html # Security monitoring
│   │   └── ...                 # Other templates
│   └── static/                 # CSS, JS, assets
├── esp32/                      # ESP32 firmware code
│   ├── smart_door_lock_complete.ino  # Main Arduino sketch (12KB)
│   ├── config.h                # Configuration header
│   └── README.md               # ESP32 setup guide
├── hardware/                   # Hardware documentation
│   └── README.md               # Hardware specifications
├── security/                   # Security & AI/ML components
│   ├── anomaly_detection.py    # ML anomaly detection (16KB)
│   ├── generate_ssl_python.py  # SSL certificate generator
│   ├── generate_ssl.ps1        # PowerShell SSL generator
│   ├── models/                 # Trained ML models
│   ├── SECURITY.md             # Security documentation
│   └── README.md               # Security overview
├── docs/                       # Project documentation
│   ├── ai_sec.md               # AI security documentation
│   └── README.md               # Documentation index
├── tests/                      # Testing framework
│   └── integration_test.py     # Comprehensive system tests
├── hardware_simulator.py       # Hardware simulation tool
├── ssl/                        # SSL certificates
├── PROJECT_STRUCTURE.md        # Clean project structure guide
├── .gitignore                  # Git ignore rules
└── README.md                   # This file
```

## 🎯 Team Roles & Responsibilities

| Role                       | Folder      | Description                              |
| -------------------------- | ----------- | ---------------------------------------- |
| **Backend Developer**      | `backend/`  | Flask API, database, MQTT communication  |
| **Frontend Developer**     | `frontend/` | HTML templates, CSS, JavaScript, UI/UX   |
| **ESP32 Developer**        | `esp32/`    | Arduino code, sensor integration         |
| **Hardware Engineer**      | `hardware/` | Circuit design, PCB, mechanical          |
| **Security/AI Specialist** | `security/` | Encryption, ML models, anomaly detection |
| **Documentation**          | `docs/`     | Guides, API docs, user manuals           |

## 🔧 Components

- **ESP32** - Main microcontroller
- **RC522** - RFID module
- **R305/GT521F32** - Fingerprint sensor
- **Solenoid Lock** - Door locking mechanism
- **Relay Module** - Lock control
- **Reed Switch** - Door state sensing
- **Power Supply** - 12V adapter + Buck converter

## 🚀 Quick Start

1. **Backend Setup**

   ```bash
   cd backend
   pip install -r requirements.txt
   python app.py
   ```

2. **ESP32 Setup**

   - Open `esp32/` folder in Arduino IDE or PlatformIO
   - Configure WiFi credentials
   - Upload to ESP32

3. **Security Setup**
   ```bash
   cd security
   .\generate_ssl.ps1  # Windows
   # or
   ./generate_ssl.sh   # Linux/Mac
   ```

## 📋 Features

### ✅ Implemented

- Web dashboard for user management
- RFID & fingerprint authentication
- Access logging and monitoring
- Flask API with MQTT communication
- ESP32 firmware with sensor integration
- SSL certificate generation scripts
- Machine learning anomaly detection system
- Comprehensive documentation structure

### 🔄 Current Status

- **Backend**: Flask API with MQTT, serial communication, and access control
- **Frontend**: Web templates and user interface
- **ESP32**: Complete Arduino firmware with sensor integration
- **Security**: AI-powered anomaly detection and SSL support
- **Documentation**: Phase-based implementation guides

## 🛡️ Security & AI Features

### Implemented Security

- **SSL/TLS Support**: Certificate generation scripts for secure communication
- **Anomaly Detection**: 16KB ML model for detecting unusual access patterns
- **Access Control**: Comprehensive user management and authentication
- **Security Documentation**: Detailed security guidelines and best practices

### AI/ML Components

- **anomaly_detection.py**: Machine learning model for behavioral analysis
- **Pattern Recognition**: Access pattern analysis and anomaly detection
- **Real-time Monitoring**: Continuous security monitoring and alerting

## 📖 Documentation

### Quick Links

- **[Getting Started](docs/phase1_implementation.md)**: Initial setup and basic functionality
- **[Advanced Features](docs/phase2_implementation.md)**: Enhanced security and AI features
- **[Configuration Guide](docs/configuration.md)**: System setup and deployment
- **[Security & AI](docs/ai_sec.md)**: AI/ML security implementation

### Component Documentation

Each folder contains detailed README files:

- `backend/README.md` - Flask API and server setup
- `frontend/README.md` - Web interface documentation
- `esp32/README.md` - Firmware and hardware setup
- `security/README.md` - Security implementation details
- `hardware/README.md` - Hardware specifications and wiring

---

**Team**: IoT Internship Project | **Date**: August 2025
