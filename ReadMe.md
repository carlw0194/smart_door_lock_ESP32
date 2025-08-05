# Smart Door Lock System (ESP32)

IoT internship project featuring RFID and fingerprint authentication with ESP32.

## 🏗️ Project Structure

```
smart_door_lock_ESP32/
├── backend/           # Flask API server
│   ├── app.py         # Main Flask application
│   ├── mqtt_handler.py# MQTT communication
│   ├── requirements.txt
│   └── .env           # Environment config
├── frontend/          # Web interface & UI
│   ├── templates/     # HTML templates
│   └── static/        # CSS, JS, assets
├── esp32/             # ESP32 firmware code
│   └── (Arduino/PlatformIO code)
├── hardware/          # Circuit diagrams & PCB designs
│   └── (Fritzing, KiCad files)
├── security/          # Security & AI/ML components
│   ├── SSL scripts
│   ├── ML models
│   └── Security docs
├── docs/              # Project documentation
│   └── (Setup guides, API docs)
└── README.md          # This file
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

- ✅ Web dashboard for user management
- ✅ RFID & fingerprint authentication
- ✅ Access logging and monitoring
- ⚠️ **In Progress**: HTTPS/TLS security
- ⚠️ **In Progress**: ML anomaly detection
- ⚠️ **Planned**: Multi-factor authentication

## 🛡️ Security & AI Goals

- Secure HTTPS/TLS communication
- API authentication for ESP32
- Machine learning anomaly detection
- Access pattern analysis
- GDPR compliance features

## 📖 Documentation

See individual folder README files for detailed information about each component.

---

**Team**: IoT Internship Project | **Date**: August 2025
