# Smart Door Lock Security & AI Implementation

## Phase 2 Implementation: MQTT + Machine Learning

### ✅ Completed Features

#### 1. **MQTT Real-time Communication**

- **MQTT Handler**: Real-time communication between ESP32 and backend
- **Topics**:
  - `door/access/request` - ESP32 sends access requests
  - `door/access/response` - Server responds with access decisions
  - `door/state` - Door state updates (open/closed/locked)
  - `door/system/status` - ESP32 health monitoring
  - `door/alerts` - Security alerts broadcast
  - `door/users/sync` - User data synchronization

#### 2. **Machine Learning Anomaly Detection**

- **Models**: Isolation Forest + Random Forest
- **Features**: Time-based, access patterns, user behavior
- **Detection**: Suspicious access attempts, unusual patterns
- **Real-time**: Integrated with MQTT for immediate alerts

#### 3. **Enhanced Security Features**

- **API Key Authentication**: Secure ESP32 communication
- **Rate Limiting**: Protection against abuse
- **Security Event Logging**: Comprehensive audit trail
- **Account Lockout**: Protection against brute force
- **Input Validation**: Secure API endpoints

#### 4. **Analytics Dashboard**

- **Security Insights**: Real-time analytics
- **User Behavior Analysis**: Pattern recognition
- **Anomaly Alerts**: ML-powered threat detection
- **Access Statistics**: Comprehensive reporting

### 🔧 Installation & Setup

#### Backend Setup

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your configuration
python app.py
```

#### MQTT Broker Setup

```bash
# Install Mosquitto MQTT Broker
# Ubuntu/Debian:
sudo apt-get install mosquitto mosquitto-clients

# Windows: Download from https://mosquitto.org/download/
# Configure authentication in mosquitto.conf
```

#### ESP32 Setup

1. Install required libraries in Arduino IDE:
   - PubSubClient
   - ArduinoJson
   - MFRC522
2. Update WiFi and MQTT credentials in `smart_door_lock.ino`
3. Upload to ESP32

### 📊 Architecture

```
┌─────────────┐    MQTT     ┌─────────────┐
│   ESP32     │◄──────────►│   Backend   │
│             │             │             │
│ - RFID      │             │ - Flask API │
│ - Sensors   │             │ - ML Models │
│ - Actuators │             │ - Database  │
└─────────────┘             └─────────────┘
                                   │
                            ┌─────────────┐
                            │   Web UI    │
                            │             │
                            │ - Dashboard │
                            │ - Analytics │
                            │ - Management│
                            └─────────────┘
```

### 🛡️ Security Implementation

#### API Security

- **Authentication**: API key required for all ESP32 endpoints
- **Rate Limiting**: Prevents abuse and DoS attacks
- **Input Validation**: Protects against injection attacks
- **HTTPS**: SSL/TLS encryption in production

#### Access Control

- **Role-based Access**: Admin/User/Guest levels
- **Account Lockout**: Prevents brute force attacks
- **Session Management**: Secure login/logout
- **Audit Logging**: Complete security event trail

### 🤖 Machine Learning Features

#### Anomaly Detection

- **Isolation Forest**: Unsupervised anomaly detection
- **Random Forest**: Classification of access patterns
- **Features**:
  - Time of day, day of week
  - User access frequency
  - Failed attempt patterns
  - Business hours analysis

#### Pattern Recognition

- **User Behavior**: Individual access patterns
- **System-wide**: Overall security trends
- **Predictive**: Early threat detection
- **Adaptive**: Model retraining with new data

### 📱 MQTT Communication Protocol

#### Access Request (ESP32 → Server)

```json
{
  "method": "rfid",
  "rfid_uid": "A1B2C3D4",
  "device_id": "ESP32_Door_001"
}
```

#### Access Response (Server → ESP32)

```json
{
  "access_granted": true,
  "user_name": "John Doe",
  "user_id": 123,
  "timestamp": "2025-08-05T10:30:00Z"
}
```

#### Security Alert (Server → All)

```json
{
  "type": "anomaly",
  "message": "Suspicious access pattern detected",
  "severity": "high",
  "timestamp": "2025-08-05T10:30:00Z"
}
```

### 🔗 API Endpoints

#### ESP32 Communication

- `POST /api/check_access` - Validate access credentials
- `POST /api/register_rfid` - Register RFID to user
- `POST /api/register_fingerprint` - Register fingerprint
- `POST /api/door_state` - Update door status
- `GET /api/users` - Sync user database

#### Analytics

- `GET /api/analytics/insights` - Security insights
- `POST /ml/train` - Trigger model retraining

### 📈 Dashboard Features

#### Main Dashboard

- User statistics
- Access attempts (today)
- Recent access logs
- System status

#### Analytics Page

- Anomaly detection results
- Security alerts
- User behavior analysis
- Access pattern insights

#### Security Events

- Complete audit log
- Event classification
- Risk assessment
- Real-time monitoring

### 🚀 Next Phase: Advanced Features

#### Planned Enhancements

1. **Multi-Factor Authentication**

   - RFID + Fingerprint + OTP
   - Time-based access codes
   - Mobile app integration

2. **Advanced ML**

   - Deep learning models
   - Computer vision (camera integration)
   - Behavioral biometrics

3. **Cloud Integration**

   - Remote monitoring
   - Data backup
   - Multi-site management

4. **Mobile App**
   - Real-time notifications
   - Remote control
   - User management

### 🔧 Troubleshooting

#### Common Issues

1. **MQTT Connection Failed**

   - Check broker IP and credentials
   - Verify network connectivity
   - Check firewall settings

2. **ML Models Not Training**

   - Ensure sufficient data (>50 access logs)
   - Check database connection
   - Review error logs

3. **ESP32 Connection Issues**
   - Verify WiFi credentials
   - Check MQTT broker availability
   - Monitor serial output

### 📝 Configuration Examples

#### MQTT Broker Configuration

```
# mosquitto.conf
port 1883
allow_anonymous false
password_file /etc/mosquitto/passwd
```

#### ESP32 Configuration

```cpp
const char* ssid = "YourWiFi";
const char* password = "YourPassword";
const char* mqtt_server = "192.168.1.100";
const char* mqtt_username = "esp32_door";
```

---

**Status**: Phase 2 Complete ✅  
**Next**: Phase 3 - Advanced Features  
**Team**: AI/Security Specialist Implementation
