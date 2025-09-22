# Smart Door Lock System Configuration Guide

This guide will help you configure your Smart Door Lock system properly. Follow these steps to ensure everything works correctly.

## 1. Backend Configuration

### Flask Backend Setup
1. Install required Python packages:
   ```bash
   pip install -r backend/requirements.txt
   ```

2. Configure the server:
   - The Flask server runs on port 5000 by default
   - Make sure the server is accessible from your local network

### Flask Backend Setup
1. Install required Python packages:
   ```bash
   pip install -r backend/requirements.txt
   ```

2. Configure the Flask application:
   - Make sure your server IP is accessible from ESP32
   - Default port is 5000 (can be changed if needed)

## 2. ESP32 Configuration

1. Edit the `esp32/config.h` file with your network settings:
   ```cpp
   // WiFi credentials
   const char *ssid = "YOUR_WIFI_SSID";
   const char *password = "YOUR_WIFI_PASSWORD";

   // Server configuration
   const char *server_address = "YOUR_SERVER_IP";  // Flask server IP address
   const int server_port = 5000;  // Default Flask port
   ```

2. Hardware Connections:
   - RFID RC522:
     - SDA (SS) -> GPIO21
     - SCK -> GPIO18
     - MOSI -> GPIO23
     - MISO -> GPIO19
     - RST -> GPIO22
   - Relay -> GPIO23
   - Door Sensor -> GPIO25
   - Buzzer -> GPIO26
   - Green LED -> GPIO27
   - Red LED -> GPIO14

## 3. Testing the Setup

1. Test HTTP Communication:
   ```bash
   # Test server status endpoint
   curl http://YOUR_SERVER_IP:5000/api/device_status
   
   # Test access control endpoint
   curl -X POST -H "Content-Type: application/json" \
        -d '{"method":"test","device_id":"test_device"}' \
        http://YOUR_SERVER_IP:5000/api/check_access
   ```

2. Verify LED Indicators:
   - Green LED: Flashes on successful connection
   - Red LED: Flashes on connection failure
   - Both LEDs should be responsive to access attempts

## 4. Troubleshooting

### Connection Issues
1. ESP32 not connecting:
   - Check WiFi credentials
   - Verify MQTT broker IP and port
   - Ensure MQTT credentials are correct

2. Access control not working:
   - Check MQTT broker logs
   - Verify user registration in database
   - Check ESP32 serial output for errors

### LED Status Codes
- Single green flash: Successful connection
- Three red flashes: Connection failure
- Alternating red/green: System error
- Steady red: Door locked
- Steady green: Door unlocked

## 5. Security Recommendations

1. Change default passwords:
   - MQTT broker
   - WiFi network
   - Web interface admin account

2. Enable SSL/TLS:
   - Generate certificates using `security/generate_ssl.sh`
   - Configure MQTT broker for SSL
   - Update ESP32 code for SSL support

3. Regular maintenance:
   - Update firmware
   - Check logs for unauthorized access attempts
   - Verify all registered users periodically

For additional help or troubleshooting, check the documentation in the `docs` folder or submit an issue on the project repository.