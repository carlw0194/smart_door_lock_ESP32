#ifndef CONFIG_H
#define CONFIG_H

// WiFi credentials
const char *ssid = "TP-Link_517A";  // Replace with your WiFi SSID
const char *password = "34369012";  // Replace with your WiFi password

// Server configuration
const char *server_address = "192.168.1.100";  // Your Flask server IP address
const int server_port = 5000;  // Default Flask port
const char *device_id = "ESP32_Door_001";  // Unique identifier for this device

// API endpoints
const char *access_endpoint = "/api/check_access";
const char *status_endpoint = "/api/device_status";

#endif