#include <Arduino.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>

// Pin definitions
#define SS_PIN 21
#define RST_PIN 22
#define RELAY_PIN 23
#define DOOR_SENSOR_PIN 25
#define BUZZER_PIN 26
#define LED_GREEN_PIN 27
#define LED_RED_PIN 14

// RFID
MFRC522 mfrc522(SS_PIN, RST_PIN);

// Variables
bool door_locked = true;
bool door_open = false;
unsigned long last_status_update = 0;
unsigned long unlock_time = 0;
const unsigned long UNLOCK_DURATION = 5000; // 5 seconds
const unsigned long STATUS_INTERVAL = 30000; // 30 seconds

void setup_wifi() {
    delay(10);
    Serial.println();
    Serial.print("Connecting to ");
    Serial.println(ssid);

    WiFi.begin(ssid, password);

    int attempt = 0;
    const int max_attempts = 20;  // 10 seconds max

    while (WiFi.status() != WL_CONNECTED && attempt < max_attempts) {
        delay(500);
        Serial.print(".");
        attempt++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("");
        Serial.println("WiFi connected");
        Serial.println("IP address: ");
        Serial.println(WiFi.localIP());
        
        digitalWrite(LED_GREEN_PIN, HIGH);
        delay(1000);
        digitalWrite(LED_GREEN_PIN, LOW);
    } else {
        Serial.println("");
        Serial.println("WiFi connection failed!");
        
        for(int i = 0; i < 3; i++) {
            digitalWrite(LED_RED_PIN, HIGH);
            delay(200);
            digitalWrite(LED_RED_PIN, LOW);
            delay(200);
        }
        
        ESP.restart();
    }
}

bool check_access(String method, String rfid_uid, String fingerprint_id) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WiFi not connected");
        return false;
    }

    HTTPClient http;
    String url = "http://" + String(server_address) + ":" + String(server_port) + String(access_endpoint);
    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    // Prepare JSON payload
    DynamicJsonDocument doc(1024);
    doc["method"] = method;
    doc["device_id"] = device_id;
    if (method == "rfid") {
        doc["rfid_uid"] = rfid_uid;
    } else if (method == "fingerprint") {
        doc["fingerprint_id"] = fingerprint_id;
    }

    String payload;
    serializeJson(doc, payload);

    int httpResponseCode = http.POST(payload);
    bool access_granted = false;

    if (httpResponseCode > 0) {
        String response = http.getString();
        DynamicJsonDocument responseDoc(1024);
        deserializeJson(responseDoc, response);

        access_granted = responseDoc["access_granted"] | false;
        
        if (access_granted) {
            unlock_door();
            buzz_success();
        } else {
            buzz_failure();
        }
    } else {
        Serial.print("Error on HTTP request: ");
        Serial.println(httpResponseCode);
        buzz_failure();
    }

    http.end();
    return access_granted;
}

void check_rfid() {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
        return;
    }

    // Read RFID UID
    String rfid_uid = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
        rfid_uid += String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
        rfid_uid += String(mfrc522.uid.uidByte[i], HEX);
    }
    rfid_uid.toUpperCase();

    Serial.println("RFID detected: " + rfid_uid);
    check_access("rfid", rfid_uid, "");

    mfrc522.PICC_HaltA();
}

void send_status(String status) {
    if (WiFi.status() != WL_CONNECTED) {
        return;
    }

    HTTPClient http;
    String url = "http://" + String(server_address) + ":" + String(server_port) + String(status_endpoint);
    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    DynamicJsonDocument doc(512);
    doc["device_id"] = device_id;
    doc["status"] = status;
    doc["door_state"] = door_locked ? "locked" : "unlocked";
    doc["door_open"] = door_open;
    doc["wifi_rssi"] = WiFi.RSSI();
    doc["free_heap"] = ESP.getFreeHeap();

    String payload;
    serializeJson(doc, payload);

    http.POST(payload);
    http.end();
}

void unlock_door() {
    digitalWrite(RELAY_PIN, HIGH);
    door_locked = false;
    unlock_time = millis();
    digitalWrite(LED_GREEN_PIN, HIGH);
    digitalWrite(LED_RED_PIN, LOW);
    Serial.println("Door unlocked");
    send_status("door_unlocked");
}

void lock_door() {
    digitalWrite(RELAY_PIN, LOW);
    door_locked = true;
    digitalWrite(LED_GREEN_PIN, LOW);
    digitalWrite(LED_RED_PIN, HIGH);
    Serial.println("Door locked");
    send_status("door_locked");
}

void check_door_sensor() {
    bool current_door_state = digitalRead(DOOR_SENSOR_PIN) == HIGH;
    if (current_door_state != door_open) {
        door_open = current_door_state;
        send_status(door_open ? "door_opened" : "door_closed");
    }
}

void buzz_success() {
    digitalWrite(BUZZER_PIN, HIGH);
    delay(100);
    digitalWrite(BUZZER_PIN, LOW);
    delay(50);
    digitalWrite(BUZZER_PIN, HIGH);
    delay(100);
    digitalWrite(BUZZER_PIN, LOW);
}

void buzz_failure() {
    for (int i = 0; i < 3; i++) {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(200);
        digitalWrite(BUZZER_PIN, LOW);
        delay(100);
    }
}

void setup() {
    Serial.begin(115200);

    // Initialize pins
    pinMode(RELAY_PIN, OUTPUT);
    pinMode(DOOR_SENSOR_PIN, INPUT_PULLUP);
    pinMode(BUZZER_PIN, OUTPUT);
    pinMode(LED_GREEN_PIN, OUTPUT);
    pinMode(LED_RED_PIN, OUTPUT);

    // Initialize with door locked
    digitalWrite(RELAY_PIN, LOW);
    digitalWrite(LED_RED_PIN, HIGH);

    // Initialize RFID
    SPI.begin();
    mfrc522.PCD_Init();

    // Connect to WiFi
    setup_wifi();

    Serial.println("ESP32 Door Lock System Ready");
    send_status("online");
}

void loop() {
    // Check RFID for new cards
    check_rfid();

    // Check door sensor
    check_door_sensor();

    // Auto-lock door after timeout
    if (!door_locked && (millis() - unlock_time > UNLOCK_DURATION)) {
        lock_door();
    }

    // Send periodic status updates
    if (millis() - last_status_update > STATUS_INTERVAL) {
        send_status("online");
        last_status_update = millis();
    }

    delay(100);
}