#include <SPI.h>
#include <MFRC522.h>
#include <Adafruit_Fingerprint.h>
#include <ESP32Servo.h>
#include <WiFi.h>
#include <HTTPClient.h>

// === PINS ===
#define SS_PIN    5    // SDA pin for RFID
#define RST_PIN   22   // RST pin for RFID
#define SCK_PIN   18   // SCK pin
#define MISO_PIN  19   // MISO pin
#define MOSI_PIN  23   // MOSI pin
#define SERVO_PIN 13   // Servo control pin
#define LED_PIN   2    // Built-in LED
#define LED_RED   27   // Red LED pin
#define LED_GREEN 26   // Green LED pin

#define FINGER_RX 16
#define FINGER_TX 17

const unsigned long DOOR_OPEN_MS = 3000;

// === WiFi / Server config ===
const char* WIFI_SSID = "TP-Link_517A";
const char* WIFI_PASS = "34369012";
const char* SERVER_HOST = "192.168.254.11";
const int   SERVER_PORT = 5000;
String CHECK_ACCESS_URL;
String DOOR_STATE_URL;
String POLL_REG_URL;
String CLEAR_REG_URL;

MFRC522 mfrc522(SS_PIN, RST_PIN);
HardwareSerial FingerSerial(2);
Adafruit_Fingerprint finger(&FingerSerial);
Servo doorServo;

bool registrationMode = false;
int registrationUserId = -1;
unsigned long lastPoll = 0;
const unsigned long POLL_INTERVAL = 2000; // ms

// Function declarations
void initServerUrls();
void connectWiFi();
void setupFingerprint();
void handleFingerprint();
void handleRFID();
void enrollFingerprint();
void checkAccess(String method, String identifier);

void setup() {
    Serial.begin(115200);
    delay(100);
    Serial.println("\nStarting Smart Door Lock System...");

    // Initialize pins
    pinMode(LED_PIN, OUTPUT);
    pinMode(LED_RED, OUTPUT);
    pinMode(LED_GREEN, OUTPUT);

    // Initialize servo
    doorServo.attach(SERVO_PIN);
    doorServo.write(0);  // Lock position

    // Initialize WiFi
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.print("Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected!");

    // Set up URLs
    CHECK_ACCESS_URL = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/check_access";
    DOOR_STATE_URL  = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/door_state";
    POLL_REG_URL    = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/poll_registration";
    CLEAR_REG_URL   = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/clear_registration";

    // Initialize RFID
    SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
    mfrc522.PCD_Init();
    Serial.println("RFID Reader initialized");

    // Initialize Fingerprint sensor
    FingerSerial.begin(57600, SERIAL_8N1, FINGER_RX, FINGER_TX);
    if (finger.verifyPassword()) {
        Serial.println("Fingerprint sensor connected!");
        finger.getTemplateCount();
    } else {
        Serial.println("Fingerprint sensor not found!");
    }

    // Ready indication
    digitalWrite(LED_GREEN, HIGH);
    delay(1000);
    digitalWrite(LED_GREEN, LOW);
    
    Serial.println("System Ready!");
}

void loop() {
    // Check WiFi
    if (WiFi.status() != WL_CONNECTED) {
        digitalWrite(LED_RED, HIGH);
        return;
    }

    // Poll for registration requests
    if (millis() - lastPoll > POLL_INTERVAL) {
        lastPoll = millis();
        pollRegistration();
    }

    // Registration mode indicator
    if (registrationMode) {
        digitalWrite(LED_PIN, (millis() / 500) % 2);
    }

    // Handle RFID cards
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
        handleRFID();
    }

    // Handle Fingerprint
    handleFingerprint();

    delay(50);  // Small delay to prevent tight loop
}

void handleRFID() {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
        return;
    }

    String uidHex = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
        if (mfrc522.uid.uidByte[i] < 0x10) uidHex += "0";
        uidHex += String(mfrc522.uid.uidByte[i], HEX);
    }
    uidHex.toLowerCase();

    if (registrationMode) {
        // Register new card
        if (WiFi.status() == WL_CONNECTED) {
            HTTPClient http;
            http.begin("http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/register_rfid");
            http.addHeader("Content-Type", "application/json");
            String payload = "{\"user_id\":" + String(registrationUserId) + ", \"rfid_uid\":\"" + uidHex + "\"}";
            int code = http.POST(payload);
            
            if (code == 200) {
                // Success feedback
                for (int i = 0; i < 3; i++) {
                    digitalWrite(LED_GREEN, HIGH);
                    delay(100);
                    digitalWrite(LED_GREEN, LOW);
                    delay(100);
                }
                Serial.println("RFID card registered successfully!");
            } else {
                // Error feedback
                for (int i = 0; i < 3; i++) {
                    digitalWrite(LED_RED, HIGH);
                    delay(100);
                    digitalWrite(LED_RED, LOW);
                    delay(100);
                }
                Serial.println("Failed to register RFID card!");
            }
            http.end();
        }
        registrationMode = false;
        registrationUserId = -1;
        clearRegistration();
    } else {
        // Check access
        checkAccess("rfid", uidHex);
    }

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    delay(250);
}

void handleFingerprint() {
    if (!registrationMode) {
        // Normal operation - check for fingerprint
        if (finger.getImage() == FINGERPRINT_OK) {
            if (finger.image2Tz() == FINGERPRINT_OK) {
                if (finger.fingerFastSearch() == FINGERPRINT_OK) {
                    checkAccess("fingerprint", String(finger.fingerID));
                }
            }
        }
    } else {
        // Registration mode
        enrollFingerprint();
    }
}

void enrollFingerprint() {
    static enum {
        WAITING_FIRST,
        WAITING_REMOVE,
        WAITING_SECOND,
        PROCESSING
    } enrollState = WAITING_FIRST;
    
    static uint32_t stateTimer = 0;
    
    switch (enrollState) {
        case WAITING_FIRST:
            Serial.println("Place finger to enroll...");
            if (finger.getImage() == FINGERPRINT_OK) {
                if (finger.image2Tz(1) == FINGERPRINT_OK) {
                    Serial.println("Remove finger");
                    enrollState = WAITING_REMOVE;
                    stateTimer = millis();
                }
            }
            break;
            
        case WAITING_REMOVE:
            if (finger.getImage() == FINGERPRINT_NOFINGER) {
                Serial.println("Place same finger again...");
                enrollState = WAITING_SECOND;
            } else if (millis() - stateTimer > 5000) {
                enrollState = WAITING_FIRST; // Timeout, start over
            }
            break;
            
        case WAITING_SECOND:
            if (finger.getImage() == FINGERPRINT_OK) {
                if (finger.image2Tz(2) == FINGERPRINT_OK) {
                    Serial.println("Processing...");
                    enrollState = PROCESSING;
                }
            }
            break;
            
        case PROCESSING:
            if (finger.createModel() == FINGERPRINT_OK) {
                // Find next available ID
                int id = 1;
                while (id < 128) {
                    if (!finger.loadModel(id)) break;
                    id++;
                }
                
                if (finger.storeModel(id) == FINGERPRINT_OK) {
                    Serial.println("Fingerprint enrolled successfully!");
                    
                    // Register with backend
                    if (WiFi.status() == WL_CONNECTED) {
                        HTTPClient http;
                        http.begin("http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/register_fingerprint");
                        http.addHeader("Content-Type", "application/json");
                        String payload = "{\"user_id\":" + String(registrationUserId) + ", \"fingerprint_id\":" + String(id) + "}";
                        http.POST(payload);
                        http.end();
                    }
                    
                    // Success feedback
                    for (int i = 0; i < 3; i++) {
                        digitalWrite(LED_GREEN, HIGH);
                        delay(200);
                        digitalWrite(LED_GREEN, LOW);
                        delay(200);
                    }
                }
            } else {
                // Error feedback
                for (int i = 0; i < 3; i++) {
                    digitalWrite(LED_RED, HIGH);
                    delay(200);
                    digitalWrite(LED_RED, LOW);
                    delay(200);
                }
            }
            
            registrationMode = false;
            registrationUserId = -1;
            clearRegistration();
            enrollState = WAITING_FIRST;
            break;
    }
}

void checkAccess(String method, String identifier) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("No WiFi connection");
        return;
    }

    HTTPClient http;
    http.begin(CHECK_ACCESS_URL);
    http.addHeader("Content-Type", "application/json");
    
    String payload;
    if (method == "rfid") {
        payload = "{\"method\":\"rfid\",\"rfid_uid\":\"" + identifier + "\"}";
    } else {
        payload = "{\"method\":\"fingerprint\",\"fingerprint_id\":" + identifier + "}";
    }
    
    int code = http.POST(payload);
    if (code == 200) {
        String response = http.getString();
        if (response.indexOf("\"access_granted\":true") != -1) {
            // Grant access
            Serial.println("Access granted!");
            doorServo.write(180);
            digitalWrite(LED_GREEN, HIGH);
            delay(DOOR_OPEN_MS);
            doorServo.write(0);
            digitalWrite(LED_GREEN, LOW);
        } else {
            // Deny access
            Serial.println("Access denied!");
            digitalWrite(LED_RED, HIGH);
            delay(1000);
            digitalWrite(LED_RED, LOW);
        }
    }
    http.end();
}

void setupFingerprint() {
    FingerSerial.begin(57600, SERIAL_8N1, FINGER_RX, FINGER_TX);
    if (finger.verifyPassword()) {
        Serial.println("Fingerprint sensor connected!");
        // Get the total number of templates
        uint8_t templateCount = finger.getTemplateCount();
        Serial.print("Sensor contains "); Serial.print(templateCount); Serial.println(" templates");
    } else {
        Serial.println("Fingerprint sensor not found!");
    }
}

void pollRegistration() {
    if (WiFi.status() != WL_CONNECTED) return;
    
    HTTPClient http;
    http.begin(POLL_REG_URL);
    int code = http.GET();
    
    if (code == 200) {
        String response = http.getString();
        if (response.indexOf("\"register\": true") != -1) {
            // Extract user_id
            int startPos = response.indexOf("\"user_id\":") + 10;
            int endPos = response.indexOf("}", startPos);
            if (startPos > 9 && endPos != -1) {
                registrationUserId = response.substring(startPos, endPos).toInt();
                registrationMode = true;
                Serial.print("Registration mode activated for user_id: ");
                Serial.println(registrationUserId);
                
                // Visual feedback
                digitalWrite(LED_PIN, HIGH);
            }
        }
    }
    http.end();
}

void clearRegistration() {
    if (WiFi.status() != WL_CONNECTED) return;
    
    HTTPClient http;
    http.begin(CLEAR_REG_URL);
    http.addHeader("Content-Type", "application/json");
    http.POST("{}");
    http.end();
    
    digitalWrite(LED_PIN, LOW);
}