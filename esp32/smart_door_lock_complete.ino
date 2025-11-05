#include <SPI.h>
#include <MFRC522.h>
#include <Adafruit_Fingerprint.h>
#include <ESP32Servo.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

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
// NOTE: set this to the machine IP where the backend is running (found: 192.168.31.252)
const char* SERVER_HOST = "192.168.31.252";
const int   SERVER_PORT = 5000;
// API key for backend requests (set this to a valid key from the backend)
const char* API_KEY = "ZQ33zgth1L1gT8MJiyoC2DLajXakBWsrgu9V-ulLgaY";

String CHECK_ACCESS_URL;
String DOOR_STATE_URL;
String POLL_REG_URL;
String CLEAR_REG_URL;
String REGISTER_RFID_URL;
String REGISTER_FP_URL;

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

// Improved WiFi connect with timeout and debug output
void connectWiFi() {
    Serial.print("Connecting to WiFi ");
    Serial.println(WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true);
    delay(100);
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    unsigned long start = millis();
    const unsigned long timeout = 20000; // 20s
    while (WiFi.status() != WL_CONNECTED && millis() - start < timeout) {
        delay(500);
        Serial.print(".");
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\nWiFi connected! IP: " + WiFi.localIP().toString());
    } else {
        Serial.println("\nWiFi connect failed, status: " + String(WiFi.status()));
    }
}


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
    Serial.print("Servo attached: "); Serial.println(doorServo.attached());

    // Initialize WiFi (non-blocking connect with debug)
    connectWiFi();

    // Set up URLs
    CHECK_ACCESS_URL = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/check_access";
    DOOR_STATE_URL  = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/door_state";
    POLL_REG_URL    = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/poll_registration";
    CLEAR_REG_URL   = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/clear_registration";
    REGISTER_RFID_URL = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/register_rfid";
    REGISTER_FP_URL   = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/api/register_fingerprint";

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
    // Check WiFi and attempt reconnect if disconnected
    if (WiFi.status() != WL_CONNECTED) {
        digitalWrite(LED_RED, HIGH);
        Serial.println("WiFi disconnected, attempting reconnect...");
        connectWiFi();
        // don't return; continue and let connection-checks guard network calls
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

    // Serial commands for debug
    if (Serial.available()) {
        char c = Serial.read();
        if (c == 't') {
            printTemplates();
        }
    }

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
    uidHex.toUpperCase();

    if (registrationMode) {
        // Register new card
        if (WiFi.status() == WL_CONNECTED) {
            HTTPClient http;
                http.begin(REGISTER_RFID_URL);
            http.addHeader("Content-Type", "application/json");
            http.addHeader("X-API-Key", API_KEY);
            String payload = "{\"user_id\":" + String(registrationUserId) + ", \"rfid_uid\":\"" + uidHex + "\"}";
            Serial.print("register_rfid payload: "); Serial.println(payload);
            Serial.print("X-API-Key: "); Serial.println(API_KEY);
            int regCode = http.POST(payload);
            String regResp = http.getString();
            Serial.print("register_rfid HTTP code: "); Serial.println(regCode);
            Serial.print("register_rfid response: "); Serial.println(regResp);
            
            if (regCode == 200) {
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
                    Serial.println("[enroll] image2Tz(1) returned OK");
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
                    Serial.println("[enroll] image2Tz(2) returned OK");
                    enrollState = PROCESSING;
                }
            }
            break;

        case PROCESSING: {
            int r = finger.createModel();
            Serial.print("[enroll] createModel() returned: "); Serial.println(r);
            if (r == FINGERPRINT_OK) {
                // Find next available ID
                int id = 1;
                // loadModel(id) returns FINGERPRINT_OK (0) when a template exists at that ID.
                // We want the first ID that does NOT have a template.
                while (id < 128) {
                    int rr = finger.loadModel(id);
                    if (rr != FINGERPRINT_OK) {
                        // no template at this ID, use it
                        break;
                    }
                    id++;
                }
                if (id >= 128) {
                    Serial.println("[enroll] no free template ID available on sensor");
                    // give feedback and abort
                    for (int i = 0; i < 3; i++) { digitalWrite(LED_RED, HIGH); delay(200); digitalWrite(LED_RED, LOW); delay(200); }
                    break; // exit PROCESSING
                }
                Serial.print("[enroll] chosen template ID: "); Serial.println(id);

                int s = finger.storeModel(id);
                Serial.print("[enroll] storeModel() returned: "); Serial.println(s);
                if (s == FINGERPRINT_OK) {
                    Serial.print("Fingerprint enrolled successfully! Template ID: "); Serial.println(id);
                    // VERIFY: ask user to place the same finger again and confirm it matches the newly stored template
                    Serial.println("Verifying stored template: please place the same finger again...");
                    unsigned long verifyStart = millis();
                    const unsigned long VERIFY_TIMEOUT = 10000; // 10s to verify
                    bool verified = false;

                    // Wait for finger placement and capture image
                    while (millis() - verifyStart < VERIFY_TIMEOUT) {
                        int p = finger.getImage();
                        if (p == FINGERPRINT_OK) {
                            Serial.println("[verify] image captured");
                            if (finger.image2Tz() == FINGERPRINT_OK) {
                                Serial.println("[verify] image converted to template, running fast search...");
                                int fs = finger.fingerFastSearch();
                                Serial.print("[verify] fingerFastSearch() returned: "); Serial.println(fs);
                                if (fs == FINGERPRINT_OK) {
                                    Serial.print("[verify] found ID: "); Serial.println(finger.fingerID);
                                    Serial.print("[verify] confidence: "); Serial.println(finger.confidence);
                                    if (finger.fingerID == id) {
                                        verified = true;
                                    }
                                } else {
                                    Serial.println("[verify] fast search did not find a match for the stored template");
                                }
                                break;
                            } else {
                                Serial.println("[verify] image2Tz failed during verification");
                            }
                        }
                        delay(200);
                    }

                    if (!verified) {
                        Serial.println("Verification failed: deleting stored template to avoid bad registrations");
                        int delRes = finger.deleteModel(id);
                        Serial.print("deleteModel() returned: "); Serial.println(delRes);
                        // Error feedback
                        for (int i = 0; i < 3; i++) { digitalWrite(LED_RED, HIGH); delay(200); digitalWrite(LED_RED, LOW); delay(200); }
                        break; // abort PROCESSING and leave registrationMode (it will be cleared below)
                    }

                    // If verified locally, register with backend
                    if (WiFi.status() == WL_CONNECTED) {
                        HTTPClient http;
                        http.begin(REGISTER_FP_URL);
                        http.addHeader("Content-Type", "application/json");
                        http.addHeader("X-API-Key", API_KEY);
                        String payload = "{\"user_id\":" + String(registrationUserId) + ", \"fingerprint_id\":" + String(id) + "}";
                        Serial.print("register_fingerprint payload: "); Serial.println(payload);
                        int regCode = http.POST(payload);
                        String regResp = http.getString();
                        Serial.print("register_fingerprint HTTP code: "); Serial.println(regCode);
                        Serial.print("register_fingerprint response: "); Serial.println(regResp);

                        if (regCode == 200) {
                            // Success feedback
                            for (int i = 0; i < 3; i++) {
                                digitalWrite(LED_GREEN, HIGH);
                                delay(200);
                                digitalWrite(LED_GREEN, LOW);
                                delay(200);
                            }
                        } else {
                            Serial.println("Backend registration failed: deleting stored template to keep sensor/server consistent");
                            int delRes = finger.deleteModel(id);
                            Serial.print("deleteModel() returned: "); Serial.println(delRes);
                            for (int i = 0; i < 3; i++) { digitalWrite(LED_RED, HIGH); delay(200); digitalWrite(LED_RED, LOW); delay(200); }
                        }
                        http.end();
                    } else {
                        Serial.println("Cannot register fingerprint: no WiFi connection - retaining template for retry");
                        // Optionally, you might choose to delete the template here. For now we keep it so that user can retry registration.
                        for (int i = 0; i < 2; i++) { digitalWrite(LED_RED, HIGH); delay(150); digitalWrite(LED_RED, LOW); delay(150); }
                    }
                } else {
                    // storeModel failed
                    Serial.println("Failed to store fingerprint template on sensor");
                    // Optionally print sensor template count for debugging
                    uint8_t tc = finger.getTemplateCount();
                    Serial.print("[enroll] sensor template count: "); Serial.println(tc);
                    for (int i = 0; i < 3; i++) {
                        digitalWrite(LED_RED, HIGH);
                        delay(200);
                        digitalWrite(LED_RED, LOW);
                        delay(200);
                    }
                }
            } else {
                // createModel failed
                Serial.println("Failed to create fingerprint model");
                uint8_t tc = finger.getTemplateCount();
                Serial.print("[enroll] sensor template count: "); Serial.println(tc);
                for (int i = 0; i < 3; i++) {
                    digitalWrite(LED_RED, HIGH);
                    delay(200);
                    digitalWrite(LED_RED, LOW);
                    delay(200);
                }
            }

            // finalize registration state
            registrationMode = false;
            registrationUserId = -1;
            clearRegistration();
            enrollState = WAITING_FIRST;
        } break;
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
    http.addHeader("X-API-Key", API_KEY);

    StaticJsonDocument<200> doc;
    if (method == "rfid") {
        doc["method"] = "rfid";
        doc["rfid_uid"] = identifier;
    } else {
        doc["method"] = "fingerprint";
        doc["fingerprint_id"] = identifier.toInt();
    }

    String body;
    serializeJson(doc, body);
    Serial.print("checkAccess payload: "); Serial.println(body);
    Serial.print("X-API-Key: "); Serial.println(API_KEY);

    int code = http.POST(body);
    Serial.print("checkAccess HTTP code: "); Serial.println(code);
    String response = http.getString();
    Serial.print("checkAccess response: "); Serial.println(response);

    if (code == 200) {
        StaticJsonDocument<200> resDoc;
        DeserializationError err = deserializeJson(resDoc, response);
        if (!err) {
            bool granted = resDoc["access_granted"] | resDoc["granted"] | false;
            if (granted) {
                Serial.println("Access granted! moving servo to open");
                Serial.print("Servo attached: "); Serial.println(doorServo.attached());
                doorServo.write(90); // move to open position (adjust if needed)
                digitalWrite(LED_GREEN, HIGH);
                delay(DOOR_OPEN_MS);
                doorServo.write(0);
                Serial.println("Servo moved back to closed");
                digitalWrite(LED_GREEN, LOW);
            } else {
                Serial.println("Access denied!");
                digitalWrite(LED_RED, HIGH);
                delay(1000);
                digitalWrite(LED_RED, LOW);
            }
        } else {
            Serial.print("JSON parse error: "); Serial.println(err.c_str());
        }
    } else {
        Serial.print("checkAccess HTTP error code: "); Serial.println(code);
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
    http.addHeader("X-API-Key", API_KEY);
    int code = http.GET();
    
    if (code == 200) {
        String response = http.getString();
        Serial.print("pollRegistration response: "); Serial.println(response);
        // Parse JSON response using ArduinoJson to avoid brittle string parsing
        StaticJsonDocument<200> doc;
        DeserializationError err = deserializeJson(doc, response);
        if (!err) {
            bool reg = doc["register"] | false;
            if (reg) {
                int uid = doc["user_id"] | -1;
                if (uid > 0) {
                    registrationUserId = uid;
                    registrationMode = true;
                    Serial.print("Registration mode activated for user_id: ");
                    Serial.println(registrationUserId);
                    // Visual feedback
                    digitalWrite(LED_PIN, HIGH);
                }
            }
        } else {
            Serial.print("pollRegistration JSON parse error: "); Serial.println(err.c_str());
        }
    }
    http.end();
}

void clearRegistration() {
    if (WiFi.status() != WL_CONNECTED) return;
    
    HTTPClient http;
    http.begin(CLEAR_REG_URL);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-API-Key", API_KEY);
    int clrCode = http.POST("{}");
    String clrResp = http.getString();
    Serial.print("clearRegistration HTTP code: "); Serial.println(clrCode);
    Serial.print("clearRegistration response: "); Serial.println(clrResp);
    http.end();
    
    digitalWrite(LED_PIN, LOW);
}

// Send door state to backend (with API key)
void updateDoorState(String state) {
    if (WiFi.status() != WL_CONNECTED) return;
    HTTPClient http;
    http.begin(DOOR_STATE_URL);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-API-Key", API_KEY);

    String body = "{\"state\":\"" + state + "\"}";
    int code = http.POST(body);
    Serial.print("updateDoorState HTTP code: "); Serial.println(code);
    String resp = http.getString();
    Serial.print("updateDoorState response: "); Serial.println(resp);
    http.end();
}

void indicateSuccess() {
    digitalWrite(LED_GREEN, HIGH);
    delay(200);
    digitalWrite(LED_GREEN, LOW);
}

void indicateError() {
    digitalWrite(LED_RED, HIGH);
    delay(200);
    digitalWrite(LED_RED, LOW);
}

// Debug helper: list templates on fingerprint sensor
void printTemplates() {
    if (!finger.verifyPassword()) {
        Serial.println("[debug] Fingerprint sensor not available for template listing");
        return;
    }
    uint8_t count = finger.getTemplateCount();
    Serial.print("[debug] Template count: "); Serial.println(count);
    Serial.println("[debug] Scanning template IDs (this may take a few seconds)...");
    for (int i = 1; i <= 127; i++) {
        int r = finger.loadModel(i);
        if (r == FINGERPRINT_OK) {
            Serial.print("[debug] Template present: ID "); Serial.println(i);
        }
    }
    Serial.println("[debug] Template scan complete");
}