/*
ESP32 Smart Door Lock System
Connects to MQTT broker and handles RFID/Fingerprint authentication
*/
/* your code goes here. this is just a sample but we can use this too no problem*/
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <SPI.h>
#include <MFRC522.h>

// WiFi credentials
const char *ssid = "YOUR_WIFI_SSID";
const char *password = "YOUR_WIFI_PASSWORD";

// MQTT configuration
const char *mqtt_server = "YOUR_MQTT_BROKER_IP";
const int mqtt_port = 1883;
const char *mqtt_username = "esp32_door";
const char *mqtt_password = "YOUR_MQTT_PASSWORD";
const char *device_id = "ESP32_Door_001";

// MQTT Topics
const char *topic_access_request = "door/access/request";
const char *topic_access_response = "door/access/response";
const char *topic_door_state = "door/state";
const char *topic_system_status = "door/system/status";
const char *topic_alerts = "door/alerts";
const char *topic_user_sync = "door/users/sync";

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

// WiFi and MQTT clients
WiFiClient espClient;
PubSubClient client(espClient);

// Variables
bool door_locked = true;
bool door_open = false;
unsigned long last_heartbeat = 0;
unsigned long unlock_time = 0;
const unsigned long UNLOCK_DURATION = 5000; // 5 seconds

void setup()
{
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

    // Setup MQTT
    client.setServer(mqtt_server, mqtt_port);
    client.setCallback(mqtt_callback);

    Serial.println("ESP32 Door Lock System Ready");
    publish_system_status("online");
}

void setup_wifi()
{
    delay(10);
    Serial.println();
    Serial.print("Connecting to ");
    Serial.println(ssid);

    WiFi.begin(ssid, password);

    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }

    Serial.println("");
    Serial.println("WiFi connected");
    Serial.println("IP address: ");
    Serial.println(WiFi.localIP());
}

void mqtt_callback(char *topic, byte *payload, unsigned int length)
{
    String message;
    for (int i = 0; i < length; i++)
    {
        message += (char)payload[i];
    }

    Serial.print("Message arrived [");
    Serial.print(topic);
    Serial.print("] ");
    Serial.println(message);

    // Parse JSON message
    DynamicJsonDocument doc(1024);
    deserializeJson(doc, message);

    if (strcmp(topic, topic_access_response) == 0)
    {
        handle_access_response(doc);
    }
    else if (strcmp(topic, topic_alerts) == 0)
    {
        handle_alert(doc);
    }
    else if (strcmp(topic, topic_user_sync) == 0)
    {
        handle_user_sync(doc);
    }
}

void handle_access_response(DynamicJsonDocument &doc)
{
    bool access_granted = doc["access_granted"];
    String user_name = doc["user_name"];
    String device_id_response = doc["device_id"];

    // Only process if response is for this device
    if (device_id_response != device_id)
    {
        return;
    }

    if (access_granted)
    {
        Serial.println("Access granted for: " + user_name);
        unlock_door();
        buzz_success();
        digitalWrite(LED_GREEN_PIN, HIGH);
        digitalWrite(LED_RED_PIN, LOW);
    }
    else
    {
        Serial.println("Access denied");
        buzz_failure();
        digitalWrite(LED_RED_PIN, HIGH);
        digitalWrite(LED_GREEN_PIN, LOW);
        delay(1000);
        digitalWrite(LED_RED_PIN, LOW);
    }
}

void handle_alert(DynamicJsonDocument &doc)
{
    String alert_type = doc["type"];
    String message = doc["message"];
    String severity = doc["severity"];

    Serial.println("Security Alert: " + message);

    if (severity == "high")
    {
        // High priority alert - sound alarm
        for (int i = 0; i < 5; i++)
        {
            digitalWrite(BUZZER_PIN, HIGH);
            digitalWrite(LED_RED_PIN, HIGH);
            delay(200);
            digitalWrite(BUZZER_PIN, LOW);
            digitalWrite(LED_RED_PIN, LOW);
            delay(200);
        }
    }
}

void handle_user_sync(DynamicJsonDocument &doc)
{
    // Handle user synchronization from server
    Serial.println("User sync received");
    JsonArray users = doc["users"];

    // In a real implementation, you would store user data in EEPROM/SPIFFS
    // For this example, we just log the users
    Serial.print("Synchronized ");
    Serial.print(users.size());
    Serial.println(" users");
}

void reconnect()
{
    while (!client.connected())
    {
        Serial.print("Attempting MQTT connection...");

        if (client.connect(device_id, mqtt_username, mqtt_password))
        {
            Serial.println("connected");

            // Subscribe to topics
            client.subscribe(topic_access_response);
            client.subscribe(topic_alerts);
            client.subscribe(topic_user_sync);

            publish_system_status("connected");
        }
        else
        {
            Serial.print("failed, rc=");
            Serial.print(client.state());
            Serial.println(" try again in 5 seconds");
            delay(5000);
        }
    }
}

void check_rfid()
{
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
    {
        return;
    }

    // Read RFID UID
    String rfid_uid = "";
    for (byte i = 0; i < mfrc522.uid.size; i++)
    {
        rfid_uid += String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
        rfid_uid += String(mfrc522.uid.uidByte[i], HEX);
    }
    rfid_uid.toUpperCase();

    Serial.println("RFID detected: " + rfid_uid);

    // Send access request via MQTT
    request_access("rfid", rfid_uid, "");

    mfrc522.PICC_HaltA();
}

void request_access(String method, String rfid_uid, String fingerprint_id)
{
    DynamicJsonDocument doc(1024);
    doc["method"] = method;
    doc["device_id"] = device_id;

    if (method == "rfid")
    {
        doc["rfid_uid"] = rfid_uid;
    }
    else if (method == "fingerprint")
    {
        doc["fingerprint_id"] = fingerprint_id;
    }

    String output;
    serializeJson(doc, output);

    client.publish(topic_access_request, output.c_str());
    Serial.println("Access request sent: " + output);
}

void unlock_door()
{
    digitalWrite(RELAY_PIN, HIGH); // Unlock
    door_locked = false;
    unlock_time = millis();

    publish_door_state("unlocked");
    Serial.println("Door unlocked");
}

void lock_door()
{
    digitalWrite(RELAY_PIN, LOW); // Lock
    door_locked = true;

    digitalWrite(LED_GREEN_PIN, LOW);
    digitalWrite(LED_RED_PIN, HIGH);

    publish_door_state("locked");
    Serial.println("Door locked");
}

void check_door_sensor()
{
    bool current_door_state = digitalRead(DOOR_SENSOR_PIN) == HIGH;

    if (current_door_state != door_open)
    {
        door_open = current_door_state;

        if (door_open)
        {
            publish_door_state("open");
            Serial.println("Door opened");
        }
        else
        {
            publish_door_state("closed");
            Serial.println("Door closed");
        }
    }
}

void publish_door_state(String state)
{
    DynamicJsonDocument doc(512);
    doc["state"] = state;
    doc["device_id"] = device_id;
    doc["timestamp"] = millis();

    String output;
    serializeJson(doc, output);

    client.publish(topic_door_state, output.c_str());
}

void publish_system_status(String status)
{
    DynamicJsonDocument doc(512);
    doc["device_id"] = device_id;
    doc["status"] = status;
    doc["timestamp"] = millis();
    doc["wifi_rssi"] = WiFi.RSSI();
    doc["free_heap"] = ESP.getFreeHeap();

    String output;
    serializeJson(doc, output);

    client.publish(topic_system_status, output.c_str());
}

void buzz_success()
{
    digitalWrite(BUZZER_PIN, HIGH);
    delay(100);
    digitalWrite(BUZZER_PIN, LOW);
    delay(50);
    digitalWrite(BUZZER_PIN, HIGH);
    delay(100);
    digitalWrite(BUZZER_PIN, LOW);
}

void buzz_failure()
{
    for (int i = 0; i < 3; i++)
    {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(200);
        digitalWrite(BUZZER_PIN, LOW);
        delay(100);
    }
}

void loop()
{
    if (!client.connected())
    {
        reconnect();
    }
    client.loop();

    // Check RFID for new cards
    check_rfid();

    // Check door sensor
    check_door_sensor();

    // Auto-lock door after timeout
    if (!door_locked && (millis() - unlock_time > UNLOCK_DURATION))
    {
        lock_door();
    }

    // Send heartbeat every 30 seconds
    if (millis() - last_heartbeat > 30000)
    {
        publish_system_status("online");
        last_heartbeat = millis();
    }

    delay(100);
}
