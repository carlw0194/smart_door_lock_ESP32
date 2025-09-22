import serial
import json
import time
from flask import Flask, jsonify, request
from datetime import datetime

app = Flask(__name__)

# Configure the serial port
SERIAL_PORT = 'COM3'  # Change this to match your ESP32's port
BAUD_RATE = 115200

# Initialize serial connection
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
time.sleep(2)  # Wait for connection to establish

def send_command(command):
    """Send a command to ESP32"""
    cmd_json = json.dumps(command) + '\n'
    ser.write(cmd_json.encode())
    time.sleep(0.1)
    return read_response()

def read_response():
    """Read response from ESP32"""
    if ser.in_waiting:
        response = ser.readline().decode().strip()
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {"status": "error", "message": "Invalid JSON response"}
    return {"status": "error", "message": "No response"}

@app.route('/api/check_access', methods=['POST'])
def check_access():
    """Handle access check requests"""
    data = request.get_json()
    rfid_uid = data.get('rfid_uid')
    
    # Check if user exists in database
    # This is where you would add your database check
    access_granted = True  # Replace with actual check
    
    if access_granted:
        response = send_command({"command": "unlock"})
    else:
        response = {"status": "denied", "message": "Access denied"}
    
    return jsonify(response)

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get door status"""
    response = send_command({"command": "status"})
    return jsonify(response)

def handle_rfid_scan(data):
    """Handle RFID scan from ESP32"""
    uid = data.get('uid')
    print(f"RFID card scanned: {uid}")
    # Add your RFID processing logic here
    
def process_serial():
    """Process incoming serial data"""
    while True:
        if ser.in_waiting:
            data = read_response()
            if data.get('type') == 'rfid_scan':
                handle_rfid_scan(data)
            print(f"Received: {data}")
        time.sleep(0.1)

if __name__ == '__main__':
    import threading
    # Start serial processing in a separate thread
    serial_thread = threading.Thread(target=process_serial, daemon=True)
    serial_thread.start()
    
    # Start Flask server
    app.run(host='0.0.0.0', port=5000)