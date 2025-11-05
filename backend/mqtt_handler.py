"""
MQTT Handler for Smart Door Lock System
Handles real-time communication with ESP32 devices
"""

import paho.mqtt.client as mqtt
import json
import logging
from datetime import datetime
from threading import Thread
import os
from dotenv import load_dotenv

load_dotenv()

class MQTTHandler:
    def __init__(self, app, db):
        self.app = app
        self.db = db
        self.client = mqtt.Client()
        self.broker_host = os.getenv('MQTT_BROKER_HOST', 'localhost')
        self.broker_port = int(os.getenv('MQTT_BROKER_PORT', 1883))
        self.username = os.getenv('MQTT_USERNAME')
        self.password = os.getenv('MQTT_PASSWORD')
        
        # MQTT Topics
        self.topics = {
            'access_request': 'door/access/request',
            'access_response': 'door/access/response',
            'door_state': 'door/state',
            'system_status': 'door/system/status',
            'alerts': 'door/alerts',
            'user_sync': 'door/users/sync'
        }
        
        self.setup_mqtt()
        
    def setup_mqtt(self):
        """Setup MQTT client callbacks and connection"""
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect
        
        if self.username and self.password:
            self.client.username_pw_set(self.username, self.password)
            
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
    def on_connect(self, client, userdata, flags, rc):
        """Callback for when client connects to MQTT broker"""
        if rc == 0:
            self.logger.info("Connected to MQTT broker")
            # Subscribe to relevant topics
            for topic_name, topic in self.topics.items():
                if topic_name in ['access_request', 'door_state', 'system_status']:
                    client.subscribe(topic)
                    self.logger.info(f"Subscribed to {topic}")
        else:
            self.logger.error(f"Failed to connect to MQTT broker: {rc}")
            
    def on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages"""
        try:
            topic = msg.topic
            payload = json.loads(msg.payload.decode())
            self.logger.info(f"Received message on {topic}: {payload}")
            
            with self.app.app_context():
                if topic == self.topics['access_request']:
                    self.handle_access_request(payload)
                elif topic == self.topics['door_state']:
                    self.handle_door_state(payload)
                elif topic == self.topics['system_status']:
                    self.handle_system_status(payload)
                    
        except Exception as e:
            self.logger.error(f"Error processing MQTT message: {e}")
            
    def on_disconnect(self, client, userdata, rc):
        """Callback for when client disconnects"""
        self.logger.warning(f"Disconnected from MQTT broker: {rc}")
        
    def handle_access_request(self, payload):
        """Handle access request from ESP32"""
        from backend.app2 import User, AccessLog, log_security_event
        
        method = payload.get('method')
        rfid_uid = payload.get('rfid_uid')
        fingerprint_id = payload.get('fingerprint_id')
        device_id = payload.get('device_id', 'unknown')
        
        user = None
        access_granted = False
        
        # Check user credentials
        if method == 'rfid' and rfid_uid:
            user = User.query.filter_by(rfid_uid=rfid_uid, is_active=True).first()
        elif method == 'fingerprint' and fingerprint_id:
            user = User.query.filter_by(fingerprint_id=fingerprint_id, is_active=True).first()
            
        if user:
            access_granted = True
            user.last_access = datetime.utcnow()
            self.db.session.commit()
            
        # Log access attempt
        log_entry = AccessLog(
            user_id=user.id if user else None,
            access_method=method,
            access_granted=access_granted,
            rfid_uid=rfid_uid,
            fingerprint_id=fingerprint_id,
            ip_address='MQTT'
        )
        self.db.session.add(log_entry)
        self.db.session.commit()
        
        # Send response back to ESP32
        response = {
            'access_granted': access_granted,
            'user_name': user.name if user else None,
            'user_id': user.id if user else None,
            'timestamp': datetime.utcnow().isoformat(),
            'device_id': device_id
        }
        
        self.publish_message(self.topics['access_response'], response)
        
        # Log security event if access denied
        if not access_granted:
            log_security_event('mqtt_access_denied', f'Device: {device_id}, Method: {method}')
            
    def handle_door_state(self, payload):
        """Handle door state updates from ESP32"""
        from backend.app2 import log_security_event
        
        state = payload.get('state')
        device_id = payload.get('device_id', 'unknown')
        timestamp = payload.get('timestamp')
        
        # Log door state change
        log_security_event('mqtt_door_state', f'Device: {device_id}, State: {state}')
        
        # Broadcast state to web clients (for real-time updates)
        self.broadcast_to_web_clients({
            'type': 'door_state',
            'state': state,
            'device_id': device_id,
            'timestamp': timestamp or datetime.utcnow().isoformat()
        })
        
    def handle_system_status(self, payload):
        """Handle system status updates from ESP32"""
        device_id = payload.get('device_id', 'unknown')
        status = payload.get('status')
        
        self.logger.info(f"System status from {device_id}: {status}")
        
        # Store device status (you can extend this to store in database)
        self.broadcast_to_web_clients({
            'type': 'system_status',
            'device_id': device_id,
            'status': status,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    def publish_message(self, topic, payload):
        """Publish message to MQTT topic"""
        try:
            message = json.dumps(payload)
            self.client.publish(topic, message)
            self.logger.info(f"Published to {topic}: {payload}")
        except Exception as e:
            self.logger.error(f"Error publishing MQTT message: {e}")
            
    def broadcast_to_web_clients(self, data):
        """Broadcast data to web clients via WebSocket (placeholder)"""
        # This would integrate with WebSocket implementation
        # For now, just log the broadcast
        self.logger.info(f"Broadcasting to web clients: {data}")
        
    def sync_users_to_esp32(self):
        """Sync user data to ESP32 devices"""
        from backend.app2 import User
        
        users = User.query.filter_by(is_active=True).all()
        user_data = []
        
        for user in users:
            user_data.append({
                'id': user.id,
                'name': user.name,
                'rfid_uid': user.rfid_uid,
                'fingerprint_id': user.fingerprint_id,
                'access_level': user.access_level
            })
            
        sync_payload = {
            'users': user_data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.publish_message(self.topics['user_sync'], sync_payload)
        
    def send_alert(self, alert_type, message, severity='medium'):
        """Send security alert to ESP32 and web clients"""
        alert_payload = {
            'type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.publish_message(self.topics['alerts'], alert_payload)
        self.broadcast_to_web_clients(alert_payload)
        
    def connect(self):
        """Connect to MQTT broker"""
        try:
            self.client.connect(self.broker_host, self.broker_port, 60)
            self.client.loop_start()
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to MQTT broker: {e}")
            return False
            
    def disconnect(self):
        """Disconnect from MQTT broker"""
        self.client.loop_stop()
        self.client.disconnect()
        
    def run_in_background(self):
        """Run MQTT client in background thread"""
        def mqtt_thread():
            if self.connect():
                self.logger.info("MQTT handler running in background")
            else:
                self.logger.error("Failed to start MQTT handler")
                
        thread = Thread(target=mqtt_thread)
        thread.daemon = True
        thread.start()
        return thread
