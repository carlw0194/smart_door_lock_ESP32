#!/usr/bin/env python3
"""
Hardware Simulator for Smart Door Lock System
Simulates ESP32, RFID, fingerprint sensor, and other hardware components
"""

import requests
import json
import time
import random
import threading
from datetime import datetime
import sys
import os

class HardwareSimulator:
    """Simulates all hardware components for testing without physical devices"""
    
    def __init__(self, backend_url="http://localhost:5000", api_key=None):
        self.backend_url = backend_url
        self.api_key = api_key
        self.is_running = False
        self.door_state = "closed"
        
        # Simulated users with RFID and fingerprint data
        self.simulated_users = {
            "alice_smith": {
                "rfid_uid": "04:52:1A:2B",
                "fingerprint_id": 1,
                "employee_id": "EMP001",
                "access_level": "admin"
            },
            "bob_jones": {
                "rfid_uid": "04:63:2B:3C", 
                "fingerprint_id": 2,
                "employee_id": "EMP002",
                "access_level": "basic"
            },
            "carol_wilson": {
                "rfid_uid": "04:74:3C:4D",
                "fingerprint_id": 3,
                "employee_id": "EMP003", 
                "access_level": "basic"
            }
        }
        
        # Unknown/unauthorized attempts
        self.unauthorized_attempts = [
            {"rfid_uid": "04:99:9A:9B", "fingerprint_id": 99},
            {"rfid_uid": "04:88:8A:8B", "fingerprint_id": 88},
        ]
        
    def get_headers(self):
        """Get API headers with authentication"""
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers
    
    def simulate_rfid_access(self, user_data, success_probability=0.9):
        """Simulate RFID card access attempt"""
        print(f"🔖 Simulating RFID access: {user_data.get('rfid_uid', 'Unknown')}")
        
        # Simulate some failures
        success = random.random() < success_probability
        
        access_data = {
            "rfid_uid": user_data["rfid_uid"],
            "access_method": "rfid",
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            response = requests.post(
                f"{self.backend_url}/api/access/check",
                json=access_data,
                headers=self.get_headers(),
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("access_granted") and success:
                    print(f"✅ RFID Access Granted: {user_data.get('employee_id', 'Unknown')}")
                    self.simulate_door_open()
                else:
                    print(f"❌ RFID Access Denied: {user_data.get('rfid_uid', 'Unknown')}")
                return result
            else:
                print(f"⚠️ API Error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Connection Error: {e}")
            return None
    
    def simulate_fingerprint_access(self, user_data, success_probability=0.95):
        """Simulate fingerprint access attempt"""
        print(f"👆 Simulating Fingerprint access: ID {user_data.get('fingerprint_id', 'Unknown')}")
        
        # Simulate some failures
        success = random.random() < success_probability
        
        access_data = {
            "fingerprint_id": user_data["fingerprint_id"],
            "access_method": "fingerprint", 
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            response = requests.post(
                f"{self.backend_url}/api/access/check",
                json=access_data,
                headers=self.get_headers(),
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("access_granted") and success:
                    print(f"✅ Fingerprint Access Granted: {user_data.get('employee_id', 'Unknown')}")
                    self.simulate_door_open()
                else:
                    print(f"❌ Fingerprint Access Denied: ID {user_data.get('fingerprint_id', 'Unknown')}")
                return result
            else:
                print(f"⚠️ API Error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Connection Error: {e}")
            return None
    
    def simulate_door_open(self):
        """Simulate door opening and closing"""
        print("🚪 Door Opening...")
        self.door_state = "open"
        
        # Report door state to backend
        try:
            response = requests.post(
                f"{self.backend_url}/api/door/state",
                json={"state": "open"},
                headers=self.get_headers(),
                timeout=5
            )
            if response.status_code == 200:
                print("📡 Door state reported to backend")
        except Exception as e:
            print(f"⚠️ Failed to report door state: {e}")
        
        # Simulate door staying open for 3-5 seconds
        open_time = random.uniform(3, 5)
        time.sleep(open_time)
        
        print("🚪 Door Closing...")
        self.door_state = "closed"
        
        # Report door closed
        try:
            response = requests.post(
                f"{self.backend_url}/api/door/state",
                json={"state": "closed"},
                headers=self.get_headers(),
                timeout=5
            )
            if response.status_code == 200:
                print("📡 Door closed state reported")
        except Exception as e:
            print(f"⚠️ Failed to report door closed: {e}")
    
    def simulate_unauthorized_attempt(self):
        """Simulate unauthorized access attempts"""
        attempt = random.choice(self.unauthorized_attempts)
        method = random.choice(["rfid", "fingerprint"])
        
        print(f"🚨 Simulating unauthorized {method} attempt")
        
        if method == "rfid":
            self.simulate_rfid_access(attempt, success_probability=0.0)
        else:
            self.simulate_fingerprint_access(attempt, success_probability=0.0)
    
    def simulate_normal_day(self, duration_minutes=5):
        """Simulate a normal day of access attempts"""
        print(f"🌅 Starting normal day simulation ({duration_minutes} minutes)")
        
        end_time = time.time() + (duration_minutes * 60)
        
        while time.time() < end_time and self.is_running:
            # Random delay between access attempts (10-30 seconds)
            delay = random.uniform(10, 30)
            time.sleep(delay)
            
            if not self.is_running:
                break
            
            # 80% chance of legitimate access, 20% unauthorized
            if random.random() < 0.8:
                # Legitimate access
                user_name = random.choice(list(self.simulated_users.keys()))
                user_data = self.simulated_users[user_name]
                method = random.choice(["rfid", "fingerprint"])
                
                if method == "rfid":
                    self.simulate_rfid_access(user_data)
                else:
                    self.simulate_fingerprint_access(user_data)
            else:
                # Unauthorized attempt
                self.simulate_unauthorized_attempt()
        
        print("🌙 Day simulation completed")
    
    def simulate_security_scenarios(self):
        """Simulate various security scenarios for testing"""
        print("🔒 Starting security scenario simulation")
        
        scenarios = [
            ("Multiple failed attempts", self.simulate_brute_force),
            ("Off-hours access", self.simulate_off_hours_access),
            ("Rapid access attempts", self.simulate_rapid_attempts),
            ("Mixed legitimate/illegitimate", self.simulate_mixed_access)
        ]
        
        for scenario_name, scenario_func in scenarios:
            if not self.is_running:
                break
                
            print(f"\n🎭 Scenario: {scenario_name}")
            scenario_func()
            time.sleep(5)  # Pause between scenarios
        
        print("🔒 Security scenarios completed")
    
    def simulate_brute_force(self):
        """Simulate brute force attack"""
        print("🚨 Simulating brute force attack...")
        
        for i in range(5):
            if not self.is_running:
                break
            self.simulate_unauthorized_attempt()
            time.sleep(2)
    
    def simulate_off_hours_access(self):
        """Simulate off-hours access attempts"""
        print("🌙 Simulating off-hours access...")
        
        # Simulate legitimate off-hours access
        user_data = self.simulated_users["alice_smith"]  # Admin user
        self.simulate_rfid_access(user_data)
        time.sleep(3)
        
        # Simulate suspicious off-hours attempt
        self.simulate_unauthorized_attempt()
    
    def simulate_rapid_attempts(self):
        """Simulate rapid successive access attempts"""
        print("⚡ Simulating rapid access attempts...")
        
        for i in range(3):
            if not self.is_running:
                break
            user_data = random.choice(list(self.simulated_users.values()))
            self.simulate_rfid_access(user_data)
            time.sleep(1)
    
    def simulate_mixed_access(self):
        """Simulate mixed legitimate and illegitimate access"""
        print("🔄 Simulating mixed access patterns...")
        
        for i in range(4):
            if not self.is_running:
                break
                
            if i % 2 == 0:
                # Legitimate
                user_data = random.choice(list(self.simulated_users.values()))
                method = random.choice(["rfid", "fingerprint"])
                if method == "rfid":
                    self.simulate_rfid_access(user_data)
                else:
                    self.simulate_fingerprint_access(user_data)
            else:
                # Illegitimate
                self.simulate_unauthorized_attempt()
            
            time.sleep(3)
    
    def start_continuous_simulation(self):
        """Start continuous simulation in background"""
        self.is_running = True
        
        def run_simulation():
            while self.is_running:
                try:
                    self.simulate_normal_day(duration_minutes=2)
                    if self.is_running:
                        time.sleep(10)  # Pause between cycles
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"❌ Simulation error: {e}")
                    time.sleep(5)
        
        thread = threading.Thread(target=run_simulation, daemon=True)
        thread.start()
        return thread
    
    def stop_simulation(self):
        """Stop the simulation"""
        self.is_running = False
        print("🛑 Simulation stopped")

def main():
    """Main function to run hardware simulation"""
    print("🔧 Smart Door Lock Hardware Simulator")
    print("=" * 50)
    
    # Default API key (you'll need to get this from your backend)
    api_key = input("Enter API key (or press Enter to skip): ").strip()
    if not api_key:
        api_key = None
        print("⚠️ Running without API key - some features may not work")
    
    simulator = HardwareSimulator(api_key=api_key)
    
    while True:
        print("\n📋 Simulation Options:")
        print("1. Test single RFID access")
        print("2. Test single fingerprint access") 
        print("3. Simulate normal day (5 minutes)")
        print("4. Run security scenarios")
        print("5. Start continuous simulation")
        print("6. Test unauthorized access")
        print("7. Exit")
        
        choice = input("\nSelect option (1-7): ").strip()
        
        if choice == "1":
            user_name = input("Enter user name (alice_smith/bob_jones/carol_wilson): ").strip()
            if user_name in simulator.simulated_users:
                simulator.simulate_rfid_access(simulator.simulated_users[user_name])
            else:
                print("❌ Unknown user")
        
        elif choice == "2":
            user_name = input("Enter user name (alice_smith/bob_jones/carol_wilson): ").strip()
            if user_name in simulator.simulated_users:
                simulator.simulate_fingerprint_access(simulator.simulated_users[user_name])
            else:
                print("❌ Unknown user")
        
        elif choice == "3":
            simulator.simulate_normal_day()
        
        elif choice == "4":
            simulator.simulate_security_scenarios()
        
        elif choice == "5":
            print("🔄 Starting continuous simulation...")
            print("Press Ctrl+C to stop")
            try:
                thread = simulator.start_continuous_simulation()
                thread.join()
            except KeyboardInterrupt:
                simulator.stop_simulation()
        
        elif choice == "6":
            simulator.simulate_unauthorized_attempt()
        
        elif choice == "7":
            simulator.stop_simulation()
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    main()
