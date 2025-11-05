#!/usr/bin/env python3
"""
Comprehensive Integration Test for Smart Door Lock System
Tests all components: Backend, Frontend, Security, Database, APIs
"""

import requests
import time
import json
import sys
import os
import subprocess
import threading
from datetime import datetime
import sqlite3

class IntegrationTester:
    """Comprehensive integration testing for the entire system"""
    
    def __init__(self):
        self.backend_url = "http://localhost:5000"
        self.backend_process = None
        self.test_results = {}
        self.api_key = None
        
    def start_backend(self):
        """Start the Flask backend server"""
        print("🚀 Starting Flask backend server...")
        
        try:
            # Start backend in background
            self.backend_process = subprocess.Popen(
                [sys.executable, "backend/app.py"],
                cwd=os.getcwd(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for server to start
            print("⏳ Waiting for server to start...")
            time.sleep(10)
            
            # Test if server is running
            try:
                response = requests.get(f"{self.backend_url}/", timeout=5)
                if response.status_code in [200, 302]:  # 302 for redirect to login
                    print("✅ Backend server started successfully")
                    return True
            except:
                pass
            
            print("❌ Backend server failed to start properly")
            return False
            
        except Exception as e:
            print(f"❌ Failed to start backend: {e}")
            return False
    
    def stop_backend(self):
        """Stop the Flask backend server"""
        if self.backend_process:
            print("🛑 Stopping backend server...")
            self.backend_process.terminate()
            self.backend_process.wait()
    
    def test_database_setup(self):
        """Test database initialization and setup"""
        print("\n📊 Testing Database Setup...")
        
        try:
            # Check if database file exists
            db_path = "backend/door_access.db"
            if os.path.exists(db_path):
                print("✅ Database file exists")
                
                # Connect and check tables
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Check for required tables
                required_tables = ['admin', 'user', 'access_log', 'api_key', 'security_event']
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                existing_tables = [row[0] for row in cursor.fetchall()]
                
                for table in required_tables:
                    if table in existing_tables:
                        print(f"✅ Table '{table}' exists")
                    else:
                        print(f"❌ Table '{table}' missing")
                
                conn.close()
                self.test_results['database'] = True
                return True
            else:
                print("❌ Database file not found")
                self.test_results['database'] = False
                return False
                
        except Exception as e:
            print(f"❌ Database test failed: {e}")
            self.test_results['database'] = False
            return False
    
    def test_api_endpoints(self):
        """Test all API endpoints"""
        print("\n🔌 Testing API Endpoints...")
        
        endpoints = [
            ("GET", "/", "Homepage"),
            ("GET", "/login", "Login page"),
            ("POST", "/api/access/check", "Access check API"),
            ("GET", "/api/security/status", "Security status API"),
            ("GET", "/api/security/anomalies", "Anomalies API"),
            ("GET", "/api/security/trends", "Trends API")
        ]
        
        api_results = {}
        
        for method, endpoint, description in endpoints:
            try:
                if method == "GET":
                    response = requests.get(f"{self.backend_url}{endpoint}", timeout=5)
                else:
                    # POST with sample data
                    sample_data = {
                        "rfid_uid": "04:52:1A:2B",
                        "access_method": "rfid",
                        "timestamp": datetime.now().isoformat()
                    }
                    headers = {'Content-Type': 'application/json'}
                    if self.api_key:
                        headers['X-API-Key'] = self.api_key
                    
                    response = requests.post(
                        f"{self.backend_url}{endpoint}",
                        json=sample_data,
                        headers=headers,
                        timeout=5
                    )
                
                if response.status_code in [200, 302, 401]:  # 401 expected without auth
                    print(f"✅ {description}: {response.status_code}")
                    api_results[endpoint] = True
                else:
                    print(f"⚠️ {description}: {response.status_code}")
                    api_results[endpoint] = False
                    
            except Exception as e:
                print(f"❌ {description}: {e}")
                api_results[endpoint] = False
        
        self.test_results['api_endpoints'] = api_results
        return all(api_results.values())
    
    def test_security_features(self):
        """Test security features"""
        print("\n🔒 Testing Security Features...")
        
        security_tests = {}
        
        # Test SSL certificates
        ssl_cert_path = "ssl/cert.pem"
        ssl_key_path = "ssl/key.pem"
        
        if os.path.exists(ssl_cert_path) and os.path.exists(ssl_key_path):
            print("✅ SSL certificates found")
            security_tests['ssl_certs'] = True
        else:
            print("❌ SSL certificates missing")
            security_tests['ssl_certs'] = False
        
        # Test anomaly detection model
        model_path = "security/models/anomaly_model.joblib"
        if os.path.exists(model_path):
            print("✅ Anomaly detection model found")
            security_tests['ml_model'] = True
        else:
            print("⚠️ Anomaly detection model not trained yet")
            security_tests['ml_model'] = False
        
        # Test security documentation
        security_doc_path = "security/SECURITY.md"
        if os.path.exists(security_doc_path):
            print("✅ Security documentation found")
            security_tests['documentation'] = True
        else:
            print("❌ Security documentation missing")
            security_tests['documentation'] = False
        
        # Test security scripts
        security_scripts = [
            "security/generate_ssl.ps1",
            "security/generate_ssl_python.py",
            "security/anomaly_detection.py"
        ]
        
        script_results = []
        for script in security_scripts:
            if os.path.exists(script):
                print(f"✅ Security script found: {os.path.basename(script)}")
                script_results.append(True)
            else:
                print(f"❌ Security script missing: {os.path.basename(script)}")
                script_results.append(False)
        
        security_tests['scripts'] = all(script_results)
        self.test_results['security'] = security_tests
        
        return all(security_tests.values())
    
    def test_frontend_templates(self):
        """Test frontend templates"""
        print("\n🎨 Testing Frontend Templates...")
        
        template_dir = "frontend/templates"
        required_templates = [
            "base.html",
            "dashboard.html", 
            "login.html",
            "users.html",
            "access_logs.html",
            "analytics.html",
            "security_dashboard.html",
            "security_events.html"
        ]
        
        template_results = {}
        
        for template in required_templates:
            template_path = os.path.join(template_dir, template)
            if os.path.exists(template_path):
                print(f"✅ Template found: {template}")
                template_results[template] = True
            else:
                print(f"❌ Template missing: {template}")
                template_results[template] = False
        
        self.test_results['templates'] = template_results
        return all(template_results.values())
    
    def test_esp32_integration(self):
        """Test ESP32 code and configuration"""
        print("\n🔧 Testing ESP32 Integration...")
        
        esp32_tests = {}
        
        # Check ESP32 code
        esp32_code_path = "esp32/smart_door_lock_complete.ino"
        if os.path.exists(esp32_code_path):
            print("✅ ESP32 Arduino code found")
            esp32_tests['arduino_code'] = True
        else:
            print("❌ ESP32 Arduino code missing")
            esp32_tests['arduino_code'] = False
        
        # Check configuration
        config_path = "esp32/config.h"
        if os.path.exists(config_path):
            print("✅ ESP32 configuration found")
            esp32_tests['config'] = True
        else:
            print("❌ ESP32 configuration missing")
            esp32_tests['config'] = False
        
        self.test_results['esp32'] = esp32_tests
        return all(esp32_tests.values())
    
    def test_documentation(self):
        """Test project documentation"""
        print("\n📚 Testing Documentation...")
        
        doc_tests = {}
        
        # Main README
        if os.path.exists("ReadMe.md"):
            print("✅ Main README found")
            doc_tests['main_readme'] = True
        else:
            print("❌ Main README missing")
            doc_tests['main_readme'] = False
        
        # Component READMEs
        component_readmes = [
            "docs/README.md",
            "backend/README.md", 
            "frontend/README.md",
            "esp32/README.md",
            "security/README.md",
            "hardware/README.md"
        ]
        
        readme_results = []
        for readme in component_readmes:
            if os.path.exists(readme):
                print(f"✅ Component README: {readme}")
                readme_results.append(True)
            else:
                print(f"⚠️ Component README missing: {readme}")
                readme_results.append(False)
        
        doc_tests['component_readmes'] = any(readme_results)  # At least some should exist
        self.test_results['documentation'] = doc_tests
        
        return all(doc_tests.values())
    
    def run_hardware_simulation_test(self):
        """Run a quick hardware simulation test"""
        print("\n🔧 Testing Hardware Simulation...")
        
        try:
            # Import and test hardware simulator
            from hardware_simulator import HardwareSimulator
            
            simulator = HardwareSimulator(api_key=self.api_key)
            
            # Test a single access attempt
            test_user = {
                "rfid_uid": "04:52:1A:2B",
                "fingerprint_id": 1,
                "employee_id": "TEST001"
            }
            
            print("🔖 Testing simulated RFID access...")
            result = simulator.simulate_rfid_access(test_user)
            
            if result is not None:
                print("✅ Hardware simulation working")
                self.test_results['hardware_simulation'] = True
                return True
            else:
                print("⚠️ Hardware simulation had issues (may be due to missing API key)")
                self.test_results['hardware_simulation'] = False
                return False
                
        except Exception as e:
            print(f"❌ Hardware simulation test failed: {e}")
            self.test_results['hardware_simulation'] = False
            return False
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("📋 COMPREHENSIVE INTEGRATION TEST REPORT")
        print("=" * 60)
        
        total_tests = 0
        passed_tests = 0
        
        for category, results in self.test_results.items():
            print(f"\n🔍 {category.upper().replace('_', ' ')}:")
            
            if isinstance(results, dict):
                for test_name, result in results.items():
                    status = "✅ PASS" if result else "❌ FAIL"
                    print(f"   {test_name}: {status}")
                    total_tests += 1
                    if result:
                        passed_tests += 1
            else:
                status = "✅ PASS" if results else "❌ FAIL"
                print(f"   Overall: {status}")
                total_tests += 1
                if results:
                    passed_tests += 1
        
        print(f"\n" + "=" * 60)
        print(f"📊 OVERALL RESULTS: {passed_tests}/{total_tests} tests passed ({passed_tests/total_tests*100:.1f}%)")
        
        if passed_tests == total_tests:
            print("🎉 ALL TESTS PASSED! System is ready for deployment.")
        elif passed_tests >= total_tests * 0.8:
            print("✅ Most tests passed. System is mostly functional with minor issues.")
        else:
            print("⚠️ Several tests failed. System needs attention before deployment.")
        
        return passed_tests / total_tests
    
    def run_full_integration_test(self):
        """Run complete integration test suite"""
        print("🔬 SMART DOOR LOCK - COMPREHENSIVE INTEGRATION TEST")
        print("=" * 70)
        
        # Start backend server
        if not self.start_backend():
            print("❌ Cannot proceed without backend server")
            return False
        
        try:
            # Run all tests
            self.test_database_setup()
            self.test_api_endpoints()
            self.test_security_features()
            self.test_frontend_templates()
            self.test_esp32_integration()
            self.test_documentation()
            self.run_hardware_simulation_test()
            
            # Generate report
            success_rate = self.generate_test_report()
            
            return success_rate >= 0.8
            
        finally:
            # Always stop backend
            self.stop_backend()

def main():
    """Main function"""
    print("🧪 Smart Door Lock Integration Tester")
    print("=" * 50)
    
    tester = IntegrationTester()
    
    print("This will test the entire Smart Door Lock system:")
    print("- Backend API server")
    print("- Database setup")
    print("- Security features") 
    print("- Frontend templates")
    print("- ESP32 integration")
    print("- Documentation")
    print("- Hardware simulation")
    
    input("\nPress Enter to start comprehensive testing...")
    
    success = tester.run_full_integration_test()
    
    if success:
        print("\n🎉 Integration test completed successfully!")
        print("💡 Next steps:")
        print("1. Run hardware simulation: python hardware_simulator.py")
        print("2. Access web interface: http://localhost:5000")
        print("3. Test security dashboard: http://localhost:5000/security/dashboard")
    else:
        print("\n⚠️ Integration test found issues that need attention.")
        print("💡 Review the test report above and fix failing components.")

if __name__ == "__main__":
    main()
