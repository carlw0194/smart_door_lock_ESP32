"""
Anomaly Detection System for Smart Door Lock
Detects suspicious access patterns and security threats
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime, timedelta
import joblib
import os
import logging

class AnomalyDetector:
    def __init__(self, app, db):
        self.app = app
        self.db = db
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.model_path = 'security/models/'
        
        # Ensure model directory exists
        os.makedirs(self.model_path, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Load existing models
        self.load_models()
        
    def extract_features(self, access_logs):
        """Extract features from access logs for ML analysis"""
        if not access_logs:
            return pd.DataFrame()
            
        features = []
        
        for log in access_logs:
            # Time-based features
            timestamp = log.timestamp
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            is_weekend = day_of_week >= 5
            is_business_hours = 8 <= hour <= 18
            
            # Access pattern features
            user_id = log.user_id if log.user_id else -1
            access_method = log.access_method
            access_granted = log.access_granted
            
            # Calculate user's access frequency (last 7 days)
            week_ago = timestamp - timedelta(days=7)
            user_recent_access = 0
            if log.user_id:
                from app import AccessLog
                user_recent_access = AccessLog.query.filter(
                    AccessLog.user_id == log.user_id,
                    AccessLog.timestamp >= week_ago,
                    AccessLog.timestamp < timestamp
                ).count()
            
            # Failed attempts in last hour for this user/method
            hour_ago = timestamp - timedelta(hours=1)
            recent_failures = 0
            if log.user_id:
                from app import AccessLog
                recent_failures = AccessLog.query.filter(
                    AccessLog.user_id == log.user_id,
                    AccessLog.access_granted == False,
                    AccessLog.timestamp >= hour_ago,
                    AccessLog.timestamp < timestamp
                ).count()
            
            feature_row = {
                'hour': hour,
                'day_of_week': day_of_week,
                'is_weekend': int(is_weekend),
                'is_business_hours': int(is_business_hours),
                'user_id': user_id,
                'access_method': access_method,
                'access_granted': int(access_granted),
                'user_recent_access': user_recent_access,
                'recent_failures': recent_failures,
                'timestamp': timestamp
            }
            
            features.append(feature_row)
            
        return pd.DataFrame(features)
    
    def prepare_data(self, df):
        """Prepare data for ML training"""
        if df.empty:
            return None, None
            
        # Encode categorical variables
        if 'access_method' not in self.encoders:
            self.encoders['access_method'] = LabelEncoder()
            df['access_method_encoded'] = self.encoders['access_method'].fit_transform(df['access_method'])
        else:
            df['access_method_encoded'] = self.encoders['access_method'].transform(df['access_method'])
        
        # Select features for training
        feature_columns = [
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours',
            'user_id', 'access_method_encoded', 'user_recent_access', 'recent_failures'
        ]
        
        X = df[feature_columns]
        y = df['access_granted']  # 1 for normal, 0 for anomaly (denied access)
        
        # Scale features
        if 'main' not in self.scalers:
            self.scalers['main'] = StandardScaler()
            X_scaled = self.scalers['main'].fit_transform(X)
        else:
            X_scaled = self.scalers['main'].transform(X)
            
        return X_scaled, y
    
    def train_anomaly_detection_model(self, contamination=0.1):
        """Train isolation forest for anomaly detection"""
        try:
            # Get access logs from database
            from app import AccessLog
            
            # Get last 30 days of data
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            logs = AccessLog.query.filter(AccessLog.timestamp >= thirty_days_ago).all()
            
            if len(logs) < 50:  # Need minimum data
                self.logger.warning("Insufficient data for training anomaly detection model")
                return False
                
            # Extract features
            df = self.extract_features(logs)
            X, y = self.prepare_data(df)
            
            if X is None:
                return False
                
            # Train Isolation Forest
            self.models['isolation_forest'] = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            
            self.models['isolation_forest'].fit(X)
            
            # Train Random Forest for classification
            if len(np.unique(y)) > 1:  # Need both classes
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42, stratify=y
                )
                
                self.models['random_forest'] = RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                    class_weight='balanced'
                )
                
                self.models['random_forest'].fit(X_train, y_train)
                
                # Evaluate model
                y_pred = self.models['random_forest'].predict(X_test)
                self.logger.info("Random Forest Classification Report:")
                self.logger.info(classification_report(y_test, y_pred))
            
            # Save models
            self.save_models()
            self.logger.info("Anomaly detection models trained successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error training anomaly detection model: {e}")
            return False
    
    def detect_anomaly(self, access_log):
        """Detect if an access attempt is anomalous"""
        try:
            if 'isolation_forest' not in self.models:
                return False, 0.0, "No trained model available"
                
            # Extract features for this log entry
            df = self.extract_features([access_log])
            X, _ = self.prepare_data(df)
            
            if X is None:
                return False, 0.0, "Unable to extract features"
                
            # Predict using Isolation Forest
            anomaly_score = self.models['isolation_forest'].decision_function(X)[0]
            is_anomaly = self.models['isolation_forest'].predict(X)[0] == -1
            
            # Get probability from Random Forest if available
            probability = 0.0
            if 'random_forest' in self.models:
                prob = self.models['random_forest'].predict_proba(X)[0]
                probability = prob[1] if len(prob) > 1 else prob[0]
            
            reason = self._get_anomaly_reason(access_log, df.iloc[0] if not df.empty else None)
            
            return is_anomaly, float(anomaly_score), reason
            
        except Exception as e:
            self.logger.error(f"Error detecting anomaly: {e}")
            return False, 0.0, "Error in anomaly detection"
    
    def _get_anomaly_reason(self, access_log, features):
        """Determine the reason for anomaly detection"""
        reasons = []
        
        if features is None:
            return "Unknown reason"
            
        # Check for unusual timing
        if not features['is_business_hours'] and features['is_weekend']:
            reasons.append("Access attempt outside business hours on weekend")
            
        # Check for repeated failures
        if features['recent_failures'] > 3:
            reasons.append(f"Multiple recent failed attempts ({features['recent_failures']})")
            
        # Check for unusual user activity
        if features['user_recent_access'] == 0:
            reasons.append("First access attempt by this user in past week")
        elif features['user_recent_access'] > 20:
            reasons.append("Unusually high access frequency")
            
        # Check for late night access
        if features['hour'] < 6 or features['hour'] > 22:
            reasons.append("Access attempt during unusual hours")
            
        return "; ".join(reasons) if reasons else "Statistical anomaly detected"
    
    def analyze_user_behavior(self, user_id, days=30):
        """Analyze behavior patterns for a specific user"""
        try:
            from app import AccessLog, User
            
            user = User.query.get(user_id)
            if not user:
                return None
                
            # Get user's access logs
            since_date = datetime.utcnow() - timedelta(days=days)
            logs = AccessLog.query.filter(
                AccessLog.user_id == user_id,
                AccessLog.timestamp >= since_date
            ).all()
            
            if not logs:
                return {
                    'user_name': user.name,
                    'total_attempts': 0,
                    'success_rate': 0,
                    'common_hours': [],
                    'common_days': [],
                    'anomalies_detected': 0
                }
            
            df = self.extract_features(logs)
            
            # Calculate statistics
            total_attempts = len(logs)
            successful_attempts = sum(1 for log in logs if log.access_granted)
            success_rate = (successful_attempts / total_attempts) * 100
            
            # Find common access patterns
            common_hours = df['hour'].mode().tolist()
            common_days = df['day_of_week'].mode().tolist()
            
            # Count anomalies
            anomalies = 0
            for log in logs:
                is_anomaly, _, _ = self.detect_anomaly(log)
                if is_anomaly:
                    anomalies += 1
            
            return {
                'user_name': user.name,
                'total_attempts': total_attempts,
                'success_rate': round(success_rate, 2),
                'common_hours': common_hours,
                'common_days': common_days,
                'anomalies_detected': anomalies,
                'anomaly_rate': round((anomalies / total_attempts) * 100, 2) if total_attempts > 0 else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing user behavior: {e}")
            return None
    
    def get_security_insights(self):
        """Generate security insights from access patterns"""
        try:
            from app import AccessLog, User
            
            # Get recent data (last 7 days)
            week_ago = datetime.utcnow() - timedelta(days=7)
            recent_logs = AccessLog.query.filter(AccessLog.timestamp >= week_ago).all()
            
            insights = {
                'total_access_attempts': len(recent_logs),
                'failed_attempts': sum(1 for log in recent_logs if not log.access_granted),
                'anomalies_detected': 0,
                'peak_hours': [],
                'most_active_users': [],
                'security_alerts': []
            }
            
            if not recent_logs:
                return insights
                
            # Extract features and detect anomalies
            df = self.extract_features(recent_logs)
            anomaly_count = 0
            
            for log in recent_logs:
                is_anomaly, score, reason = self.detect_anomaly(log)
                if is_anomaly:
                    anomaly_count += 1
                    if score < -0.5:  # High confidence anomaly
                        insights['security_alerts'].append({
                            'timestamp': log.timestamp.isoformat(),
                            'user_id': log.user_id,
                            'reason': reason,
                            'confidence': abs(score)
                        })
            
            insights['anomalies_detected'] = anomaly_count
            
            # Find peak hours
            if not df.empty:
                hour_counts = df['hour'].value_counts()
                insights['peak_hours'] = hour_counts.head(3).index.tolist()
            
            # Find most active users
            user_activity = {}
            for log in recent_logs:
                if log.user_id:
                    user_activity[log.user_id] = user_activity.get(log.user_id, 0) + 1
            
            most_active = sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:5]
            for user_id, count in most_active:
                user = User.query.get(user_id)
                if user:
                    insights['most_active_users'].append({
                        'name': user.name,
                        'attempts': count
                    })
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Error generating security insights: {e}")
            return {}
    
    def save_models(self):
        """Save trained models to disk"""
        try:
            for name, model in self.models.items():
                joblib.dump(model, os.path.join(self.model_path, f'{name}_model.pkl'))
                
            for name, scaler in self.scalers.items():
                joblib.dump(scaler, os.path.join(self.model_path, f'{name}_scaler.pkl'))
                
            for name, encoder in self.encoders.items():
                joblib.dump(encoder, os.path.join(self.model_path, f'{name}_encoder.pkl'))
                
            self.logger.info("Models saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            # Load models
            for model_file in os.listdir(self.model_path):
                if model_file.endswith('_model.pkl'):
                    name = model_file.replace('_model.pkl', '')
                    self.models[name] = joblib.load(os.path.join(self.model_path, model_file))
                    
            # Load scalers
            for scaler_file in os.listdir(self.model_path):
                if scaler_file.endswith('_scaler.pkl'):
                    name = scaler_file.replace('_scaler.pkl', '')
                    self.scalers[name] = joblib.load(os.path.join(self.model_path, scaler_file))
                    
            # Load encoders
            for encoder_file in os.listdir(self.model_path):
                if encoder_file.endswith('_encoder.pkl'):
                    name = encoder_file.replace('_encoder.pkl', '')
                    self.encoders[name] = joblib.load(os.path.join(self.model_path, encoder_file))
                    
            if self.models:
                self.logger.info(f"Loaded {len(self.models)} models")
        except Exception as e:
            self.logger.info(f"No existing models found or error loading: {e}")
    
    def retrain_models(self):
        """Retrain models with latest data"""
        self.logger.info("Retraining anomaly detection models...")
        success = self.train_anomaly_detection_model()
        return success
