#!/usr/bin/env python3
"""
Enhanced Security Integration Module
Integrates security features with backend and frontend for real-time display
"""

from flask import jsonify, render_template, request
from datetime import datetime, timedelta
import json
import sys
import os

# Add security module to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'security'))

class SecurityIntegration:
    """Enhanced security integration for backend-frontend communication"""
    
    def __init__(self, app, db, anomaly_detector):
        self.app = app
        self.db = db
        self.anomaly_detector = anomaly_detector
        
    def get_real_time_security_status(self):
        """Get real-time security status for dashboard"""
        try:
            # Import models from app context
            from app import AccessLog, SecurityEvent, User
            
            # Get recent access logs (last 24 hours)
            recent_logs = AccessLog.query.filter(
                AccessLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).order_by(AccessLog.timestamp.desc()).all()
            
            # Get security events (last 7 days)
            security_events = SecurityEvent.query.filter(
                SecurityEvent.timestamp >= datetime.utcnow() - timedelta(days=7)
            ).order_by(SecurityEvent.timestamp.desc()).limit(50).all()
            
            # Analyze anomalies if detector is available
            anomalies = []
            security_score = 100
            
            if self.anomaly_detector and recent_logs:
                try:
                    # Extract features and detect anomalies
                    features = self.anomaly_detector.extract_features(recent_logs)
                    if not features.empty:
                        detected_anomalies = self.anomaly_detector.detect_anomalies(features)
                        
                        # Convert anomalies to display format
                        for idx, anomaly in detected_anomalies.iterrows():
                            anomaly_data = {
                                'id': idx,
                                'timestamp': anomaly.get('timestamp', datetime.utcnow()).strftime('%Y-%m-%d %H:%M:%S'),
                                'user_id': anomaly.get('user_id', 'Unknown'),
                                'method': anomaly.get('method', 'Unknown'),
                                'success': anomaly.get('success', False),
                                'duration': round(anomaly.get('duration', 0), 2),
                                'risk_level': self._calculate_risk_level(anomaly),
                                'description': self._generate_anomaly_description(anomaly)
                            }
                            anomalies.append(anomaly_data)
                        
                        # Calculate security score based on anomalies
                        security_score = max(50, 100 - (len(anomalies) * 10))
                        
                except Exception as e:
                    print(f"Error in anomaly detection: {e}")
            
            # Calculate statistics
            total_access = len(recent_logs)
            failed_access = len([log for log in recent_logs if not log.access_granted])
            success_rate = ((total_access - failed_access) / total_access * 100) if total_access > 0 else 100
            
            # Get active users (accessed in last 7 days)
            active_users = User.query.filter(
                User.last_access >= datetime.utcnow() - timedelta(days=7)
            ).count()
            
            return {
                'security_score': security_score,
                'total_access_24h': total_access,
                'failed_access_24h': failed_access,
                'success_rate': round(success_rate, 1),
                'active_users': active_users,
                'anomalies': anomalies,
                'security_events_count': len(security_events),
                'last_updated': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            print(f"Error getting security status: {e}")
            return {
                'security_score': 0,
                'total_access_24h': 0,
                'failed_access_24h': 0,
                'success_rate': 0,
                'active_users': 0,
                'anomalies': [],
                'security_events_count': 0,
                'last_updated': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'error': str(e)
            }
    
    def get_detailed_anomalies(self, limit=50):
        """Get detailed anomaly information for security dashboard"""
        try:
            from app import AccessLog
            
            # Get recent access logs
            recent_logs = AccessLog.query.filter(
                AccessLog.timestamp >= datetime.utcnow() - timedelta(days=7)
            ).order_by(AccessLog.timestamp.desc()).all()
            
            if not self.anomaly_detector or not recent_logs:
                return []
            
            # Extract features and detect anomalies
            features = self.anomaly_detector.extract_features(recent_logs)
            if features.empty:
                return []
            
            detected_anomalies = self.anomaly_detector.detect_anomalies(features)
            
            detailed_anomalies = []
            for idx, anomaly in detected_anomalies.head(limit).iterrows():
                # Get associated user info
                user_info = "Unknown User"
                if anomaly.get('user_id'):
                    from app import User
                    user = User.query.get(anomaly['user_id'])
                    if user:
                        user_info = f"{user.name} ({user.employee_id})"
                
                anomaly_detail = {
                    'id': idx,
                    'timestamp': anomaly.get('timestamp', datetime.utcnow()),
                    'user_info': user_info,
                    'user_id': anomaly.get('user_id', 'Unknown'),
                    'method': anomaly.get('method', 'Unknown'),
                    'success': anomaly.get('success', False),
                    'duration': round(anomaly.get('duration', 0), 2),
                    'location': anomaly.get('location', 'Unknown'),
                    'risk_level': self._calculate_risk_level(anomaly),
                    'risk_score': self._calculate_risk_score(anomaly),
                    'description': self._generate_anomaly_description(anomaly),
                    'recommendations': self._generate_recommendations(anomaly)
                }
                detailed_anomalies.append(anomaly_detail)
            
            return detailed_anomalies
            
        except Exception as e:
            print(f"Error getting detailed anomalies: {e}")
            return []
    
    def get_security_trends(self, days=30):
        """Get security trends for analytics dashboard"""
        try:
            from app import AccessLog, SecurityEvent
            
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Daily access trends
            daily_access = {}
            logs = AccessLog.query.filter(
                AccessLog.timestamp >= start_date
            ).all()
            
            for log in logs:
                date_key = log.timestamp.strftime('%Y-%m-%d')
                if date_key not in daily_access:
                    daily_access[date_key] = {'total': 0, 'failed': 0, 'success': 0}
                
                daily_access[date_key]['total'] += 1
                if log.access_granted:
                    daily_access[date_key]['success'] += 1
                else:
                    daily_access[date_key]['failed'] += 1
            
            # Security events trends
            security_events = SecurityEvent.query.filter(
                SecurityEvent.timestamp >= start_date
            ).all()
            
            event_trends = {}
            for event in security_events:
                date_key = event.timestamp.strftime('%Y-%m-%d')
                event_type = event.event_type
                
                if date_key not in event_trends:
                    event_trends[date_key] = {}
                if event_type not in event_trends[date_key]:
                    event_trends[date_key][event_type] = 0
                
                event_trends[date_key][event_type] += 1
            
            return {
                'daily_access': daily_access,
                'security_events': event_trends,
                'period': f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
            }
            
        except Exception as e:
            print(f"Error getting security trends: {e}")
            return {'daily_access': {}, 'security_events': {}, 'error': str(e)}
    
    def _calculate_risk_level(self, anomaly):
        """Calculate risk level based on anomaly characteristics"""
        risk_score = self._calculate_risk_score(anomaly)
        
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_risk_score(self, anomaly):
        """Calculate numerical risk score (0-100)"""
        score = 0
        
        # Failed access attempts
        if not anomaly.get('success', True):
            score += 30
        
        # Off-hours access
        hour = anomaly.get('hour', 12)
        if hour < 7 or hour > 19:
            score += 25
        
        # Weekend access
        if anomaly.get('is_weekend', False):
            score += 20
        
        # Long duration
        duration = anomaly.get('duration', 0)
        if duration > 10:
            score += 15
        elif duration > 5:
            score += 10
        
        # Unknown user
        if not anomaly.get('user_id') or anomaly.get('user_id', '').startswith('unknown'):
            score += 40
        
        return min(100, score)
    
    def _generate_anomaly_description(self, anomaly):
        """Generate human-readable anomaly description"""
        descriptions = []
        
        if not anomaly.get('success', True):
            descriptions.append("Failed access attempt")
        
        hour = anomaly.get('hour', 12)
        if hour < 7 or hour > 19:
            descriptions.append(f"Off-hours access at {hour}:00")
        
        if anomaly.get('is_weekend', False):
            descriptions.append("Weekend access")
        
        duration = anomaly.get('duration', 0)
        if duration > 10:
            descriptions.append(f"Unusually long duration ({duration:.1f}s)")
        
        if not anomaly.get('user_id') or anomaly.get('user_id', '').startswith('unknown'):
            descriptions.append("Unknown user")
        
        if not descriptions:
            descriptions.append("Unusual access pattern detected")
        
        return "; ".join(descriptions)
    
    def _generate_recommendations(self, anomaly):
        """Generate security recommendations based on anomaly"""
        recommendations = []
        
        if not anomaly.get('success', True):
            recommendations.append("Investigate failed access attempts")
            recommendations.append("Check for potential brute force attacks")
        
        hour = anomaly.get('hour', 12)
        if hour < 7 or hour > 19:
            recommendations.append("Verify authorization for off-hours access")
            recommendations.append("Consider implementing time-based access controls")
        
        if anomaly.get('is_weekend', False):
            recommendations.append("Confirm weekend access authorization")
        
        duration = anomaly.get('duration', 0)
        if duration > 10:
            recommendations.append("Investigate cause of extended access duration")
        
        if not anomaly.get('user_id') or anomaly.get('user_id', '').startswith('unknown'):
            recommendations.append("Identify unknown user immediately")
            recommendations.append("Review access logs for security breach")
        
        if not recommendations:
            recommendations.append("Monitor for continued unusual behavior")
        
        return recommendations

def create_security_routes(app, db, anomaly_detector):
    """Create enhanced security routes for the Flask app"""
    
    security_integration = SecurityIntegration(app, db, anomaly_detector)
    
    @app.route('/api/security/status')
    def api_security_status():
        """API endpoint for real-time security status"""
        status = security_integration.get_real_time_security_status()
        return jsonify(status)
    
    @app.route('/api/security/anomalies')
    def api_security_anomalies():
        """API endpoint for detailed anomalies"""
        limit = request.args.get('limit', 50, type=int)
        anomalies = security_integration.get_detailed_anomalies(limit)
        return jsonify(anomalies)
    
    @app.route('/api/security/trends')
    def api_security_trends():
        """API endpoint for security trends"""
        days = request.args.get('days', 30, type=int)
        trends = security_integration.get_security_trends(days)
        return jsonify(trends)
    
    @app.route('/security/dashboard')
    def security_dashboard():
        """Enhanced security dashboard"""
        status = security_integration.get_real_time_security_status()
        anomalies = security_integration.get_detailed_anomalies(20)
        trends = security_integration.get_security_trends(7)
        
        return render_template('security_dashboard.html', 
                             status=status, 
                             anomalies=anomalies, 
                             trends=trends)
    
    return security_integration
