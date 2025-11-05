from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import secrets
import json
import jwt
import hashlib
import hmac
import os
from dotenv import load_dotenv
import ssl
from mqtt_handler import MQTTHandler
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'security'))
from anomaly_detection import AnomalyDetector

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///door_access.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['API_SECRET_KEY'] = os.getenv('API_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))

# Security Headers with Talisman
talisman = Talisman(
    app,
    force_https=False,  # Set to True in production
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        'style-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        'font-src': "'self' https://cdnjs.cloudflare.com",
        'img-src': "'self' data:",
    }
)

# Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[os.getenv('RATELIMIT_DEFAULT', '100 per hour')],
    storage_uri=os.getenv('RATELIMIT_STORAGE_URL', 'memory://')
)
limiter.init_app(app)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize MQTT Handler and Anomaly Detector
mqtt_handler = None
anomaly_detector = None

# Database Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(255), unique=True, nullable=False)
    device_name = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, nullable=True)

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)  # failed_login, api_abuse, etc.
    ip_address = db.Column(db.String(15), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    employee_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    rfid_uid = db.Column(db.String(50), unique=True, nullable=True)
    fingerprint_id = db.Column(db.Integer, unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    access_level = db.Column(db.String(20), default='basic')  # basic, admin, guest
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_access = db.Column(db.DateTime, nullable=True)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    access_method = db.Column(db.String(20), nullable=False)  # rfid, fingerprint
    access_granted = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    door_state = db.Column(db.String(10), default='closed')  # open, closed
    rfid_uid = db.Column(db.String(50), nullable=True)
    fingerprint_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(15), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# Security Helper Functions
def generate_api_key():
    """Generate a secure API key"""
    return secrets.token_urlsafe(32)

def hash_api_key(api_key):
    """Hash an API key for storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()

def verify_api_key(provided_key):
    """Verify an API key against stored hashes"""
    if not provided_key:
        return None
    
    key_hash = hash_api_key(provided_key)
    api_key = APIKey.query.filter_by(key_hash=key_hash, is_active=True).first()
    
    if api_key:
        api_key.last_used = datetime.utcnow()
        db.session.commit()
        return api_key
    return None

def log_security_event(event_type, details=None):
    """Log security events"""
    event = SecurityEvent(
        event_type=event_type,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=details
    )
    db.session.add(event)
    db.session.commit()

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            log_security_event('api_access_denied', 'Missing API key')
            return jsonify({'error': 'API key required'}), 401
        
        api_key_obj = verify_api_key(api_key)
        if not api_key_obj:
            log_security_event('api_access_denied', f'Invalid API key: {api_key[:8]}...')
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Add API key info to request context
        request.api_key = api_key_obj
        return f(*args, **kwargs)
    
    return decorated_function

def validate_input(data, required_fields):
    """Validate input data"""
    if not data:
        return False, "No data provided"
    
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing required field: {field}"
    
    return True, "Valid"

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required')
            log_security_event('failed_login', f'Empty credentials for username: {username}')
            return render_template('login.html')
        
        admin = Admin.query.filter_by(username=username).first()
        
        # Check if account is locked
        if admin and admin.locked_until and admin.locked_until > datetime.utcnow():
            flash('Account is temporarily locked due to too many failed attempts')
            log_security_event('account_locked', f'Login attempt on locked account: {username}')
            return render_template('login.html')
        
        if admin and check_password_hash(admin.password_hash, password):
            # Reset failed attempts on successful login
            admin.failed_login_attempts = 0
            admin.locked_until = None
            db.session.commit()
            
            login_user(admin)
            log_security_event('successful_login', f'User: {username}')
            return redirect(url_for('dashboard'))
        else:
            # Handle failed login
            if admin:
                admin.failed_login_attempts += 1
                if admin.failed_login_attempts >= 5:
                    admin.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash('Account locked for 15 minutes due to too many failed attempts')
                else:
                    flash(f'Invalid credentials. {5 - admin.failed_login_attempts} attempts remaining.')
                db.session.commit()
            else:
                flash('Invalid username or password')
            
            log_security_event('failed_login', f'Failed login for username: {username}')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(10).all()
    
    # Get access statistics
    today_access = AccessLog.query.filter(
        AccessLog.timestamp >= datetime.now().replace(hour=0, minute=0, second=0)
    ).count()
    
    granted_access = AccessLog.query.filter_by(access_granted=True).count()
    denied_access = AccessLog.query.filter_by(access_granted=False).count()
    
    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'today_access': today_access,
        'granted_access': granted_access,
        'denied_access': denied_access
    }
    
    return render_template('dashboard.html', stats=stats, recent_logs=recent_logs)

@app.route('/users')
@login_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=all_users)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        name = request.form['name']
        employee_id = request.form['employee_id']
        email = request.form['email']
        access_level = request.form['access_level']
        
        # Check if employee_id already exists
        existing_user = User.query.filter_by(employee_id=employee_id).first()
        if existing_user:
            flash('Employee ID already exists')
            return render_template('add_user.html')
        
        new_user = User(
            name=name,
            employee_id=employee_id,
            email=email,
            access_level=access_level
        )
        
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully')
        return redirect(url_for('users'))
    
    return render_template('add_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        user.access_level = request.form['access_level']
        user.is_active = 'is_active' in request.form
        
        db.session.commit()
        flash('User updated successfully')
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully')
    return redirect(url_for('users'))

@app.route('/access_logs')
@login_required
def access_logs():
    page = request.args.get('page', 1, type=int)
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template('access_logs.html', logs=logs)

# API Endpoints for ESP32
@app.route('/api/check_access', methods=['POST'])
@limiter.limit("60 per minute")
@require_api_key
def check_access():
    """API endpoint for ESP32 to check if access should be granted"""
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['method']
        is_valid, error_msg = validate_input(data, required_fields)
        if not is_valid:
            log_security_event('api_validation_error', error_msg)
            return jsonify({'error': error_msg}), 400
        
        access_method = data.get('method')  # 'rfid' or 'fingerprint'
        rfid_uid = data.get('rfid_uid')
        fingerprint_id = data.get('fingerprint_id')
        
        # Validate method-specific requirements
        if access_method == 'rfid' and not rfid_uid:
            return jsonify({'error': 'RFID UID required for RFID method'}), 400
        elif access_method == 'fingerprint' and not fingerprint_id:
            return jsonify({'error': 'Fingerprint ID required for fingerprint method'}), 400
        
        # Find the user record even if the account is inactive so we can record last_access for audit
        user = None
        user_any = None
        access_granted = False

        if access_method == 'rfid' and rfid_uid:
            user_any = User.query.filter_by(rfid_uid=rfid_uid).first()
            # Only grant access if user exists and is active
            user = user_any if (user_any and user_any.is_active) else None
        elif access_method == 'fingerprint' and fingerprint_id:
            user_any = User.query.filter_by(fingerprint_id=fingerprint_id).first()
            user = user_any if (user_any and user_any.is_active) else None

        # Update last_access for the user record if it exists (audit every attempt)
        if user_any:
            try:
                user_any.last_access = datetime.utcnow()
                db.session.commit()
            except Exception:
                db.session.rollback()

        if user:
            access_granted = True
        
        # Log the access attempt (use the actual user record if present even when inactive)
        log_entry = AccessLog(
            user_id=user_any.id if user_any else None,
            access_method=access_method,
            access_granted=access_granted,
            rfid_uid=rfid_uid,
            fingerprint_id=fingerprint_id,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Check for anomalies using ML
        if anomaly_detector and log_entry:
            is_anomaly, anomaly_score, reason = anomaly_detector.detect_anomaly(log_entry)
            if is_anomaly:
                log_security_event('ml_anomaly_detected', f'Score: {anomaly_score}, Reason: {reason}')
                # Send alert via MQTT if available
                if mqtt_handler:
                    mqtt_handler.send_alert('anomaly', f'Suspicious access detected: {reason}', 'high')
        
        # Log security event for denied access
        if not access_granted:
            log_security_event('access_denied', f'Method: {access_method}, RFID: {rfid_uid}, FP: {fingerprint_id}')
        
        response = {
            'access_granted': access_granted,
            'user_name': (user.name if user else (user_any.name if user_any else None)),
            'user_id': (user.id if user else (user_any.id if user_any else None)),
            'message': 'Access granted' if access_granted else 'Access denied',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(response)
        
    except Exception as e:
        log_security_event('api_error', f'Check access error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/register_rfid', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def register_rfid():
    """API endpoint to register RFID card to user"""
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['user_id', 'rfid_uid']
        is_valid, error_msg = validate_input(data, required_fields)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        user_id = data.get('user_id')
        rfid_uid = data.get('rfid_uid')
        
        user = User.query.get(user_id)
        if not user:
            log_security_event('rfid_registration_failed', f'User not found: {user_id}')
            return jsonify({'error': 'User not found'}), 404
        
        # Check if RFID is already registered
        existing = User.query.filter_by(rfid_uid=rfid_uid).first()
        if existing and existing.id != user_id:
            log_security_event('rfid_registration_failed', f'RFID already registered: {rfid_uid}')
            return jsonify({'error': 'RFID already registered to another user'}), 400
        
        user.rfid_uid = rfid_uid
        db.session.commit()
        
        log_security_event('rfid_registered', f'User: {user.name}, RFID: {rfid_uid}')
        return jsonify({'message': 'RFID registered successfully'})
        
    except Exception as e:
        log_security_event('api_error', f'RFID registration error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/register_fingerprint', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def register_fingerprint():
    """API endpoint to register fingerprint to user"""
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['user_id', 'fingerprint_id']
        is_valid, error_msg = validate_input(data, required_fields)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        user_id = data.get('user_id')
        fingerprint_id = data.get('fingerprint_id')
        
        user = User.query.get(user_id)
        if not user:
            log_security_event('fingerprint_registration_failed', f'User not found: {user_id}')
            return jsonify({'error': 'User not found'}), 404
        
        # Check if fingerprint is already registered
        existing = User.query.filter_by(fingerprint_id=fingerprint_id).first()
        if existing and existing.id != user_id:
            log_security_event('fingerprint_registration_failed', f'Fingerprint already registered: {fingerprint_id}')
            return jsonify({'error': 'Fingerprint already registered to another user'}), 400
        
        user.fingerprint_id = fingerprint_id
        db.session.commit()
        
        log_security_event('fingerprint_registered', f'User: {user.name}, FP ID: {fingerprint_id}')
        return jsonify({'message': 'Fingerprint registered successfully'})
        
    except Exception as e:
        log_security_event('api_error', f'Fingerprint registration error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500


# Simple registration state used to coordinate UI -> ESP32 registration flow
# UI (admin) triggers /api/start_registration (login_required). The ESP32 polls
# /api/poll_registration (require_api_key) to know when to enter registration mode.
registration_state = {
    'register': False,
    'user_id': None
}


@app.route('/api/start_registration', methods=['POST'])
def start_registration():
    try:
        # Allow start_registration to be triggered either by a logged-in admin OR by a valid API key
        authorized = False
        if current_user and getattr(current_user, 'is_authenticated', False):
            authorized = True
            actor = f'admin:{current_user.username}' if getattr(current_user, 'username', None) else 'admin'
        else:
            api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            if api_key and verify_api_key(api_key):
                authorized = True
                actor = f'api_key:{api_key[:8]}...'

        if not authorized:
            log_security_event('api_access_denied', 'Unauthorized start_registration attempt')
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json() or {}
        user_id = data.get('user_id') or request.form.get('user_id')
        if not user_id:
            return jsonify({'error': 'user_id required'}), 400

        # set the registration state
        registration_state['register'] = True
        registration_state['user_id'] = int(user_id)
        log_security_event('registration_started', f'User: {user_id} by {actor}')
        return jsonify({'message': 'Registration started', 'user_id': int(user_id)})
    except Exception as e:
        log_security_event('api_error', f'start_registration error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/poll_registration', methods=['GET'])
@require_api_key
def poll_registration():
    """Polled by the ESP32 to learn if it should enter registration mode."""
    try:
        # Return the current registration state (do not clear here; ESP32 will call clear when done)
        return jsonify({
            'register': bool(registration_state.get('register')),
            'user_id': int(registration_state.get('user_id')) if registration_state.get('user_id') else None
        })
    except Exception as e:
        log_security_event('api_error', f'poll_registration error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/clear_registration', methods=['POST'])
@require_api_key
def clear_registration():
    """Called by ESP32 to clear registration state after handling enrollment."""
    try:
        registration_state['register'] = False
        registration_state['user_id'] = None
        return jsonify({'message': 'Registration cleared'})
    except Exception as e:
        log_security_event('api_error', f'clear_registration error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/door_state', methods=['POST'])
@limiter.limit("100 per minute")
@require_api_key
def update_door_state():
    """API endpoint for ESP32 to report door state"""
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['state']
        is_valid, error_msg = validate_input(data, required_fields)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        door_state = data.get('state')  # 'open' or 'closed'
        
        if door_state not in ['open', 'closed']:
            return jsonify({'error': 'Invalid door state. Must be "open" or "closed"'}), 400
        
        # Log door state change
        log_security_event('door_state_change', f'State: {door_state}')
        
        # You can add logic here to update door state in database
        # or trigger alerts if door is left open too long
        
        return jsonify({'message': 'Door state updated', 'state': door_state})
        
    except Exception as e:
        log_security_event('api_error', f'Door state update error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users')
@limiter.limit("30 per minute")
@require_api_key
def api_users():
    """API endpoint to get all users (for ESP32 sync if needed)"""
    try:
        users = User.query.filter_by(is_active=True).all()
        users_data = []
        
        for user in users:
            users_data.append({
                'id': user.id,
                'name': user.name,
                'employee_id': user.employee_id,
                'rfid_uid': user.rfid_uid,
                'fingerprint_id': user.fingerprint_id,
                'access_level': user.access_level
            })
        
        return jsonify(users_data)
        
    except Exception as e:
        log_security_event('api_error', f'Users API error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

# API Key Management Routes
@app.route('/api_keys')
@login_required
def manage_api_keys():
    """Manage API keys for ESP32 devices"""
    api_keys = APIKey.query.order_by(APIKey.created_at.desc()).all()
    return render_template('api_keys.html', api_keys=api_keys)

@app.route('/api_keys/create', methods=['POST'])
@login_required
def create_api_key():
    """Create a new API key"""
    device_name = request.form.get('device_name', '').strip()
    
    if not device_name:
        flash('Device name is required')
        return redirect(url_for('manage_api_keys'))
    
    # Generate new API key
    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)
    
    new_key = APIKey(
        key_hash=key_hash,
        device_name=device_name
    )
    
    db.session.add(new_key)
    db.session.commit()
    
    # Show the API key only once
    flash(f'API Key created for {device_name}: {api_key}', 'success')
    log_security_event('api_key_created', f'Device: {device_name}')
    
    return redirect(url_for('manage_api_keys'))

@app.route('/api_keys/revoke/<int:key_id>')
@login_required
def revoke_api_key(key_id):
    """Revoke an API key"""
    api_key = APIKey.query.get_or_404(key_id)
    api_key.is_active = False
    db.session.commit()
    
    flash(f'API key for {api_key.device_name} has been revoked')
    log_security_event('api_key_revoked', f'Device: {api_key.device_name}')
    
    return redirect(url_for('manage_api_keys'))

# Security Events View
@app.route('/security_events')
@login_required
def security_events():
    """View security events"""
    page = request.args.get('page', 1, type=int)
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template('security_events.html', events=events)

# ML and Analytics Routes
@app.route('/analytics')
@login_required
def analytics():
    """View ML analytics and insights"""
    insights = {}
    user_analysis = []
    
    if anomaly_detector:
        insights = anomaly_detector.get_security_insights()
        
        # Get analysis for top 5 most active users
        recent_users = db.session.query(AccessLog.user_id).filter(
            AccessLog.user_id.isnot(None),
            AccessLog.timestamp >= datetime.utcnow() - timedelta(days=7)
        ).distinct().limit(5).all()
        
        for (user_id,) in recent_users:
            analysis = anomaly_detector.analyze_user_behavior(user_id)
            if analysis:
                user_analysis.append(analysis)
    
    return render_template('analytics.html', insights=insights, user_analysis=user_analysis)

@app.route('/ml/train', methods=['POST'])
@login_required
def train_ml_models():
    """Manually trigger ML model training"""
    if not anomaly_detector:
        flash('Anomaly detector not initialized', 'error')
        return redirect(url_for('analytics'))
    
    success = anomaly_detector.retrain_models()
    if success:
        flash('ML models trained successfully', 'success')
    else:
        flash('Failed to train ML models - insufficient data', 'warning')
    
    return redirect(url_for('analytics'))

@app.route('/api/analytics/insights')
@limiter.limit("10 per minute")
@require_api_key
def api_analytics_insights():
    """API endpoint to get security insights"""
    try:
        if not anomaly_detector:
            return jsonify({'error': 'Anomaly detector not available'}), 503
            
        insights = anomaly_detector.get_security_insights()
        return jsonify(insights)
        
    except Exception as e:
        log_security_event('api_error', f'Analytics API error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

def create_admin():
    """Create default admin user if none exists"""
    if not Admin.query.first():
        admin = Admin(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            email='admin@dooraccess.com'
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin created - Username: admin, Password: admin123")
        print("WARNING: Please change the default password immediately!")

def create_default_api_key():
    """Create a default API key for development"""
    if not APIKey.query.first():
        api_key = generate_api_key()
        key_hash = hash_api_key(api_key)
        
        default_key = APIKey(
            key_hash=key_hash,
            device_name='ESP32-Development'
        )
        db.session.add(default_key)
        db.session.commit()
        print(f"Default API key created for ESP32: {api_key}")
        print("WARNING: This is for development only!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
        create_default_api_key()
        
        # Initialize and start MQTT handler
        mqtt_handler = MQTTHandler(app, db)
        mqtt_handler.run_in_background()
        
        # Initialize anomaly detector
        try:
            anomaly_detector = AnomalyDetector(app, db)
            print("Anomaly detector initialized")
        except Exception as e:
            print(f"Warning: Could not initialize anomaly detector: {e}")
            anomaly_detector = None
    
    # SSL Configuration for production
    ssl_context = None
    if os.getenv('FLASK_ENV') == 'production':
        cert_path = os.getenv('SSL_CERT_PATH')
        key_path = os.getenv('SSL_KEY_PATH')
        if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            ssl_context.load_cert_chain(cert_path, key_path)
            print("HTTPS enabled")
        else:
            print("WARNING: SSL certificates not found, running on HTTP")
    
    debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
    app.run(
        debug=debug_mode, 
        host='0.0.0.0', 
        port=5000,
        ssl_context=ssl_context
    )