from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import secrets
import json
from sqlalchemy.sql import func
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///door_access.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Registration state (in-memory, for demo; use DB for production)
registration_state = {'active': False, 'user_id': None}

# Database Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  
    username = db.Column(db.String(80), unique=True, nullable=False)
    employee_id = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    employee_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    rfid_uid = db.Column(db.String(50), unique=True, nullable=True)
    fingerprint_id = db.Column(db.Integer, unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    access_level = db.Column(db.String(20), default='basic')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_access = db.Column(db.DateTime, nullable=True)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    access_method = db.Column(db.String(20), nullable=False)
    access_granted = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    door_state = db.Column(db.String(10), default='closed')
    rfid_uid = db.Column(db.String(50), nullable=True)
    fingerprint_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(15), nullable=True)
    
    # Add relationship to User
    user = db.relationship('User', backref='access_logs')

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

@app.route('/api/start_registration', methods=['POST'])
def start_registration():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON data provided'}), 400
            
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Missing user_id'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
        registration_state['active'] = True
        registration_state['user_id'] = user_id
        
        logger.info(f"Registration started for user {user_id} ({user.name})")
        
        return jsonify({
            'status': 'success', 
            'message': f'Registration started for {user.name}', 
            'user_id': user_id
        })
    except Exception as e:
        logger.error(f"Error in start_registration: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/poll_registration', methods=['GET'])
def poll_registration():
    try:
        if registration_state['active'] and registration_state['user_id']:
            return jsonify({'register': True, 'user_id': registration_state['user_id']})
        return jsonify({'register': False})
    except Exception as e:
        logger.error(f"Error in poll_registration: {str(e)}")
        return jsonify({'register': False})

@app.route('/api/clear_registration', methods=['POST'])
def clear_registration():
    try:
        registration_state['active'] = False
        registration_state['user_id'] = None
        logger.info("Registration state cleared")
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error in clear_registration: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/start_registration/<int:user_id>', methods=['POST'])
@login_required
def start_registration_web(user_id):
    try:
        user = User.query.get_or_404(user_id)
        registration_state['active'] = True
        registration_state['user_id'] = user_id
        flash(f'Registration mode started for {user.name}', 'success')
        logger.info(f"Registration started via web for user {user_id} ({user.name})")
    except Exception as e:
        flash(f'Error starting registration: {str(e)}', 'danger')
        logger.error(f"Error in start_registration_web: {str(e)}")
    
    return redirect(url_for('users'))

# Registration endpoints
@app.route('/api/register_rfid', methods=['POST'])
def register_rfid():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        user_id = data.get('user_id')
        rfid_uid = data.get('rfid_uid')
        
        logger.info(f"RFID registration request - User ID: {user_id}, RFID: {rfid_uid}")
        
        if not user_id or not rfid_uid:
            return jsonify({'error': 'Missing user_id or rfid_uid'}), 400
        
        user = User.query.get(user_id)
        if not user:
            logger.error(f"User {user_id} not found for RFID registration")
            return jsonify({'error': 'User not found'}), 404
        

        existing = User.query.filter_by(rfid_uid=rfid_uid).first()
        if existing and existing.id != user_id:
            logger.warning(f"RFID {rfid_uid} already registered to user {existing.id}")
            return jsonify({'error': f'RFID already registered to {existing.name}'}), 400
        
        # Update user with RFID
        user.rfid_uid = rfid_uid
        db.session.commit()
        
        logger.info(f"RFID {rfid_uid} successfully registered to user {user.name}")
        
        return jsonify({'message': f'RFID registered successfully to {user.name}', 'user_name': user.name})
        
    except Exception as e:
        logger.error(f"Error in register_rfid: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/register_fingerprint', methods=['POST'])
def register_fingerprint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        user_id = data.get('user_id')
        fingerprint_id = data.get('fingerprint_id')
        
        logger.info(f"Fingerprint registration request - User ID: {user_id}, Fingerprint ID: {fingerprint_id}")
        
        if not user_id or fingerprint_id is None:
            return jsonify({'error': 'Missing user_id or fingerprint_id'}), 400
        
        user = User.query.get(user_id)
        if not user:
            logger.error(f"User {user_id} not found for fingerprint registration")
            return jsonify({'error': 'User not found'}), 404
        
        try:
            fingerprint_id = int(fingerprint_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid fingerprint_id format'}), 400
        
        # Check if fingerprint is already registered
        existing = User.query.filter_by(fingerprint_id=fingerprint_id).first()
        if existing and existing.id != user_id:
            logger.warning(f"Fingerprint ID {fingerprint_id} already registered to user {existing.id}")
            return jsonify({'error': f'Fingerprint already registered to {existing.name}'}), 400
        
        # Update user with fingerprint
        user.fingerprint_id = fingerprint_id
        db.session.commit()
        
        logger.info(f"Fingerprint ID {fingerprint_id} successfully registered to user {user.name} (User ID: {user.id})")
        
        return jsonify({'message': f'Fingerprint registered successfully to {user.name}', 'user_name': user.name})
        
    except Exception as e:
        logger.error(f"Error in register_fingerprint: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# FIXED Access control endpoint
@app.route('/api/check_access', methods=['POST'])
def check_access():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'access_granted': False, 'message': 'No data provided'}), 400
            
        method = data.get('method')
        user = None
        access_granted = False
        
        logger.info(f"Access check request: {data}")
        
        if method == 'rfid':
            rfid_uid = data.get('rfid_uid')
            if rfid_uid:
                user = User.query.filter_by(rfid_uid=rfid_uid, is_active=True).first()
                logger.info(f"RFID lookup for {rfid_uid}: {'Found user ' + user.name if user else 'Not found'}")
                
        elif method == 'fingerprint':
            fingerprint_id = data.get('fingerprint_id')
            logger.info(f"Looking for fingerprint_id: {fingerprint_id}")
            
            if fingerprint_id is not None:
                # Convert to integer if it's a string
                try:
                    fingerprint_id = int(fingerprint_id)
                except (ValueError, TypeError):
                    logger.error(f"Could not convert fingerprint_id to int: {fingerprint_id}")
                    return jsonify({'access_granted': False, 'message': 'Invalid fingerprint ID'}), 400
                
                # Find user with this fingerprint ID
                user = User.query.filter_by(fingerprint_id=fingerprint_id, is_active=True).first()
                
                # Debug logging
                if user:
                    logger.info(f"Found user: {user.name} (ID: {user.id}, FP_ID: {user.fingerprint_id})")
                else:
                    # Show what users exist for debugging
                    all_fp_users = User.query.filter(User.fingerprint_id.isnot(None), User.is_active == True).all()
                    logger.warning(f"Fingerprint {fingerprint_id} not found. Available fingerprints: {[(u.name, u.fingerprint_id) for u in all_fp_users]}")
        
        if user:
            access_granted = True
            user.last_access = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Access granted to {user.name} (ID: {user.id}) via {method}")
        else:
            logger.warning(f"Access denied for {method} request: {data}")
        
        # Log the access attempt
        log_entry = AccessLog(
            user_id=user.id if user else None,
            access_method=method,
            access_granted=access_granted,
            rfid_uid=data.get('rfid_uid'),
            fingerprint_id=data.get('fingerprint_id'),
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        response = {
            'access_granted': access_granted,
            'user_name': user.name if user else None,
            'user_id': user.id if user else None,
            'message': f'Welcome, {user.name}!' if access_granted else 'Access denied'
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in check_access: {str(e)}")
        db.session.rollback()
        return jsonify({'access_granted': False, 'error': str(e)}), 500

@app.route('/api/door_state', methods=['POST'])
def update_door_state():
    try:
        data = request.get_json()
        door_state = data.get('state', 'unknown')
        
        log_entry = AccessLog(
            access_method="system",
            access_granted=True,
            door_state=door_state,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info(f"Door state updated to: {door_state}")
        return jsonify({'message': 'Door state updated', 'state': door_state})
        
    except Exception as e:
        logger.error(f"Error updating door state: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users')
def api_users():
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
        logger.error(f"Error in api_users: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Debug route - temporary for troubleshooting
@app.route('/debug/users')
def debug_users():
    try:
        users = User.query.all()
        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'name': user.name,
                'employee_id': user.employee_id,
                'rfid_uid': user.rfid_uid,
                'fingerprint_id': user.fingerprint_id,
                'fingerprint_id_type': type(user.fingerprint_id).__name__,
                'is_active': user.is_active
            })
        return jsonify(user_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Web Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        employee_id = request.form['employee_id']
        password = request.form['password']
        
        if not username or not employee_id or not password:
            flash("All fields are required!", 'danger')
            return redirect(url_for('login'))
        
        admin = Admin.query.filter_by(username=username, employee_id=employee_id).first()
        
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Credentials. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        employee_id = request.form.get('employee_id', '').strip()
        email = request.form.get('email', '').strip()

        if not username or not password or not confirm_password or not employee_id or not email:
            flash("All fields are required!", 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match!", 'danger')
            return redirect(url_for('signup'))

        if Admin.query.filter_by(username=username).first():
            flash("Username already taken!", 'danger')
            return redirect(url_for('signup'))

        if Admin.query.filter_by(employee_id=employee_id).first():
            flash("Employee ID already exists!", 'danger')
            return redirect(url_for('signup'))

        if Admin.query.filter_by(email=email).first():
            flash("Email already in use!", 'danger')
            return redirect(url_for('signup'))

        new_admin = Admin(
            username=username,
            employee_id=employee_id,
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256')
        )
        db.session.add(new_admin)
        db.session.commit()

        flash("Signup successful! You can now log in.", 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

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

@app.route('/active-users')
@login_required
def active_users():
    today = date.today()
    active_user_ids = db.session.query(AccessLog.user_id).filter(func.date(AccessLog.timestamp) == today).distinct()
    active_users_list = User.query.filter(User.id.in_(active_user_ids)).all()
    return render_template('active_users.html', users=active_users_list)

@app.route('/today-access')
@login_required
def today_access():
    today = date.today()
    todays_logs = AccessLog.query.filter(func.date(AccessLog.timestamp) == today).all()
    return render_template('today_access.html', logs=todays_logs)

@app.route('/granted-access')
@login_required
def granted_access():
    granted_logs = AccessLog.query.filter_by(access_granted=True).all()
    return render_template('granted_access.html', logs=granted_logs)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        employee_id = request.form.get('employee_id', '').strip()
        email = request.form.get('email', '').strip()
        access_level = request.form.get('access_level', 'basic')

        if not name or not employee_id or not email:
            flash("All fields are required!", 'danger')
            return redirect(url_for('add_user'))
        
        if User.query.filter_by(employee_id=employee_id).first():
            flash('Employee ID already exists', 'danger')
            return render_template('add_user.html')
        
        if User.query.filter_by(name=name).first():
            flash("Name already taken!", 'danger')
            return redirect(url_for('add_user'))
        
        if User.query.filter_by(email=email).first():
            flash("Email already in use!", 'danger')
            return redirect(url_for('add_user'))
        
        new_user = User(
            name=name,
            employee_id=employee_id,
            email=email,
            access_level=access_level
        )
        
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {name} added successfully', 'success')
        logger.info(f"New user added: {name} (ID: {new_user.id})")
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
        flash(f'User {user.name} updated successfully', 'success')
        logger.info(f"User updated: {user.name} (ID: {user.id})")
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    user_name = user.name
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user_name} deleted successfully', 'success')
    logger.info(f"User deleted: {user_name} (ID: {user_id})")
    return redirect(url_for('users'))

@app.route('/access_logs')
@login_required
def access_logs():
    page = request.args.get('page', 1, type=int)
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template('access_logs.html', logs=logs)

def create_admin():
    """Create default admin user if none exists"""
    if not Admin.query.first():
        admin = Admin(
            username='admin',
            employee_id='admin001',
            password_hash=generate_password_hash('admin123'),
            email='admin@dooraccess.com'
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin created - Username: admin, Employee ID: admin001, Password: admin123")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
    
    print("Starting Door Access Control System...")
    print("Default admin credentials:")
    print("Username: admin")
    print("Employee ID: admin001") 
    print("Password: admin123")
    print("\nServer running at http://0.0.0.0:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)