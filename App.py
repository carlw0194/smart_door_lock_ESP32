
# ...existing code...

# Place this after all Flask setup and before main routes




from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import secrets
import json
from sqlalchemy.sql import func


app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///door_access.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
@app.route('/start_registration/<int:user_id>', methods=['POST'])
def start_registration_web(user_id):
    import requests
    backend_url = 'http://127.0.0.1:5000/api/start_registration'  # Change to your backend IP if needed
    requests.post(backend_url, json={'user_id': user_id})
    flash(f'Registration mode started for user {user_id}')
    return redirect(url_for('users'))
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Registration state (in-memory, for demo; use DB for production)
registration_state = {'active': False, 'user_id': None}

# Endpoint for web app to trigger registration for a user
@app.route('/api/start_registration', methods=['POST'])
def start_registration():
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'status': 'error', 'message': 'Missing user_id'}), 400
    registration_state['active'] = True
    registration_state['user_id'] = user_id
    return jsonify({'status': 'success', 'message': 'Registration started', 'user_id': user_id})

# Endpoint for ESP32 to poll registration state
@app.route('/api/poll_registration', methods=['GET'])
def poll_registration():
    if registration_state['active'] and registration_state['user_id']:
        return jsonify({'register': True, 'user_id': registration_state['user_id']})
    return jsonify({'register': False})

# Endpoint for ESP32 to clear registration state after use
@app.route('/api/clear_registration', methods=['POST'])
def clear_registration():
    registration_state['active'] = False
    registration_state['user_id'] = None
    return jsonify({'status': 'success'})


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
    username = db.Column(db.String(150), unique=True, nullable=True) # Unique username for user login
    password = db.Column(db.String(200), nullable=True)  # Password for user login, optional
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

# Routes
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
        admin = Admin.query.filter_by(username=username, employee_id=employee_id).first()
        
        if not username or not employee_id or not password:
            flash("All fields are required!", 'danger')
            return redirect(url_for('login'))
        
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Credentials. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        employee_id = request.form.get('employee_id').strip()
        email = request.form.get('email').strip()

        # Required fields check
        if not username or not password or not confirm_password or not employee_id or not email:
            flash("All fields are required!")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect(url_for('signup'))

        if Admin.query.filter_by(username=username).first():
            flash("Username already taken!")
            return redirect(url_for('signup'))

        if Admin.query.filter_by(employee_id=employee_id).first():
            flash("Employee ID already exists!")
            return redirect(url_for('signup'))

        if Admin.query.filter_by(email=email).first():
            flash("Email already in use!")
            return redirect(url_for('signup'))

        new_admin = Admin(
            username=username,
            employee_id=employee_id,
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
            
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

@app.route('/active-users')
@login_required
def active_users():
    # Active users logic: users who accessed today (or recently) or have is_active flag
    # Adjust criteria depending on your model fields
    today = date.today()
    active_user_ids = db.session.query(AccessLog.user_id).filter(func.date(AccessLog.timestamp) == today).distinct()
    active_users = User.query.filter(User.id.in_(active_user_ids)).all()
    return render_template('active_users.html', users=active_users)

@app.route('/today-access')
@login_required
def today_access():
    # Logs of all access attempts today
    today = date.today()
    todays_logs = AccessLog.query.filter(func.date(AccessLog.timestamp) == today).all()
    return render_template('today_access.html', logs=todays_logs)

@app.route('/granted-access')
@login_required
def granted_access():
    # All logs where access was granted
    granted_logs = AccessLog.query.filter_by(access_granted=True).all()
    return render_template('granted_access.html', logs=granted_logs)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        name = request.form.get('name')
        employee_id = request.form.get('employee_id')
        email = request.form.get('email')
        access_level = request.form['access_level']

        #validate required fields
        if not name or not employee_id or not email:
            flash("All fields are required!")
            return redirect(url_for('add_user'))
        
        # Check if employee_id already exists
        existing_user = User.query.filter_by(employee_id=employee_id).first()
        if existing_user:
            flash('Employee ID already exists')
            return render_template('add_user.html')
        
        # Check for duplicate username
        if User.query.filter_by(name=name).first():
            flash("Username already taken!")
            return redirect(url_for('add_user'))
        
         # Check for duplicate email
        if User.query.filter_by(email=email).first():
            flash("Email already in use!")
            return redirect(url_for('add_user'))
        
        #create and save new user
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
def check_access():
    """API endpoint for ESP32 to check if access should be granted
    Note: This endpoint forwards the request to MQTT for consistency"""
    try:
        data = request.get_json()
        
        # Add device_id if not present
        if 'device_id' not in data:
            data['device_id'] = request.remote_addr
            
        # Forward request to MQTT handler
        mqtt_handler = current_app.mqtt_handler
        if mqtt_handler:
            # Process request through MQTT handler
            mqtt_handler.handle_access_request(data)
            
            # Return immediate response for HTTP request
            return jsonify({
                'status': 'success',
                'message': 'Access request processed via MQTT',
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'MQTT handler not available',
                'timestamp': datetime.utcnow().isoformat()
            }), 503
    except Exception as e:
        app.logger.error(f"Error in check_access: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500
        # For now, this line is removed as log_entry is not defined
        db.session.add(log_entry)
        db.session.commit()
        
        response = {
            'access_granted': access_granted,
            'user_name': user.name if user else None,
            'user_id': user.id if user else None,
            'message': 'Access granted' if access_granted else 'Access denied'
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/register_rfid', methods=['POST'])
def register_rfid():
    """API endpoint to register RFID card to user"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        rfid_uid = data.get('rfid_uid')
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if RFID is already registered
        existing = User.query.filter_by(rfid_uid=rfid_uid).first()
        if existing and existing.id != user_id:
            return jsonify({'error': 'RFID already registered to another user'}), 400
        
        user.rfid_uid = rfid_uid
        db.session.commit()
        
        return jsonify({'message': 'RFID registered successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/register_fingerprint', methods=['POST'])
def register_fingerprint():
    """API endpoint to register fingerprint to user"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        fingerprint_id = data.get('fingerprint_id')
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if fingerprint is already registered
        existing = User.query.filter_by(fingerprint_id=fingerprint_id).first()
        if existing and existing.id != user_id:
            return jsonify({'error': 'Fingerprint already registered to another user'}), 400
        
        user.fingerprint_id = fingerprint_id
        db.session.commit()
        
        return jsonify({'message': 'Fingerprint registered successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/door_state', methods=['POST'])
def update_door_state():
    """API endpoint for ESP32 to report door state"""
    try:
        data = request.get_json()
        door_state = data.get('state')  # 'open' or 'closed'
        
        # You can add logic here to update door state in database
        # or trigger alerts if door is left open too long
        log_entry = AccessLog(
        access_method="system",
        access_granted=True,
        door_state=door_state,
        ip_address=request.remote_addr
)
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({'message': 'Door state updated'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users')
def api_users():
    """API endpoint to get all users (for ESP32 sync if needed)"""
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
        print("Default admin created - Username: admin, employee_id: admin001, Password: admin123")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
    app.run(debug=True, host='0.0.0.0', port=5000)