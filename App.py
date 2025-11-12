import os
import secrets
import logging
from datetime import datetime, date

from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

# =============== Logging ===============
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("door-access")

# =============== App / Config ===============
app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(16))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///door_access.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["API_KEY"] = os.getenv("API_KEY", "")  # optional; if empty then not enforced

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# In-memory registration state (simple demo). For production, persist in DB.
registration_state = {"active": False, "user_id": None, "mode": "any"}  # mode: any|rfid|finger

# =============== Helpers ===============
def json_error(message, code=400, **extra):
    payload = {"error": message, "status": code}
    payload.update(extra)
    response = jsonify(payload)
    response.status_code = code
    return response

def get_json():
    if not request.is_json:
        return None, json_error("Request must be application/json", 415)
    try:
        data = request.get_json(silent=False)
        if data is None:
            return None, json_error("Invalid or empty JSON", 400)
        return data, None
    except Exception as e:
        logger.exception("JSON parse error")
        return None, json_error(f"JSON parse error: {e}", 400)

def enforce_api_key():
    """Optional API key guard for API endpoints."""
    configured = app.config.get("API_KEY", "")
    if not configured:
        return None  # not enforced
    provided = request.headers.get("X-API-Key", "")
    if secrets.compare_digest(configured, provided):
        return None
    return json_error("Unauthorized: invalid API key", 401)

def commit_or_rollback():
    try:
        db.session.commit()
        return None
    except IntegrityError as ie:
        db.session.rollback()
        logger.exception("Integrity error")
        # Extract a friendly message if possible
        return json_error("Integrity constraint violated (duplicate or invalid data).", 409, detail=str(ie))
    except SQLAlchemyError as se:
        db.session.rollback()
        logger.exception("Database error")
        return json_error("Database error.", 500, detail=str(se))

def client_ip():
    # Works behind proxies if they set X-Forwarded-For; otherwise remote_addr
    xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return xff or (request.remote_addr or "")

# =============== Models ===============
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    employee_id = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    employee_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    rfid_uid = db.Column(db.String(50), unique=True, nullable=True)
    fingerprint_id = db.Column(db.Integer, unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    access_level = db.Column(db.String(20), default="basic", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_access = db.Column(db.DateTime, nullable=True)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    access_method = db.Column(db.String(20), nullable=False)  # rfid|fingerprint|system|other
    access_granted = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    door_state = db.Column(db.String(16), default="closed")
    rfid_uid = db.Column(db.String(50), nullable=True)
    fingerprint_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4/IPv6-safe

    user = db.relationship("User", backref="access_logs")

@login_manager.user_loader
def load_user(user_id):
    try:
        return Admin.query.get(int(user_id))
    except Exception:
        return None

# =============== Error Handlers ===============
@app.errorhandler(400)
def bad_request(e):  return json_error("Bad request.", 400)
@app.errorhandler(401)
def unauth(e):       return json_error("Unauthorized.", 401)
@app.errorhandler(403)
def forbid(e):       return json_error("Forbidden.", 403)
@app.errorhandler(404)
def not_found(e):    return json_error("Not found.", 404)
@app.errorhandler(405)
def method_not_allowed(e): return json_error("Method not allowed.", 405)
@app.errorhandler(413)
def too_large(e):    return json_error("Payload too large.", 413)
@app.errorhandler(429)
def too_many(e):     return json_error("Too many requests.", 429)
@app.errorhandler(500)
def server_error(e): return json_error("Internal server error.", 500)

# =============== Health / Debug ===============
@app.route("/health")
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat() + "Z"})

@app.before_request
def _log_request():
    # Small, safe access log
    logger.debug(f"{request.method} {request.path} IP={client_ip()} ct={request.content_type}")

# =============== Registration Flow (server-driven) ===============
@app.route("/api/start_registration", methods=["POST"])
def start_registration():
    api_guard = enforce_api_key()
    if api_guard:
        return api_guard

    data, err = get_json()
    if err:
        return err

    user_id = data.get("user_id")
    mode = (data.get("mode") or "any").strip().lower()  # any|rfid|finger
    if mode not in {"any", "rfid", "finger", "fingerprint"}:
        return json_error("Invalid mode. Use any|rfid|finger", 400)

    if not user_id:
        return json_error("Missing user_id", 400)

    user = User.query.get(user_id)
    if not user:
        return json_error("User not found", 404)

    registration_state["active"] = True
    registration_state["user_id"] = int(user_id)
    registration_state["mode"] = "finger" if mode == "fingerprint" else mode

    logger.info(f"Registration started for user {user_id} ({user.name}) mode={registration_state['mode']}")
    return jsonify({"status": "success", "message": f"Registration started for {user.name}",
                    "user_id": user_id, "mode": registration_state["mode"]})

@app.route("/api/poll_registration", methods=["GET"])
def poll_registration():
    api_guard = enforce_api_key()
    if api_guard:
        return api_guard

    try:
        if registration_state["active"] and registration_state["user_id"]:
            return jsonify({
                "register": True,
                "user_id": registration_state["user_id"],
                "mode": registration_state.get("mode", "any")
            })
        return jsonify({"register": False})
    except Exception as e:
        logger.exception("Error in poll_registration")
        return jsonify({"register": False, "error": str(e)})

@app.route("/api/clear_registration", methods=["POST"])
def clear_registration():
    api_guard = enforce_api_key()
    if api_guard:
        return api_guard

    try:
        registration_state.update({"active": False, "user_id": None, "mode": "any"})
        logger.info("Registration state cleared")
        return jsonify({"status": "success"})
    except Exception as e:
        logger.exception("Error in clear_registration")
        return json_error(str(e), 500)

@app.route("/start_registration/<int:user_id>", methods=["POST"])
@login_required
def start_registration_web(user_id):
    try:
        user = User.query.get_or_404(user_id)
        registration_state.update({"active": True, "user_id": user_id, "mode": "any"})
        flash(f"Registration mode started for {user.name}", "success")
        logger.info(f"Registration started via web for user {user_id} ({user.name})")
    except Exception as e:
        logger.exception("Error in start_registration_web")
        flash(f"Error starting registration: {str(e)}", "danger")
    return redirect(url_for("users"))

# =============== Registration Endpoints (RFID / Fingerprint) ===============
@app.route("/api/register_rfid", methods=["POST"])
def register_rfid():
    api_guard = enforce_api_key()
    if api_guard:
        return api_guard

    data, err = get_json()
    if err:
        return err

    user_id = data.get("user_id")
    rfid_uid = (data.get("rfid_uid") or "").strip().upper()

    logger.info(f"RFID registration request - user_id={user_id}, rfid={rfid_uid}")

    if not user_id or not rfid_uid:
        return json_error("Missing user_id or rfid_uid", 400)

    user = User.query.get(user_id)
    if not user:
        return json_error("User not found", 404)

    existing = User.query.filter_by(rfid_uid=rfid_uid).first()
    if existing and existing.id != user_id:
        return json_error(f"RFID already registered to {existing.name}", 409)

    user.rfid_uid = rfid_uid
    err = commit_or_rollback()
    if err:
        return err

    logger.info(f"RFID {rfid_uid} registered to user {user.name} (id={user.id})")
    return jsonify({"message": f"RFID registered successfully to {user.name}", "user_name": user.name})

@app.route("/api/register_fingerprint", methods=["POST"])
def register_fingerprint():
    api_guard = enforce_api_key()
    if api_guard:
        return api_guard

    data, err = get_json()
    if err:
        return err

    user_id = data.get("user_id")
    fingerprint_id = data.get("fingerprint_id")

    logger.info(f"Fingerprint registration request - user_id={user_id}, fp_id={fingerprint_id}")

    if user_id is None or fingerprint_id is None:
        return json_error("Missing user_id or fingerprint_id", 400)

    user = User.query.get(user_id)
    if not user:
        return json_error("User not found", 404)

    try:
        fingerprint_id = int(fingerprint_id)
    except (ValueError, TypeError):
        return json_error("Invalid fingerprint_id format (must be integer)", 400)

    existing = User.query.filter_by(fingerprint_id=fingerprint_id).first()
    if existing and existing.id != user_id:
        return json_error(f"Fingerprint already registered to {existing.name}", 409)

    user.fingerprint_id = fingerprint_id
    err = commit_or_rollback()
    if err:
        return err

    logger.info(f"Fingerprint {fingerprint_id} registered to user {user.name} (id={user.id})")
    return jsonify({"message": f"Fingerprint registered successfully to {user.name}", "user_name": user.name})

# =============== Access Control ===============
@app.route("/api/check_access", methods=["POST"])
def check_access():
    api_guard = enforce_api_key()
    if api_guard:
        return api_guard

    data, err = get_json()
    if err:
        return err

    method = (data.get("method") or "").strip().lower()
    if method not in {"rfid", "fingerprint", "finger"}:
        return json_error("Invalid method. Use rfid|fingerprint", 400)

    user = None
    granted = False

    try:
        logger.info(f"Access check request: {data}")

        if method == "rfid":
            rfid_uid = (data.get("rfid_uid") or "").strip().upper()
            if rfid_uid:
                user = User.query.filter_by(rfid_uid=rfid_uid, is_active=True).first()

        else:  # fingerprint
            fp = data.get("fingerprint_id")
            try:
                fp = int(fp)
            except (TypeError, ValueError):
                return json_error("Invalid fingerprint_id (must be integer)", 400)
            user = User.query.filter_by(fingerprint_id=fp, is_active=True).first()

        if user:
            granted = True
            user.last_access = datetime.utcnow()
            e = commit_or_rollback()
            if e:
                # Not fatal for access decision; just log
                logger.warning(f"Could not update last_access: {e.get_json() if hasattr(e, 'get_json') else e}")

        # Always log attempt
        log_entry = AccessLog(
            user_id=user.id if user else None,
            access_method="rfid" if method == "rfid" else "fingerprint",
            access_granted=granted,
            rfid_uid=data.get("rfid_uid"),
            fingerprint_id=data.get("fingerprint_id"),
            ip_address=client_ip(),
        )
        db.session.add(log_entry)
        e = commit_or_rollback()
        if e:
            logger.warning(f"Could not write access log: {e.get_json() if hasattr(e, 'get_json') else e}")

        resp = {
            "access_granted": granted,
            "user_name": user.name if user else None,
            "user_id": user.id if user else None,
            "message": f"Welcome, {user.name}!" if granted else "Access denied",
        }
        return jsonify(resp)

    except Exception as ex:
        logger.exception("Error in check_access")
        db.session.rollback()
        return json_error(str(ex), 500)

# =============== Door State (optional telemetry) ===============
@app.route("/api/door_state", methods=["POST"])
def update_door_state():
    api_guard = enforce_api_key()
    if api_guard:
        return api_guard

    data, err = get_json()
    if err:
        return err

    door_state = (data.get("state") or "unknown").strip().lower()
    if door_state not in {"open", "closed", "opening", "closing", "unknown"}:
        door_state = "unknown"

    entry = AccessLog(
        access_method="system",
        access_granted=True,
        door_state=door_state,
        ip_address=client_ip(),
    )
    db.session.add(entry)
    e = commit_or_rollback()
    if e:
        return e

    logger.info(f"Door state updated to: {door_state}")
    return jsonify({"message": "Door state updated", "state": door_state})

# =============== API: Active Users (machine-readable) ===============
@app.route("/api/users")
def api_users():
    api_guard = enforce_api_key()
    if api_guard:
        return api_guard

    try:
        users = User.query.filter_by(is_active=True).all()
        return jsonify([
            {
                "id": u.id,
                "name": u.name,
                "employee_id": u.employee_id,
                "rfid_uid": u.rfid_uid,
                "fingerprint_id": u.fingerprint_id,
                "access_level": u.access_level,
            }
            for u in users
        ])
    except Exception as e:
        logger.exception("Error in api_users")
        return json_error(str(e), 500)

# Debug route – list all users (do NOT enable in prod)
@app.route("/debug/users")
def debug_users():
    try:
        users = User.query.all()
        return jsonify([
            {
                "id": u.id,
                "name": u.name,
                "employee_id": u.employee_id,
                "rfid_uid": u.rfid_uid,
                "fingerprint_id": u.fingerprint_id,
                "fingerprint_id_type": type(u.fingerprint_id).__name__,
                "is_active": bool(u.is_active),
            }
            for u in users
        ])
    except Exception as e:
        logger.exception("Error in debug_users")
        return json_error(str(e), 500)

# =============== Web Views (Admin) ===============
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        employee_id = request.form.get("employee_id", "").strip()
        password = request.form.get("password", "")

        if not username or not employee_id or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for("login"))

        admin = Admin.query.filter_by(username=username, employee_id=employee_id).first()
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid Credentials. Please try again.", "danger")

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        employee_id = request.form.get("employee_id", "").strip()
        email = request.form.get("email", "").strip()

        if not username or not password or not confirm_password or not employee_id or not email:
            flash("All fields are required!", "danger")
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signup"))

        if Admin.query.filter_by(username=username).first():
            flash("Username already taken!", "danger")
            return redirect(url_for("signup"))

        if Admin.query.filter_by(employee_id=employee_id).first():
            flash("Employee ID already exists!", "danger")
            return redirect(url_for("signup"))

        if Admin.query.filter_by(email=email).first():
            flash("Email already in use!", "danger")
            return redirect(url_for("signup"))

        new_admin = Admin(
            username=username,
            employee_id=employee_id,
            email=email,
            password_hash=generate_password_hash(password, method="pbkdf2:sha256"),
        )
        db.session.add(new_admin)
        e = commit_or_rollback()
        if e:
            flash(f"Signup failed: {e.get_json().get('detail','')}", "danger")
            return redirect(url_for("signup"))

        flash("Signup successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(10).all()

    today_access = AccessLog.query.filter(
        AccessLog.timestamp >= datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()

    granted_access = AccessLog.query.filter_by(access_granted=True).count()
    denied_access = AccessLog.query.filter_by(access_granted=False).count()

    stats = {
        "total_users": total_users,
        "active_users": active_users,
        "today_access": today_access,
        "granted_access": granted_access,
        "denied_access": denied_access,
    }
    return render_template("dashboard.html", stats=stats, recent_logs=recent_logs)

@app.route("/users")
@login_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=all_users)

@app.route("/active-users")
@login_required
def active_users():
    today = date.today()
    active_user_ids = db.session.query(AccessLog.user_id).filter(func.date(AccessLog.timestamp) == today).distinct()
    active_users_list = User.query.filter(User.id.in_(active_user_ids)).all()
    return render_template("active_users.html", users=active_users_list)

@app.route("/today-access")
@login_required
def today_access():
    today = date.today()
    todays_logs = AccessLog.query.filter(func.date(AccessLog.timestamp) == today).all()
    return render_template("today_access.html", logs=todays_logs)

@app.route("/granted-access")
@login_required
def granted_access():
    granted_logs = AccessLog.query.filter_by(access_granted=True).all()
    return render_template("granted_access.html", logs=granted_logs)

@app.route("/add_user", methods=["GET", "POST"])
@login_required
def add_user():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        employee_id = request.form.get("employee_id", "").strip()
        email = request.form.get("email", "").strip()
        access_level = request.form.get("access_level", "basic").strip() or "basic"

        if not name or not employee_id or not email:
            flash("All fields are required!", "danger")
            return redirect(url_for("add_user"))

        if User.query.filter_by(employee_id=employee_id).first():
            flash("Employee ID already exists", "danger")
            return render_template("add_user.html")

        if User.query.filter_by(name=name).first():
            flash("Name already taken!", "danger")
            return redirect(url_for("add_user"))

        if User.query.filter_by(email=email).first():
            flash("Email already in use!", "danger")
            return redirect(url_for("add_user"))

        new_user = User(
            name=name,
            employee_id=employee_id,
            email=email,
            access_level=access_level,
        )
        db.session.add(new_user)
        e = commit_or_rollback()
        if e:
            flash(f"Add user failed: {e.get_json().get('detail','')}", "danger")
            return redirect(url_for("add_user"))

        flash(f"User {name} added successfully", "success")
        logger.info(f"New user added: {name} (ID: {new_user.id})")
        return redirect(url_for("users"))

    return render_template("add_user.html")

@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        user.name = request.form.get("name", user.name)
        user.email = request.form.get("email", user.email)
        user.access_level = request.form.get("access_level", user.access_level)
        user.is_active = "is_active" in request.form

        e = commit_or_rollback()
        if e:
            flash(f"Update failed: {e.get_json().get('detail','')}", "danger")
            return redirect(url_for("edit_user", user_id=user.id))

        flash(f"User {user.name} updated successfully", "success")
        logger.info(f"User updated: {user.name} (ID: {user.id})")
        return redirect(url_for("users"))

    return render_template("edit_user.html", user=user)

@app.route("/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    user_name = user.name
    try:
        db.session.delete(user)
        e = commit_or_rollback()
        if e:
            flash(f"Delete failed: {e.get_json().get('detail','')}", "danger")
            return redirect(url_for("users"))
        flash(f"User {user_name} deleted successfully", "success")
        logger.info(f"User deleted: {user_name} (ID: {user_id})")
    except Exception as ex:
        db.session.rollback()
        flash(f"Delete failed: {ex}", "danger")
        logger.exception("Delete user failed")
    return redirect(url_for("users"))

@app.route("/access_logs")
@login_required
def access_logs():
    page = request.args.get("page", 1, type=int)
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template("access_logs.html", logs=logs)

# =============== Bootstrap ===============
def create_admin():
    """Create default admin user if none exists."""
    if not Admin.query.first():
        admin = Admin(
            username="admin",
            employee_id="admin001",
            email="admin@dooraccess.com",
            password_hash=generate_password_hash("admin123", method="pbkdf2:sha256"),
        )
        db.session.add(admin)
        db.session.commit()
        logger.warning("Default admin created - Username: admin, Employee ID: admin001, Password: admin123")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_admin()

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))

    print("Starting Door Access Control System...")
    print("Default admin credentials (if none existed):")
    print("Username: admin")
    print("Employee ID: admin001")
    print("Password: admin123")
    print(f"\nServer running at http://{host}:{port}")
    if app.config.get("API_KEY"):
        print("API key enforcement: ON")
    else:
        print("API key enforcement: OFF (set API_KEY env to enable)")

    app.run(debug=True, host=host, port=port)

