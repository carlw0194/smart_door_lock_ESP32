import sqlite3, hashlib, secrets, datetime, json, os

# Path for the backend DB used by app.py (default sqlite:///door_access.db)
db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'backend', 'door_access.db')
# Ensure path exists
os.makedirs(os.path.dirname(db_path), exist_ok=True)

# Generate a new API key
api_key = secrets.token_urlsafe(32)
key_hash = hashlib.sha256(api_key.encode()).hexdigest()
now = datetime.datetime.utcnow().isoformat()

try:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Create table if not exists (matching SQLAlchemy model)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS APIKey (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            device_name TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT,
            last_used TEXT
        )
    ''')
    # Insert new key
    cur.execute('INSERT INTO APIKey (key_hash, device_name, is_active, created_at) VALUES (?, ?, ?, ?)',
                (key_hash, 'ESP32-manual', 1, now))
    conn.commit()
    conn.close()
    print(json.dumps({'api_key': api_key, 'key_hash': key_hash, 'db': db_path}))
except Exception as e:
    print(json.dumps({'error': str(e)}))
