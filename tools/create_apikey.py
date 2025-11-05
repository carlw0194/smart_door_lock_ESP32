import sqlite3, secrets, hashlib, json, datetime, os, sys
path = r'C:\Users\MECHACK\smart_door_lock_ESP32\instance\door_access.db'
if not os.path.exists(path):
    print('DB not found at', path)
    sys.exit(1)
conn = sqlite3.connect(path)
cur = conn.cursor()
# Create APIKey table if it doesn't exist
cur.execute("""
CREATE TABLE IF NOT EXISTS APIKey (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT UNIQUE NOT NULL,
    device_name TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at TEXT,
    last_used TEXT
)
""")
conn.commit()
# Generate new API key
plain = secrets.token_urlsafe(24)
key_hash = hashlib.sha256(plain.encode()).hexdigest()
created_at = datetime.datetime.utcnow().isoformat()
try:
    cur.execute('INSERT INTO APIKey (key_hash, device_name, is_active, created_at) VALUES (?,?,?,?)',
                (key_hash, 'ESP32-generated', 1, created_at))
    conn.commit()
    print('Created API key:')
    print(plain)
    print('\nKey hash (stored in DB):', key_hash[:12] + '...')
    print('Inserted into', path)
except Exception as e:
    print('ERROR inserting API key into DB:', e)
    # If duplicate, try to find existing
    cur.execute('SELECT id, key_hash, device_name, is_active, created_at FROM APIKey')
    rows = cur.fetchall()
    print('Existing APIKey rows:')
    for r in rows:
        print(r)
finally:
    conn.close()
