import sqlite3, json, sys, os
instance_dir = r'C:\Users\MECHACK\smart_door_lock_ESP32\instance'
files = [f for f in os.listdir(instance_dir) if f.endswith('.db')]
print('DB files found:', files)
for f in files:
    path = os.path.join(instance_dir, f)
    try:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        print('\nChecking', f, 'tables:', tables)
        if 'APIKey' in tables:
            print(' -> APIKey table found in', f)
            cur.execute("PRAGMA table_info('APIKey')")
            cols = [r[1] for r in cur.fetchall()]
            print('APIKey columns:', cols)
            cur.execute('SELECT * FROM APIKey')
            rows = cur.fetchall()
            for r in rows:
                entry = dict(zip(cols, r))
                if 'plain_key' in entry and entry['plain_key']:
                    print('  ', json.dumps(entry, default=str))
                else:
                    if 'key_hash' in entry:
                        entry['key_hash'] = entry['key_hash'][:8] + '...'
                    print('  ', json.dumps(entry, default=str))
        conn.close()
    except Exception as e:
        print('ERROR reading', path, e)
