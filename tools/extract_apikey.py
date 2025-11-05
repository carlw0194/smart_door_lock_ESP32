import sqlite3, json, sys
path = r'C:\Users\MECHACK\smart_door_lock_ESP32\instance\door_access.db'
try:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    # Check tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print('tables:', tables)
    if 'APIKey' not in tables:
        print('APIKey table not found')
    else:
        cur.execute("PRAGMA table_info('APIKey')")
        cols = [r[1] for r in cur.fetchall()]
        print('APIKey columns:', cols)
        cur.execute('SELECT * FROM APIKey')
        rows = cur.fetchall()
        if not rows:
            print('APIKey table is empty')
        else:
            for r in rows:
                entry = dict(zip(cols, r))
                # hide long hashes but show whether plain_key exists
                if 'plain_key' in entry and entry['plain_key']:
                    entry_display = entry
                else:
                    entry_display = entry.copy()
                    if 'key_hash' in entry_display and entry_display['key_hash']:
                        entry_display['key_hash'] = entry_display['key_hash'][:8] + '...'
                print(json.dumps(entry_display, default=str))
    conn.close()
except Exception as e:
    print('ERROR:', e)
    sys.exit(1)
