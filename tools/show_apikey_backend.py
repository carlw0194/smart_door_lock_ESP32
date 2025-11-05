import sqlite3, json, os
p = r'C:\Users\MECHACK\smart_door_lock_ESP32\backend\door_access.db'
if not os.path.exists(p):
    print(json.dumps({'error':'db not found', 'path':p}))
else:
    conn = sqlite3.connect(p)
    cur = conn.cursor()
    try:
        cur.execute('SELECT id,key_hash,device_name,is_active,created_at,last_used FROM APIKey')
        rows = cur.fetchall()
        print(json.dumps({'rows':rows}, default=str))
    except Exception as e:
        print(json.dumps({'error':str(e)}))
    conn.close()
