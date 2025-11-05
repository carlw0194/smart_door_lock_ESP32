import sqlite3, json, sys, glob
paths = glob.glob(r'C:\Users\MECHACK\smart_door_lock_ESP32\instance\*.db')
result = {}
for p in paths:
    try:
        conn = sqlite3.connect(p)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        result[p] = tables
        conn.close()
    except Exception as e:
        result[p] = str(e)
print(json.dumps(result, indent=2))
