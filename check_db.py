import sqlite3

try:
    conn = sqlite3.connect('lms_database')
    cursor = conn.cursor()
    
    # Check tables
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table";')
    tables = cursor.fetchall()
    
    print("✅ Database opened successfully!")
    print(f"Found {len(tables)} tables:")
    
    for table in tables:
        print(f"  - {table[0]}")
    
    # Check if there's a users/admin table
    for table in tables:
        if 'user' in table[0].lower() or 'admin' in table[0].lower():
            print(f"\n🔍 Let's check '{table[0]}' table:")
            try:
                cursor.execute(f'SELECT * FROM {table[0]} LIMIT 3;')
                rows = cursor.fetchall()
                print(f"First few rows: {rows}")
            except:
                print(f"Couldn't read {table[0]} table structure")
    
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")