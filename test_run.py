print("Testing Flask app...")
try:
    from app import app
    print("✅ App imported successfully!")
    
    # Test MongoDB connection
    with app.app_context():
        from app import get_db
        db = get_db()
        print(f"✅ Connected to database: {db.name}")
        
except Exception as e:
    print(f"❌ Error: {e}")