from pymongo import MongoClient
from urllib.parse import quote_plus
import os

# Method 1: Try environment variable first
def test_connection():
    print("🔧 Testing MongoDB connection...")
    
    # Try different connection methods
    connection_methods = []
    
    # Method A: Environment variable
    env_uri = os.environ.get('MONGO_URI')
    if env_uri:
        connection_methods.append(("Environment Variable", env_uri))
    
    # Method B: Hardcoded with encoding
    username = "School_Lms"
    password = "gwrNKQH7KPPpK"
    encoded_password = quote_plus(password)
    hardcoded_uri = f"mongodb+srv://{username}:{encoded_password}@cluster0.kwfjszf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    connection_methods.append(("Hardcoded", hardcoded_uri))
    
    # Method C: Hardcoded without encoding (in case password doesn't need it)
    plain_uri = f"mongodb+srv://{username}:{password}@cluster0.kwfjszf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    connection_methods.append(("Plain Password", plain_uri))
    
    # Test each method
    for method_name, uri in connection_methods:
        print(f"\n🔍 Testing: {method_name}")
        print(f"   URI: {uri[:60]}...")
        
        try:
            client = MongoClient(uri, serverSelectionTimeoutMS=5000)
            client.admin.command('ping')
            print(f"   ✅ SUCCESS with {method_name}!")
            
            # List databases
            print(f"   📁 Databases: {client.list_database_names()[:5]}...")
            
            # Test our database
            db = client['lms_database']
            print(f"   🗄️  Database '{db.name}' accessible")
            
            # List collections
            collections = db.list_collection_names()
            print(f"   📊 Collections: {collections if collections else 'None yet'}")
            
            client.close()
            return True
            
        except Exception as e:
            print(f"   ❌ Failed: {str(e)[:100]}...")
            continue
    
    print("\n❌ All connection methods failed!")
    return False

# Also check password encoding
print("🔐 Password analysis:")
password = "gwrNKQH7KPPpK"
print(f"   Original: {password}")
print(f"   Encoded: {quote_plus(password)}")
print(f"   Same?: {password == quote_plus(password)}")

# Run the test
if __name__ == "__main__":
    success = test_connection()
    if success:
        print("\n🎉 MongoDB connection successful! Your app should work.")
    else:
        print("\n⚠️  Check your MongoDB Atlas settings:")
        print("   1. Is your IP address whitelisted? (Add 0.0.0.0/0 for testing)")
        print("   2. Is the username 'School_Lms' correct?")
        print("   3. Is the cluster name 'cluster0.kwfjszf.mongodb.net' correct?")