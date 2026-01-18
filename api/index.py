from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Enable CORS for all routes
from flask_cors import CORS
CORS(app, supports_credentials=True, 
     origins=['https://your-app.vercel.app', 'http://localhost:5000'],
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

DATABASE = '/tmp/lms_database.db'  # Use /tmp directory for Vercel

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with admin user"""
    print("📌 Initializing database on Vercel...")
    conn = get_db()
    
    # Users table
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Create admin user if not exists
    admin_exists = conn.execute('SELECT * FROM users WHERE email = ?', 
                               ('admin@school.edu',)).fetchone()
    if not admin_exists:
        conn.execute('''INSERT INTO users (email, password, first_name, last_name, role)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('admin@school.edu', generate_password_hash('admin123'), 
                   'System', 'Administrator', 'admin'))
        print("✅ Admin user created")
    
    # Create teacher user if not exists
    teacher_exists = conn.execute('SELECT * FROM users WHERE email = ?', 
                                 ('teacher@school.edu',)).fetchone()
    if not teacher_exists:
        conn.execute('''INSERT INTO users (email, password, first_name, last_name, role)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('teacher@school.edu', generate_password_hash('teacher123'), 
                   'John', 'Doe', 'teacher'))
        print("✅ Teacher user created")
    
    conn.commit()
    conn.close()
    print("✅ Database initialized!")

# Initialize database on startup
init_db()

# Login route
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        print(f"🔑 Login attempt for: {data.get('email')}")
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', 
                           (data['email'],)).fetchone()
        
        if user:
            print(f"✅ User found: {user['email']}")
            print(f"📝 Stored hash: {user['password'][:20]}...")
            
            if check_password_hash(user['password'], data['password']):
                print(f"✅ Password correct!")
                
                # Create session
                session['user_id'] = user['id']
                session['role'] = user['role']
                
                return jsonify({
                    'id': user['id'],
                    'email': user['email'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'role': user['role'],
                    'message': 'Login successful'
                })
            else:
                print(f"❌ Password incorrect")
                return jsonify({'error': 'Invalid password'}), 401
        else:
            print(f"❌ User not found")
            return jsonify({'error': 'User not found'}), 401
            
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({'error': str(e)}), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        conn = get_db()
        conn.execute('SELECT 1').fetchone()
        
        admin = conn.execute('SELECT * FROM users WHERE email = ?', 
                           ('admin@school.edu',)).fetchone()
        
        return jsonify({
            'status': 'healthy',
            'platform': 'vercel',
            'admin_exists': bool(admin),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# Debug users
@app.route('/api/debug/users', methods=['GET'])
def debug_users():
    try:
        conn = get_db()
        users = conn.execute('SELECT id, email, role, password FROM users').fetchall()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user['id'],
                'email': user['email'],
                'role': user['role'],
                'password_hash': user['password'][:30] + '...'
            })
        
        return jsonify({
            'total_users': len(users_list),
            'users': users_list
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Test endpoint
@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({
        'message': 'Server is running on Vercel!',
        'timestamp': datetime.now().isoformat()
    })

# Handle all other routes
@app.route('/')
def home():
    return jsonify({
        'message': 'School LMS API',
        'endpoints': [
            '/api/login - POST - User login',
            '/api/health - GET - Health check',
            '/api/debug/users - GET - List users',
            '/api/test - GET - Test endpoint'
        ]
    })

# This is required for Vercel
if __name__ == '__main__':
    app.run(debug=True)