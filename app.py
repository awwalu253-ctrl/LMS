from flask import Flask, request, jsonify, session, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
import json
import time
from functools import wraps
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from bson.json_util import dumps, loads
from urllib.parse import quote_plus  # Added for password encoding
from dotenv import load_dotenv  # Added for environment variables

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_folder='.')
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

CORS(app, supports_credentials=True, 
     origins=['http://localhost:5000', 'http://127.0.0.1:5000'],
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     expose_headers=['Set-Cookie'])

# MongoDB connection with password encoding
def get_mongo_uri():
    # Try environment variable first (for Vercel)
    env_uri = os.environ.get('MONGO_URI')
    if env_uri:
        return env_uri
    
    # Fallback for local development
    username = "School_Lms"
    password = "gwrNKQH7KPPpK"
    encoded_password = quote_plus(password)
    return f"mongodb+srv://{username}:{encoded_password}@cluster0.kwfjszf.mongodb.net/lms_database?retryWrites=true&w=majority&appName=Cluster0"

MONGO_URI = get_mongo_uri()
DATABASE_NAME = 'lms_database'

def get_db():
    if 'db' not in g:
        g.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        g.db = g.client[DATABASE_NAME]
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    client = g.pop('client', None)
    if client is not None:
        client.close()

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'teacher':
            return jsonify({'error': 'Teacher access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'student':
            return jsonify({'error': 'Student access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def serialize_doc(doc):
    if doc is None:
        return None
    if '_id' in doc:
        doc['_id'] = str(doc['_id'])
    return doc

def serialize_list(docs):
    return [serialize_doc(doc) for doc in docs]

def generate_student_id(db):
    try:
        last_student = db.users.find_one(
            {'role': 'student', 'student_id': {'$regex': '^LMS'}},
            sort=[('student_id', DESCENDING)]
        )
        
        if not last_student or 'student_id' not in last_student:
            return "LMS001"
        
        last_id = last_student['student_id']
        try:
            number_part = last_id[3:]
            next_number = int(number_part) + 1
            return f"LMS{next_number:03d}"
        except ValueError:
            return "LMS001"
        
    except Exception as e:
        timestamp = int(time.time() % 1000)
        return f"LMS{timestamp:03d}"

def auto_enroll_compulsory_courses(db, student_id, level, department=None):
    try:
        compulsory_courses = list(db.courses.find({
            'level': level,
            'is_compulsory': True,
            'status': 'active'
        }))
        
        enrollments_to_insert = []
        for course in compulsory_courses:
            enrollments_to_insert.append({
                'student_id': ObjectId(student_id),
                'course_id': course['_id'],
                'enrolled_at': datetime.utcnow()
            })
        
        if enrollments_to_insert:
            try:
                db.enrollments.insert_many(enrollments_to_insert, ordered=False)
            except:
                pass  # Some might already exist
        
        print(f"✅ Auto-enrolled student {student_id} in {len(compulsory_courses)} compulsory courses for level {level}")
        
    except Exception as e:
        print(f"⚠️ Error auto-enrolling student: {e}")

def init_db():
    with app.app_context():
        try:
            db = get_db()
            
            # Test connection first
            db.command('ping')
            print("✅ MongoDB connected successfully!")
            
            # Create indexes
            db.users.create_index([('email', ASCENDING)], unique=True)
            db.users.create_index([('teacher_code', ASCENDING)], unique=True, sparse=True)
            db.users.create_index([('student_id', ASCENDING)], unique=True, sparse=True)
            db.users.create_index([('role', ASCENDING)])
            db.users.create_index([('level', ASCENDING), ('department', ASCENDING)])
            
            db.courses.create_index([('course_code', ASCENDING)], unique=True)
            db.courses.create_index([('level', ASCENDING), ('department', ASCENDING)])
            db.courses.create_index([('status', ASCENDING)])
            db.courses.create_index([('is_compulsory', ASCENDING)])
            
            db.teacher_courses.create_index([('teacher_id', ASCENDING), ('course_id', ASCENDING)], unique=True)
            db.teacher_courses.create_index([('teacher_id', ASCENDING)])
            db.teacher_courses.create_index([('course_id', ASCENDING)])
            
            db.enrollments.create_index([('student_id', ASCENDING), ('course_id', ASCENDING)], unique=True)
            db.enrollments.create_index([('student_id', ASCENDING)])
            db.enrollments.create_index([('course_id', ASCENDING)])
            
            db.announcements.create_index([('course_id', ASCENDING)])
            db.announcements.create_index([('teacher_id', ASCENDING)])
            db.announcements.create_index([('created_at', DESCENDING)])
            
            db.assignments.create_index([('course_id', ASCENDING)])
            db.assignments.create_index([('teacher_id', ASCENDING)])
            db.assignments.create_index([('due_date', ASCENDING)])
            
            db.submissions.create_index([('assignment_id', ASCENDING), ('student_id', ASCENDING)], unique=True)
            db.submissions.create_index([('assignment_id', ASCENDING)])
            db.submissions.create_index([('student_id', ASCENDING)])
            
            db.materials.create_index([('course_id', ASCENDING)])
            db.materials.create_index([('teacher_id', ASCENDING)])
            
            db.discussion_posts.create_index([('course_id', ASCENDING)])
            db.discussion_posts.create_index([('user_id', ASCENDING)])
            db.discussion_posts.create_index([('created_at', DESCENDING)])
            
            db.discussion_replies.create_index([('post_id', ASCENDING)])
            db.discussion_replies.create_index([('user_id', ASCENDING)])
            
            db.notifications.create_index([('user_id', ASCENDING)])
            db.notifications.create_index([('is_read', ASCENDING)])
            db.notifications.create_index([('created_at', DESCENDING)])
            
            db.admin_announcements.create_index([('created_at', DESCENDING)])
            
            db.course_approval_requests.create_index([('status', ASCENDING)])
            db.course_approval_requests.create_index([('teacher_id', ASCENDING)])
            db.course_approval_requests.create_index([('course_id', ASCENDING)])
            db.course_approval_requests.create_index([('requested_at', DESCENDING)])
            
            # Create admin user
            if not db.users.find_one({'email': 'admin@school.edu'}):
                db.users.insert_one({
                    'email': 'admin@school.edu',
                    'password': generate_password_hash('admin123'),
                    'first_name': 'System',
                    'last_name': 'Administrator',
                    'role': 'admin',
                    'status': 'active',
                    'created_at': datetime.utcnow()
                })
                print("✅ Admin user created")
            
            # Create teacher user
            if not db.users.find_one({'email': 'teacher@school.edu'}):
                db.users.insert_one({
                    'email': 'teacher@school.edu',
                    'password': generate_password_hash('teacher123'),
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'role': 'teacher',
                    'teacher_code': 'TCH001',
                    'status': 'active',
                    'created_at': datetime.utcnow()
                })
                print("✅ Teacher user created")
            
            # Create initial courses
            if db.courses.count_documents({}) == 0:
                compulsory_courses_config = {
                    'MS1': [
                        ('Mathematics MS1', 'Mathematics for Middle School 1', 'MATH-MS1', 3, 'all', 'MS1', True),
                        ('English Language MS1', 'English Language for Middle School 1', 'ENG-MS1', 3, 'all', 'MS1', True),
                        ('Data Processing MS1', 'Data Processing for Middle School 1', 'DATA-PROC-MS1', 3, 'all', 'MS1', True)
                    ],
                    'MS2': [
                        ('Mathematics MS2', 'Mathematics for Middle School 2', 'MATH-MS2', 3, 'all', 'MS2', True),
                        ('English Language MS2', 'English Language for Middle School 2', 'ENG-MS2', 3, 'all', 'MS2', True),
                        ('Data Processing MS2', 'Data Processing for Middle School 2', 'DATA-PROC-MS2', 3, 'all', 'MS2', True)
                    ],
                    'MS3': [
                        ('Mathematics MS3', 'Mathematics for Middle School 3', 'MATH-MS3', 3, 'all', 'MS3', True),
                        ('English Language MS3', 'English Language for Middle School 3', 'ENG-MS3', 3, 'all', 'MS3', True),
                        ('Data Processing MS3', 'Data Processing for Middle School 3', 'DATA-PROC-MS3', 3, 'all', 'MS3', True)
                    ],
                    'HS1': [
                        ('Mathematics HS1', 'Mathematics for High School 1', 'MATH-HS1', 3, 'all', 'HS1', True),
                        ('English Language HS1', 'English Language for High School 1', 'ENG-HS1', 3, 'all', 'HS1', True),
                        ('Data Processing HS1', 'Data Processing for High School 1', 'DATA-PROC-HS1', 3, 'all', 'HS1', True)
                    ],
                    'HS2': [
                        ('Mathematics HS2', 'Mathematics for High School 2', 'MATH-HS2', 3, 'all', 'HS2', True),
                        ('English Language HS2', 'English Language for High School 2', 'ENG-HS2', 3, 'all', 'HS2', True),
                        ('Data Processing HS2', 'Data Processing for High School 2', 'DATA-PROC-HS2', 3, 'all', 'HS2', True)
                    ],
                    'HS3': [
                        ('Mathematics HS3', 'Mathematics for High School 3', 'MATH-HS3', 3, 'all', 'HS3', True),
                        ('English Language HS3', 'English Language for High School 3', 'ENG-HS3', 3, 'all', 'HS3', True),
                        ('Data Processing HS3', 'Data Processing for High School 3', 'DATA-PROC-HS3', 3, 'all', 'HS3', True)
                    ]
                }
                
                for level, level_courses in compulsory_courses_config.items():
                    for title, description, code, credits, department, level_name, is_compulsory in level_courses:
                        db.courses.insert_one({
                            'title': title,
                            'description': description,
                            'course_code': code,
                            'credits': credits,
                            'teacher_lock': True,
                            'status': 'active',
                            'level': level_name,
                            'department': department,
                            'is_compulsory': is_compulsory,
                            'created_at': datetime.utcnow()
                        })
                
                print("✅ Database initialized with compulsory courses for each level!")
                
        except Exception as e:
            print(f"❌ Database initialization error: {e}")

# Serve the main page
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# Authentication routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        db = get_db()
        
        if data['role'] == 'student':
            level = data.get('level', '')
            department = data.get('department', '')
            
            if level.startswith('HS') and not department:
                return jsonify({'error': 'Department is required for High School students'}), 400
            
            data['student_id'] = generate_student_id(db)
        
        if data['role'] == 'teacher':
            existing_code = db.users.find_one({'teacher_code': data.get('teacher_code')})
            if existing_code:
                return jsonify({'error': 'Teacher code already exists'}), 400
        
        hashed_password = generate_password_hash(data['password'])
        
        user_data = {
            'email': data['email'],
            'password': hashed_password,
            'first_name': data['first_name'],
            'last_name': data['last_name'],
            'role': data['role'],
            'status': 'active',
            'created_at': datetime.utcnow()
        }
        
        optional_fields = ['student_id', 'phone', 'address', 'date_of_birth', 
                          'gender', 'department', 'level', 'teacher_code', 'specialization']
        for field in optional_fields:
            if field in data and data[field]:
                user_data[field] = data[field]
        
        result = db.users.insert_one(user_data)
        new_user_id = str(result.inserted_id)
        
        if data['role'] == 'student':
            auto_enroll_compulsory_courses(db, new_user_id, data.get('level'), data.get('department'))
        
        return jsonify({
            'message': 'Registration successful',
            'student_id': data.get('student_id') if data['role'] == 'student' else None,
            'user_id': new_user_id
        }), 201
    except DuplicateKeyError as e:
        if 'email' in str(e):
            return jsonify({'error': 'Email already exists'}), 400
        elif 'teacher_code' in str(e):
            return jsonify({'error': 'Teacher code already exists'}), 400
        return jsonify({'error': 'Registration failed'}), 400
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/users/<user_id>', methods=['GET', 'PUT'])
@login_required
def user_profile(user_id):
    if session['user_id'] != user_id and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    db = get_db()
    
    if request.method == 'GET':
        try:
            user = db.users.find_one({'_id': ObjectId(user_id)})
            if user:
                user = serialize_doc(user)
                user.pop('password', None)
                return jsonify(user)
            return jsonify({'error': 'User not found'}), 404
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.json
            update_data = {}
            
            allowed_fields = ['first_name', 'last_name', 'phone', 'address', 
                            'date_of_birth', 'gender', 'department', 'level', 
                            'specialization']
            
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if 'password' in data and data['password']:
                update_data['password'] = generate_password_hash(data['password'])
            
            if update_data:
                db.users.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$set': update_data}
                )
            
            return jsonify({'message': 'Profile updated'})
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        db = get_db()
        
        user = db.users.find_one({'email': data['email']})
        
        if user and check_password_hash(user['password'], data['password']):
            if user['status'] == 'suspended':
                return jsonify({'error': 'Your account has been suspended. Please contact administrator.'}), 403
            
            if data.get('role') == 'student' and user['role'] != 'student':
                return jsonify({'error': 'Invalid student account'}), 401
            
            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            session.permanent = True
            return jsonify({
                'id': str(user['_id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'role': user['role']
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/teacher-login', methods=['POST'])
def teacher_login():
    try:
        data = request.json
        db = get_db()
        
        user = db.users.find_one({
            'email': data['email'],
            'role': 'teacher'
        })
        
        if user and check_password_hash(user['password'], data['password']):
            if user['status'] == 'suspended':
                return jsonify({'error': 'Your account has been suspended. Please contact administrator.'}), 403
            
            if user['teacher_code'] != data.get('teacher_code'):
                return jsonify({'error': 'Invalid teacher code'}), 401
            
            teacher_courses = list(db.teacher_courses.find(
                {'teacher_id': user['_id']},
                {'course_id': 1}
            ))
            
            course_ids = [tc['course_id'] for tc in teacher_courses]
            courses = list(db.courses.find({'_id': {'$in': course_ids}}))
            
            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            session.permanent = True
            return jsonify({
                'id': str(user['_id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'role': user['role'],
                'teacher_code': user['teacher_code'],
                'teacher_id': str(user['_id']),
                'assigned_courses': serialize_list(courses)
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/admin-login', methods=['POST'])
def admin_login():
    try:
        data = request.json
        db = get_db()
        
        user = db.users.find_one({
            'email': data['email'],
            'role': 'admin'
        })
        
        if user and check_password_hash(user['password'], data['password']):
            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            session.permanent = True
            return jsonify({
                'id': str(user['_id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'role': user['role']
            })
        
        return jsonify({'error': 'Invalid admin credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/check-session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        return jsonify({
            'logged_in': True,
            'user_id': session['user_id'],
            'role': session.get('role')
        })
    return jsonify({'logged_in': False})

# Course routes - REST OF THE CODE CONTINUES EXACTLY AS YOU HAVE IT...
# [All your other routes remain exactly the same - they are already correct]

# Health check route
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        db = get_db()
        db.command('ping')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("🎓 SCHOOL LEARNING MANAGEMENT SYSTEM (MongoDB)")
    print("="*60)
    print("\n📌 Open your browser and go to:")
    print("   ➡️  http://localhost:5000")
    print("\n🔐 Login Credentials:")
    print("   👑 Admin:      admin@school.edu / admin123")
    print("   👨‍🏫 Teacher:   teacher@school.edu / teacher123 / TCH001")
    print("   👨‍🎓 Students:  Register on the portal")
    print("\n📚 Level System:")
    print("   🏫 Middle School: MS1, MS2, MS3")
    print("   🎓 High School:   HS1, HS2, HS3 (Department required)")
    print("\n📖 Compulsory Courses:")
    print("   1. Mathematics")
    print("   2. English Language")
    print("   3. Data Processing")
    print("\n🔧 Health Check:")
    print("   🌐 http://localhost:5000/api/health")
    print("\n" + "="*60 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0', threaded=True)
else:
    # For Vercel deployment
    init_db()