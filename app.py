from flask import Flask, request, jsonify, session, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
import json
import time
import sys
import logging
import signal
from functools import wraps
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from pymongo.server_api import ServerApi
from bson import ObjectId
from bson.json_util import dumps, loads
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Validate required environment variables
required_env_vars = []
for var in required_env_vars:
    if not os.environ.get(var):
        logger.warning(f"⚠️ Warning: {var} not set in environment")

app = Flask(__name__, static_folder='.')
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configure CORS
cors_origins = ['http://localhost:5000', 'http://127.0.0.1:5000']
if os.environ.get('ALLOWED_ORIGINS'):
    cors_origins.extend(os.environ.get('ALLOWED_ORIGINS').split(','))

CORS(app, supports_credentials=True, 
     origins=cors_origins,
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     expose_headers=['Set-Cookie'])

# MongoDB connection
def get_mongo_uri():
    env_uri = os.environ.get('MONGO_URI')
    if env_uri:
        return env_uri
    
    username = "School_Lms"
    password = "gwrNKQH7KPPpK"
    encoded_password = quote_plus(password)
    return f"mongodb+srv://{username}:{encoded_password}@cluster0.kwfjszf.mongodb.net/lms_database?retryWrites=true&w=majority"

DATABASE_NAME = 'lms_database'

def get_db():
    if 'db' not in g:
        MONGO_URI = get_mongo_uri()
        logger.info("🔧 Connecting to MongoDB Atlas...")
        
        try:
            server_api = ServerApi('1')
            g.client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                server_api=server_api
            )
            g.db = g.client[DATABASE_NAME]
            g.client.admin.command('ping')
            logger.info("✅ MongoDB connected successfully!")
            
        except Exception as e:
            logger.error(f"❌ Standard connection failed: {e}")
            try:
                logger.info("🔄 Trying alternative connection method...")
                g.client = MongoClient(
                    MONGO_URI,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=5000
                )
                g.db = g.client[DATABASE_NAME]
                g.client.admin.command('ping')
                logger.info("✅ Alternative connection successful!")
                
            except Exception as e2:
                logger.error(f"❌ Alternative connection failed: {e2}")
                raise Exception(f"MongoDB connection failed: {e2}")
    
    return g.db

def get_db_with_pool():
    """Alternative connection with connection pooling"""
    if 'db_pool' not in g:
        MONGO_URI = get_mongo_uri()
        g.db_pool = MongoClient(MONGO_URI, maxPoolSize=50)
    return g.db_pool[DATABASE_NAME]

@app.teardown_appcontext
def close_db(exception=None):
    client = g.pop('client', None)
    if client is not None:
        client.close()
    # Also clean up connection pool if used
    if 'db_pool' in g:
        g.pop('db_pool', None)

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

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)

# Helper functions
def serialize_doc(doc):
    if doc is None:
        return None
    
    # Create a copy to avoid modifying the original
    doc_dict = dict(doc)
    
    # Convert ObjectId to string
    if '_id' in doc_dict:
        doc_dict['id'] = str(doc_dict['_id'])
        del doc_dict['_id']
    
    # Convert any remaining ObjectIds
    for key, value in doc_dict.items():
        if isinstance(value, ObjectId):
            doc_dict[key] = str(value)
        elif isinstance(value, datetime):
            doc_dict[key] = value.isoformat()
        elif isinstance(value, list):
            # Recursively handle lists
            doc_dict[key] = [str(item) if isinstance(item, ObjectId) else 
                            item.isoformat() if isinstance(item, datetime) else 
                            item for item in value]
    
    return doc_dict

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
                pass
        
        logger.info(f"✅ Auto-enrolled student {student_id} in {len(compulsory_courses)} compulsory courses for level {level}")
        
    except Exception as e:
        logger.warning(f"⚠️ Error auto-enrolling student: {e}")

def create_notification(db, user_id, title, message, notification_type='info', reference_id=None):
    notification = {
        'user_id': ObjectId(user_id),
        'title': title,
        'message': message,
        'type': notification_type,
        'reference_id': reference_id,
        'is_read': False,
        'created_at': datetime.utcnow()
    }
    db.notifications.insert_one(notification)

def check_fee_payment_status(db, student_id):
    """Check if student's fees have been approved"""
    student = db.users.find_one({'_id': ObjectId(student_id), 'role': 'student'})
    if not student:
        return False
    
    # Check if fee payment is required for this student
    if student.get('fee_payment_required', True):
        # Check if there's an approved fee payment
        fee_payment = db.fee_payments.find_one({
            'student_id': ObjectId(student_id),
            'status': 'approved'
        })
        return fee_payment is not None
    
    return True  # If fee payment not required, allow access

def init_db():
    with app.app_context():
        try:
            db = get_db()
            db.command('ping')
            logger.info("✅ MongoDB connected successfully!")
            
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
            
            # Fee payments indexes
            db.fee_payments.create_index([('student_id', ASCENDING)])
            db.fee_payments.create_index([('status', ASCENDING)])
            db.fee_payments.create_index([('payment_date', DESCENDING)])
            db.fee_payments.create_index([('receipt_number', ASCENDING)], unique=True)
            db.fee_payments.create_index([('academic_year', ASCENDING), ('semester', ASCENDING)])
            
            # Fee structures indexes
            db.fee_structures.create_index([('level', ASCENDING)])
            db.fee_structures.create_index([('department', ASCENDING)])
            db.fee_structures.create_index([('academic_year', ASCENDING)])
            db.fee_structures.create_index([('semester', ASCENDING)])
            
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
                logger.info("✅ Admin user created")
            
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
                logger.info("✅ Teacher user created")
            
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
                
                logger.info("✅ Database initialized with compulsory courses for each level!")
                
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")

# ==============================================
# MAIN ROUTES
# ==============================================

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# ==============================================
# AUTHENTICATION ROUTES
# ==============================================

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
            # Set fee payment required to True by default for new students
            data['fee_payment_required'] = True
        
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
                          'gender', 'department', 'level', 'teacher_code', 
                          'specialization', 'fee_payment_required']
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
        logger.error(f"Registration error: {e}")
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
            
            # Check fee payment for students
            if user['role'] == 'student':
                # Get all fee payments for student
                fee_payments = list(db.fee_payments.find({
                    'student_id': user['_id']
                }))
                
                # Check if there's an approved payment
                has_approved_payment = any(p['status'] == 'approved' for p in fee_payments)
                
                # Check if fee payment is required
                fee_payment_required = user.get('fee_payment_required', True)
                
                # Student can access if: no fee required OR has approved payment
                can_access_courses = not fee_payment_required or has_approved_payment
                
                if not can_access_courses:
                    return jsonify({
                        'error': 'Fee payment pending approval',
                        'requires_fee_approval': True,
                        'student_id': str(user['_id']),
                        'message': 'Please wait for fee payment approval to access courses. You can still access the fee payment section.'
                    }), 403
            
            if data.get('role') == 'student' and user['role'] != 'student':
                return jsonify({'error': 'Invalid student account'}), 401
            
            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            session.permanent = True
            
            user_data = serialize_doc(user)
            user_data.pop('password', None)
            
            # Add fee payment status for students
            if user['role'] == 'student':
                fee_payments = list(db.fee_payments.find({
                    'student_id': user['_id']
                }))
                has_approved_payment = any(p['status'] == 'approved' for p in fee_payments)
                fee_payment_required = user.get('fee_payment_required', True)
                
                user_data['has_approved_fee_payment'] = has_approved_payment
                user_data['fee_payment_required'] = fee_payment_required
                user_data['can_access_courses'] = not fee_payment_required or has_approved_payment
                user_data['pending_fee_approval'] = fee_payment_required and not has_approved_payment
            
            return jsonify(user_data)
        
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
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
                'teacher_code': user.get('teacher_code', ''),
                'teacher_id': str(user['_id']),
                'assigned_courses': serialize_list(courses)
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Teacher login error: {e}")
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
            
            user_data = serialize_doc(user)
            user_data.pop('password', None)
            
            return jsonify(user_data)
        
        return jsonify({'error': 'Invalid admin credentials'}), 401
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/check-session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        db = get_db()
        user_id = session['user_id']
        
        # Check fee payment for students
        if session.get('role') == 'student':
            if not check_fee_payment_status(db, user_id):
                return jsonify({
                    'logged_in': True,
                    'user_id': user_id,
                    'role': session.get('role'),
                    'requires_fee_approval': True,
                    'message': 'Fee payment pending approval'
                }), 403
        
        return jsonify({
            'logged_in': True,
            'user_id': user_id,
            'role': session.get('role')
        })
    return jsonify({'logged_in': False})

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
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# ==============================================
# USER PROFILE ROUTES
# ==============================================

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
            logger.error(f"Get user profile error: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.json
            update_data = {}
            
            allowed_fields = ['first_name', 'last_name', 'phone', 'address', 
                            'date_of_birth', 'gender', 'department', 'level', 
                            'specialization', 'fee_payment_required']
            
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
            logger.error(f"Update user profile error: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500

# ==============================================
# FEE PAYMENT ROUTES
# ==============================================

@app.route('/api/fee-payments', methods=['GET', 'POST'])
@login_required
def fee_payments():
    db = get_db()
    
    if request.method == 'GET':
        try:
            if session.get('role') == 'student':
                payments = list(db.fee_payments.find({
                    'student_id': ObjectId(session['user_id'])
                }).sort('payment_date', -1))
            elif session.get('role') == 'admin':
                payments = list(db.fee_payments.find().sort('payment_date', -1))
            else:
                return jsonify({'error': 'Unauthorized'}), 403
            
            # Add student info to payments
            for payment in payments:
                student = db.users.find_one({'_id': payment['student_id']})
                if student:
                    payment['student_name'] = f"{student.get('first_name', '')} {student.get('last_name', '')}"
                    payment['student_id_display'] = student.get('student_id', '')
                    payment['level'] = student.get('level', '')
                    payment['department'] = student.get('department', '')
            
            return jsonify(serialize_list(payments))
        except Exception as e:
            logger.error(f"Get fee payments error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            if session.get('role') != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            
            data = request.json
            
            # Check if student exists
            student = db.users.find_one({
                '_id': ObjectId(data['student_id']),
                'role': 'student'
            })
            if not student:
                return jsonify({'error': 'Student not found'}), 404
            
            # Generate receipt number
            receipt_number = f"REC{datetime.now().strftime('%Y%m%d')}{str(int(time.time() % 1000)).zfill(3)}"
            
            payment = {
                'student_id': ObjectId(data['student_id']),
                'amount': float(data['amount']),
                'payment_date': datetime.fromisoformat(data['payment_date'].replace('Z', '+00:00')),
                'receipt_number': receipt_number,
                'payment_method': data.get('payment_method', 'cash'),
                'academic_year': data.get('academic_year', datetime.now().year),
                'semester': data.get('semester', 1),
                'description': data.get('description', ''),
                'status': 'pending',  # Default to pending, needs admin approval
                'created_by': ObjectId(session['user_id']),
                'created_at': datetime.utcnow(),
                'approved_by': None,
                'approved_at': None,
                'notes': data.get('notes', '')
            }
            
            result = db.fee_payments.insert_one(payment)
            
            # Create notification for admin
            admins = list(db.users.find({'role': 'admin'}))
            for admin in admins:
                create_notification(
                    db,
                    str(admin['_id']),
                    'New Fee Payment Recorded',
                    f'Student {student.get("first_name")} {student.get("last_name")} ({student.get("student_id")}) has made a fee payment of ${payment["amount"]}. Requires approval.',
                    'fee_payment',
                    str(result.inserted_id)
                )
            
            # Create notification for student
            create_notification(
                db,
                data['student_id'],
                'Fee Payment Recorded',
                f'Your fee payment of ${payment["amount"]} has been recorded. Waiting for admin approval.',
                'fee_payment',
                str(result.inserted_id)
            )
            
            return jsonify({
                'message': 'Fee payment recorded successfully',
                'receipt_number': receipt_number,
                'payment_id': str(result.inserted_id)
            }), 201
        except Exception as e:
            logger.error(f"Create fee payment error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/fee-payments/<payment_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def fee_payment_detail(payment_id):
    db = get_db()
    
    if request.method == 'GET':
        try:
            payment = db.fee_payments.find_one({'_id': ObjectId(payment_id)})
            if not payment:
                return jsonify({'error': 'Payment not found'}), 404
            
            # Check authorization
            if session.get('role') == 'student' and str(payment['student_id']) != session['user_id']:
                return jsonify({'error': 'Unauthorized'}), 403
            
            # Add student and admin info
            payment = serialize_doc(payment)
            student = db.users.find_one({'_id': ObjectId(payment['student_id'])})
            if student:
                payment['student_name'] = f"{student.get('first_name', '')} {student.get('last_name', '')}"
                payment['student_id_display'] = student.get('student_id', '')
                payment['student_email'] = student.get('email', '')
                payment['student_phone'] = student.get('phone', '')
            
            if payment.get('created_by'):
                creator = db.users.find_one({'_id': ObjectId(payment['created_by'])})
                if creator:
                    payment['created_by_name'] = f"{creator.get('first_name', '')} {creator.get('last_name', '')}"
            
            if payment.get('approved_by'):
                approver = db.users.find_one({'_id': ObjectId(payment['approved_by'])})
                if approver:
                    payment['approved_by_name'] = f"{approver.get('first_name', '')} {approver.get('last_name', '')}"
            
            return jsonify(payment)
        except Exception as e:
            logger.error(f"Get fee payment detail error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
        try:
            if session.get('role') != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            
            data = request.json
            payment = db.fee_payments.find_one({'_id': ObjectId(payment_id)})
            if not payment:
                return jsonify({'error': 'Payment not found'}), 404
            
            update_data = {}
            allowed_fields = ['amount', 'payment_date', 'payment_method', 'academic_year', 
                            'semester', 'description', 'notes', 'status']
            
            for field in allowed_fields:
                if field in data:
                    if field == 'payment_date':
                        update_data[field] = datetime.fromisoformat(data[field].replace('Z', '+00:00'))
                    else:
                        update_data[field] = data[field]
            
            # If status is being updated to approved
            if 'status' in update_data and update_data['status'] == 'approved':
                update_data['approved_by'] = ObjectId(session['user_id'])
                update_data['approved_at'] = datetime.utcnow()
                
                # Create notification for student
                student = db.users.find_one({'_id': payment['student_id']})
                if student:
                    create_notification(
                        db,
                        str(payment['student_id']),
                        'Fee Payment Approved',
                        f'Your fee payment of ${payment["amount"]} has been approved. You now have full access to the system.',
                        'fee_payment_approved',
                        payment_id
                    )
            
            db.fee_payments.update_one(
                {'_id': ObjectId(payment_id)},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Payment updated successfully'})
        except Exception as e:
            logger.error(f"Update fee payment error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            if session.get('role') != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            
            result = db.fee_payments.delete_one({'_id': ObjectId(payment_id)})
            if result.deleted_count == 0:
                return jsonify({'error': 'Payment not found'}), 404
            
            return jsonify({'message': 'Payment deleted successfully'})
        except Exception as e:
            logger.error(f"Delete fee payment error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/fee-payments/student/<student_id>', methods=['GET'])
@login_required
def student_fee_payments(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        payments = list(db.fee_payments.find({
            'student_id': ObjectId(student_id)
        }).sort('payment_date', -1))
        
        # Add status summary
        total_paid = sum(p['amount'] for p in payments if p['status'] == 'approved')
        pending_payments = [p for p in payments if p['status'] == 'pending']
        approved_payments = [p for p in payments if p['status'] == 'approved']
        
        # Get fee structure if available
        student = db.users.find_one({'_id': ObjectId(student_id)})
        fee_structure = None
        if student:
            fee_structure = db.fee_structures.find_one({
                'level': student.get('level'),
                'department': student.get('department'),
                'academic_year': datetime.now().year
            })
        
        return jsonify({
            'payments': serialize_list(payments),
            'summary': {
                'total_paid': total_paid,
                'pending_count': len(pending_payments),
                'approved_count': len(approved_payments),
                'has_approved_payment': len(approved_payments) > 0
            },
            'fee_structure': serialize_doc(fee_structure) if fee_structure else None
        })
    except Exception as e:
        logger.error(f"Get student fee payments error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/fee-structures', methods=['GET', 'POST'])
@admin_required
def fee_structures():
    db = get_db()
    
    if request.method == 'GET':
        try:
            fee_structures = list(db.fee_structures.find().sort('academic_year', -1))
            return jsonify(serialize_list(fee_structures))
        except Exception as e:
            logger.error(f"Get fee structures error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Check if fee structure already exists
            existing = db.fee_structures.find_one({
                'level': data['level'],
                'department': data['department'],
                'academic_year': data['academic_year'],
                'semester': data.get('semester', 1)
            })
            
            if existing:
                return jsonify({'error': 'Fee structure already exists for this level, department, and academic year'}), 400
            
            fee_structure = {
                'level': data['level'],
                'department': data['department'],
                'academic_year': data['academic_year'],
                'semester': data.get('semester', 1),
                'tuition_fee': float(data['tuition_fee']),
                'registration_fee': float(data.get('registration_fee', 0)),
                'library_fee': float(data.get('library_fee', 0)),
                'sports_fee': float(data.get('sports_fee', 0)),
                'lab_fee': float(data.get('lab_fee', 0)),
                'other_fees': float(data.get('other_fees', 0)),
                'description': data.get('description', ''),
                'is_active': data.get('is_active', True),
                'created_by': ObjectId(session['user_id']),
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            
            result = db.fee_structures.insert_one(fee_structure)
            
            return jsonify({
                'message': 'Fee structure created successfully',
                'fee_structure_id': str(result.inserted_id)
            }), 201
        except Exception as e:
            logger.error(f"Create fee structure error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/fee-structures/<structure_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def fee_structure_detail(structure_id):
    db = get_db()
    
    if request.method == 'GET':
        try:
            fee_structure = db.fee_structures.find_one({'_id': ObjectId(structure_id)})
            if not fee_structure:
                return jsonify({'error': 'Fee structure not found'}), 404
            
            return jsonify(serialize_doc(fee_structure))
        except Exception as e:
            logger.error(f"Get fee structure detail error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.json
            fee_structure = db.fee_structures.find_one({'_id': ObjectId(structure_id)})
            if not fee_structure:
                return jsonify({'error': 'Fee structure not found'}), 404
            
            update_data = {}
            allowed_fields = ['tuition_fee', 'registration_fee', 'library_fee', 'sports_fee', 
                            'lab_fee', 'other_fees', 'description', 'is_active', 'academic_year']
            
            for field in allowed_fields:
                if field in data:
                    if field in ['tuition_fee', 'registration_fee', 'library_fee', 'sports_fee', 'lab_fee', 'other_fees']:
                        update_data[field] = float(data[field])
                    else:
                        update_data[field] = data[field]
            
            update_data['updated_at'] = datetime.utcnow()
            
            db.fee_structures.update_one(
                {'_id': ObjectId(structure_id)},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Fee structure updated successfully'})
        except Exception as e:
            logger.error(f"Update fee structure error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            result = db.fee_structures.delete_one({'_id': ObjectId(structure_id)})
            if result.deleted_count == 0:
                return jsonify({'error': 'Fee structure not found'}), 404
            
            return jsonify({'message': 'Fee structure deleted successfully'})
        except Exception as e:
            logger.error(f"Delete fee structure error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/fee-payments/approve/<payment_id>', methods=['POST'])
@admin_required
def approve_fee_payment(payment_id):
    try:
        db = get_db()
        
        payment = db.fee_payments.find_one({'_id': ObjectId(payment_id)})
        if not payment:
            return jsonify({'error': 'Payment not found'}), 404
        
        if payment['status'] == 'approved':
            return jsonify({'error': 'Payment already approved'}), 400
        
        # Update payment status
        db.fee_payments.update_one(
            {'_id': ObjectId(payment_id)},
            {'$set': {
                'status': 'approved',
                'approved_by': ObjectId(session['user_id']),
                'approved_at': datetime.utcnow()
            }}
        )
        
        # Create notification for student
        student = db.users.find_one({'_id': payment['student_id']})
        if student:
            create_notification(
                db,
                str(payment['student_id']),
                'Fee Payment Approved',
                f'Your fee payment of ${payment["amount"]} has been approved. You now have full access to the system.',
                'fee_payment_approved',
                payment_id
            )
        
        return jsonify({'message': 'Fee payment approved successfully'})
    except Exception as e:
        logger.error(f"Approve fee payment error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/fee-payments/reject/<payment_id>', methods=['POST'])
@admin_required
def reject_fee_payment(payment_id):
    try:
        data = request.json
        db = get_db()
        
        payment = db.fee_payments.find_one({'_id': ObjectId(payment_id)})
        if not payment:
            return jsonify({'error': 'Payment not found'}), 404
        
        if payment['status'] == 'rejected':
            return jsonify({'error': 'Payment already rejected'}), 400
        
        # Update payment status
        db.fee_payments.update_one(
            {'_id': ObjectId(payment_id)},
            {'$set': {
                'status': 'rejected',
                'rejected_by': ObjectId(session['user_id']),
                'rejected_at': datetime.utcnow(),
                'rejection_reason': data.get('rejection_reason', '')
            }}
        )
        
        # Create notification for student
        student = db.users.find_one({'_id': payment['student_id']})
        if student:
            create_notification(
                db,
                str(payment['student_id']),
                'Fee Payment Rejected',
                f'Your fee payment of ${payment["amount"]} has been rejected. Reason: {data.get("rejection_reason", "No reason provided")}. Please contact administration.',
                'fee_payment_rejected',
                payment_id
            )
        
        return jsonify({'message': 'Fee payment rejected successfully'})
    except Exception as e:
        logger.error(f"Reject fee payment error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# STUDENT ROUTES (with fee payment check)
# ==============================================

@app.route('/api/students/<student_id>/courses', methods=['GET'])
@login_required
def get_student_courses(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Check fee payment for student
        if session.get('role') == 'student':
            db = get_db()
            if not check_fee_payment_status(db, student_id):
                return jsonify({
                    'error': 'Fee payment pending approval',
                    'requires_fee_approval': True,
                    'message': 'Please wait for fee payment approval to access courses'
                }), 403
        
        db = get_db()
        
        enrollments = list(db.enrollments.find(
            {'student_id': ObjectId(student_id)}
        ))
        
        course_ids = [ObjectId(enrollment['course_id']) for enrollment in enrollments]
        courses = list(db.courses.find({'_id': {'$in': course_ids}}))
        
        # Get teacher names for each course
        for course in courses:
            teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
            teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
            teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
            course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        return jsonify(serialize_list(courses))
    except Exception as e:
        logger.error(f"Get student courses error: {e}")
        return jsonify({'error': str(e)}), 500
    
# ==============================================
# STUDENT FEE STATUS ROUTES
# ==============================================

@app.route('/api/students/<student_id>/fee-status', methods=['GET'])
@login_required
def get_student_fee_status(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        # Get student info
        student = db.users.find_one({'_id': ObjectId(student_id)})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Get fee payments
        payments = list(db.fee_payments.find({
            'student_id': ObjectId(student_id)
        }).sort('payment_date', -1))
        
        # Calculate summary
        total_paid = sum(p['amount'] for p in payments if p['status'] == 'approved')
        pending_payments = [p for p in payments if p['status'] == 'pending']
        approved_payments = [p for p in payments if p['status'] == 'approved']
        has_approved_payment = len(approved_payments) > 0
        
        # Get fee structure for student's level and department
        fee_structure = None
        if student.get('level') and student.get('department'):
            fee_structure = db.fee_structures.find_one({
                'level': student.get('level'),
                'department': student.get('department'),
                'is_active': True
            })
        
        return jsonify({
            'student_info': {
                'id': str(student['_id']),
                'first_name': student.get('first_name', ''),
                'last_name': student.get('last_name', ''),
                'student_id': student.get('student_id', ''),
                'level': student.get('level', ''),
                'department': student.get('department', ''),
                'email': student.get('email', '')
            },
            'payments': serialize_list(payments),
            'summary': {
                'total_paid': total_paid,
                'pending_count': len(pending_payments),
                'approved_count': len(approved_payments),
                'has_approved_payment': has_approved_payment,
                'requires_fee_payment': student.get('fee_payment_required', True)
            },
            'fee_structure': serialize_doc(fee_structure) if fee_structure else None,
            'has_access_to_courses': has_approved_payment or not student.get('fee_payment_required', True)
        })
    except Exception as e:
        logger.error(f"Get student fee status error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/students/<student_id>/courses-access', methods=['GET'])
@login_required
def check_student_course_access(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        # Check fee payment status
        has_access = check_fee_payment_status(db, student_id)
        
        # Get student info
        student = db.users.find_one({'_id': ObjectId(student_id)})
        
        return jsonify({
            'has_access': has_access,
            'student_id': str(student['_id']) if student else student_id,
            'requires_fee_approval': not has_access and student.get('fee_payment_required', True) if student else True,
            'message': 'Access granted' if has_access else 'Fee payment approval required'
        })
    except Exception as e:
        logger.error(f"Check student course access error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/students/<student_id>/subject-combination', methods=['GET'])
@login_required
def get_student_subject_combination(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Check fee payment for student
        if session.get('role') == 'student':
            db = get_db()
            if not check_fee_payment_status(db, student_id):
                return jsonify({
                    'error': 'Fee payment pending approval',
                    'requires_fee_approval': True,
                    'message': 'Please wait for fee payment approval to access subject combination'
                }), 403
        
        db = get_db()
        
        # Get student info
        student = db.users.find_one({'_id': ObjectId(student_id)})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Get enrolled courses
        enrollments = list(db.enrollments.find({'student_id': ObjectId(student_id)}))
        course_ids = [ObjectId(enrollment['course_id']) for enrollment in enrollments]
        enrolled_courses = list(db.courses.find({'_id': {'$in': course_ids}}))
        
        # Get all compulsory courses for student's level
        compulsory_courses = list(db.courses.find({
            'level': student.get('level'),
            'is_compulsory': True,
            'status': 'active'
        }))
        
        # Get departmental courses for student's level and department
        departmental_courses = list(db.courses.find({
            'level': student.get('level'),
            'department': student.get('department'),
            'is_compulsory': False,
            'status': 'active'
        }))
        
        # Calculate total credits
        total_credits = sum(course.get('credits', 0) for course in enrolled_courses)
        
        return jsonify({
            'student_info': serialize_doc(student),
            'enrolled_courses': serialize_list(enrolled_courses),
            'compulsory_courses': serialize_list(compulsory_courses),
            'departmental_courses': serialize_list(departmental_courses),
            'total_credits': total_credits
        })
    except Exception as e:
        logger.error(f"Get student subject combination error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/students/<student_id>/grades', methods=['GET'])
@login_required
def get_student_grades(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Check fee payment for student
        if session.get('role') == 'student':
            db = get_db()
            if not check_fee_payment_status(db, student_id):
                return jsonify({
                    'error': 'Fee payment pending approval',
                    'requires_fee_approval': True,
                    'message': 'Please wait for fee payment approval to access grades'
                }), 403
        
        db = get_db()
        course_id = request.args.get('course_id')
        
        query = {'student_id': ObjectId(student_id)}
        if course_id:
            query['course_id'] = ObjectId(course_id)
        
        submissions = list(db.submissions.find(query))
        
        grades = []
        for submission in submissions:
            assignment = db.assignments.find_one({'_id': submission['assignment_id']})
            if assignment:
                grades.append({
                    'assignment_title': assignment.get('title'),
                    'grade': submission.get('grade'),
                    'max_points': assignment.get('max_points'),
                    'feedback': submission.get('feedback'),
                    'submitted_at': submission.get('submitted_at')
                })
        
        return jsonify(grades)
    except Exception as e:
        logger.error(f"Get student grades error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# COURSE ROUTES
# ==============================================

@app.route('/api/courses', methods=['GET'])
@login_required
def get_courses():
    try:
        db = get_db()
        
        # Check fee payment for students
        if session.get('role') == 'student':
            if not check_fee_payment_status(db, session['user_id']):
                return jsonify({
                    'error': 'Fee payment pending approval',
                    'requires_fee_approval': True,
                    'message': 'Please wait for fee payment approval to access courses'
                }), 403
        
        # Get courses based on user role
        if session.get('role') == 'student':
            student = db.users.find_one({'_id': ObjectId(session['user_id'])})
            query = {'status': 'active'}
            
            # Filter by student's level and department
            if student.get('level'):
                query['level'] = student.get('level')
            if student.get('department'):
                query['department'] = student.get('department')
            
            courses = list(db.courses.find(query))
        elif session.get('role') == 'teacher':
            teacher = db.users.find_one({'_id': ObjectId(session['user_id'])})
            teacher_dept = teacher.get('department')
            
            # Get courses for teacher's department and compulsory courses
            courses = list(db.courses.find({
                'status': 'active',
                '$or': [
                    {'department': teacher_dept},
                    {'department': 'all'}
                ]
            }))
        else:
            # Admin sees all courses
            courses = list(db.courses.find())
        
        # Get teacher names for each course
        for course in courses:
            teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
            teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
            teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
            course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        return jsonify(serialize_list(courses))
    except Exception as e:
        logger.error(f"Get courses error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/courses/<course_id>', methods=['GET'])
@login_required
def get_course(course_id):
    try:
        db = get_db()
        
        # Check fee payment for students
        if session.get('role') == 'student':
            if not check_fee_payment_status(db, session['user_id']):
                return jsonify({
                    'error': 'Fee payment pending approval',
                    'requires_fee_approval': True,
                    'message': 'Please wait for fee payment approval to access course details'
                }), 403
        
        course = db.courses.find_one({'_id': ObjectId(course_id)})
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        
        # Get teacher names
        teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
        teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
        teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
        course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        return jsonify(serialize_doc(course))
    except Exception as e:
        logger.error(f"Get course detail error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/courses/for-teacher', methods=['GET'])
@teacher_required
def get_courses_for_teacher():
    try:
        db = get_db()
        
        teacher = db.users.find_one({'_id': ObjectId(session['user_id'])})
        teacher_dept = teacher.get('department')
        
        # Get courses for teacher's department and compulsory courses
        courses = list(db.courses.find({
            'status': 'active',
            '$or': [
                {'department': teacher_dept},
                {'department': 'all'}
            ]
        }))
        
        # Get teacher names for each course
        for course in courses:
            teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
            teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
            teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
            course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        return jsonify(serialize_list(courses))
    except Exception as e:
        logger.error(f"Get courses for teacher error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# ENROLLMENT ROUTES
# ==============================================

@app.route('/api/enroll', methods=['POST'])
@student_required
def enroll_in_course():
    try:
        # Check fee payment
        db = get_db()
        if not check_fee_payment_status(db, session['user_id']):
            return jsonify({
                'error': 'Fee payment pending approval',
                'requires_fee_approval': True,
                'message': 'Please wait for fee payment approval before enrolling in courses'
            }), 403
        
        data = request.json
        
        # Check if already enrolled
        existing = db.enrollments.find_one({
            'student_id': ObjectId(session['user_id']),
            'course_id': ObjectId(data['course_id'])
        })
        
        if existing:
            return jsonify({'error': 'Already enrolled in this course'}), 400
        
        # Check if course exists and is active
        course = db.courses.find_one({'_id': ObjectId(data['course_id'])})
        if not course or course.get('status') != 'active':
            return jsonify({'error': 'Course not available'}), 400
        
        # Check if student meets prerequisites (level/department)
        student = db.users.find_one({'_id': ObjectId(session['user_id'])})
        
        if course.get('level') != 'all' and course.get('level') != student.get('level'):
            return jsonify({'error': 'Course not available for your level'}), 400
        
        if course.get('department') != 'all' and course.get('department') != student.get('department'):
            return jsonify({'error': 'Course not available for your department'}), 400
        
        enrollment = {
            'student_id': ObjectId(session['user_id']),
            'course_id': ObjectId(data['course_id']),
            'enrolled_at': datetime.utcnow()
        }
        
        db.enrollments.insert_one(enrollment)
        
        # Create notification for student
        create_notification(
            db, 
            session['user_id'],
            'Course Enrollment',
            f'You have successfully enrolled in {course.get("title")}',
            'enrollment',
            course['_id']
        )
        
        return jsonify({'message': 'Successfully enrolled in course'})
    except Exception as e:
        logger.error(f"Enroll in course error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/enrollments/<enrollment_id>/student/<student_id>', methods=['DELETE'])
@login_required
def unenroll_from_course(enrollment_id, student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        result = db.enrollments.delete_one({
            '_id': ObjectId(enrollment_id),
            'student_id': ObjectId(student_id)
        })
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Enrollment not found'}), 404
        
        return jsonify({'message': 'Successfully unenrolled from course'})
    except Exception as e:
        logger.error(f"Unenroll from course error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# TEACHER COURSE MANAGEMENT
# ==============================================

@app.route('/api/teachers/<teacher_id>/assign-course', methods=['POST'])
@teacher_required
def assign_course_to_teacher(teacher_id):
    try:
        if session['user_id'] != teacher_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.json
        db = get_db()
        
        course = db.courses.find_one({'_id': ObjectId(data['course_id'])})
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        
        # Check if course is already assigned to this teacher
        existing = db.teacher_courses.find_one({
            'teacher_id': ObjectId(teacher_id),
            'course_id': ObjectId(data['course_id'])
        })
        
        if existing:
            return jsonify({'error': 'Course already assigned to this teacher'}), 400
        
        # Check if course has teacher lock and is already assigned to another teacher
        if course.get('teacher_lock') == True:
            existing_teacher = db.teacher_courses.find_one({
                'course_id': ObjectId(data['course_id'])
            })
            
            if existing_teacher:
                # Create approval request
                approval_request = {
                    'teacher_id': ObjectId(teacher_id),
                    'course_id': ObjectId(data['course_id']),
                    'current_teacher_id': existing_teacher['teacher_id'],
                    'status': 'pending',
                    'requested_at': datetime.utcnow()
                }
                
                db.course_approval_requests.insert_one(approval_request)
                
                # Notify admin
                admins = list(db.users.find({'role': 'admin'}))
                teacher = db.users.find_one({'_id': ObjectId(teacher_id)})
                
                for admin in admins:
                    create_notification(
                        db,
                        str(admin['_id']),
                        'Course Approval Request',
                        f'Teacher {teacher.get("first_name")} {teacher.get("last_name")} requested to teach {course.get("title")}. Course is currently assigned to another teacher.',
                        'approval_request',
                        str(approval_request['_id'])
                    )
                
                return jsonify({
                    'message': 'Approval request sent to admin',
                    'requires_approval': True
                })
        
        # Assign course to teacher
        teacher_course = {
            'teacher_id': ObjectId(teacher_id),
            'course_id': ObjectId(data['course_id']),
            'assigned_at': datetime.utcnow()
        }
        
        db.teacher_courses.insert_one(teacher_course)
        
        return jsonify({'message': 'Course assigned successfully'})
    except Exception as e:
        logger.error(f"Assign course to teacher error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/teachers/<teacher_id>/unassign-course/<course_id>', methods=['DELETE'])
@teacher_required
def unassign_course_from_teacher(teacher_id, course_id):
    try:
        if session['user_id'] != teacher_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        result = db.teacher_courses.delete_one({
            'teacher_id': ObjectId(teacher_id),
            'course_id': ObjectId(course_id)
        })
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Course assignment not found'}), 404
        
        return jsonify({'message': 'Course unassigned successfully'})
    except Exception as e:
        logger.error(f"Unassign course from teacher error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/teachers/<teacher_id>/courses', methods=['GET'])
@login_required
def get_teacher_courses(teacher_id):
    try:
        if session['user_id'] != teacher_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        teacher_courses = list(db.teacher_courses.find({'teacher_id': ObjectId(teacher_id)}))
        course_ids = [tc['course_id'] for tc in teacher_courses]
        courses = list(db.courses.find({'_id': {'$in': course_ids}}))
        
        return jsonify(serialize_list(courses))
    except Exception as e:
        logger.error(f"Get teacher courses error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# ASSIGNMENT ROUTES
# ==============================================

@app.route('/api/assignments', methods=['GET', 'POST'])
@login_required
def assignments():
    db = get_db()
    
    if request.method == 'GET':
        try:
            course_id = request.args.get('course_id')
            query = {}
            
            if course_id:
                query['course_id'] = ObjectId(course_id)
            
            # Check fee payment for students
            if session.get('role') == 'student':
                if not check_fee_payment_status(db, session['user_id']):
                    return jsonify({
                        'error': 'Fee payment pending approval',
                        'requires_fee_approval': True,
                        'message': 'Please wait for fee payment approval to access assignments'
                    }), 403
                
                # Only show assignments for courses student is enrolled in
                enrollments = list(db.enrollments.find({'student_id': ObjectId(session['user_id'])}))
                enrolled_course_ids = [e['course_id'] for e in enrollments]
                query['course_id'] = {'$in': enrolled_course_ids}
            
            assignments = list(db.assignments.find(query).sort('due_date', 1))
            return jsonify(serialize_list(assignments))
        except Exception as e:
            logger.error(f"Get assignments error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            if session.get('role') != 'teacher':
                return jsonify({'error': 'Teacher access required'}), 403
            
            data = request.json
            
            assignment = {
                'course_id': ObjectId(data['course_id']),
                'teacher_id': ObjectId(session['user_id']),
                'title': data['title'],
                'description': data['description'],
                'due_date': datetime.fromisoformat(data['due_date'].replace('Z', '+00:00')),
                'max_points': int(data['max_points']),
                'created_at': datetime.utcnow()
            }
            
            result = db.assignments.insert_one(assignment)
            
            # Create notifications for enrolled students
            enrollments = list(db.enrollments.find({'course_id': assignment['course_id']}))
            course = db.courses.find_one({'_id': assignment['course_id']})
            
            for enrollment in enrollments:
                create_notification(
                    db,
                    str(enrollment['student_id']),
                    'New Assignment',
                    f'New assignment "{assignment["title"]}" posted in {course.get("title", "Course")}. Due: {assignment["due_date"].strftime("%Y-%m-%d %H:%M")}',
                    'assignment',
                    str(result.inserted_id)
                )
            
            return jsonify({'message': 'Assignment created successfully'})
        except Exception as e:
            logger.error(f"Create assignment error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<assignment_id>', methods=['GET'])
@login_required
def get_assignment(assignment_id):
    try:
        db = get_db()
        
        # Check fee payment for students
        if session.get('role') == 'student':
            if not check_fee_payment_status(db, session['user_id']):
                return jsonify({
                    'error': 'Fee payment pending approval',
                    'requires_fee_approval': True,
                    'message': 'Please wait for fee payment approval to access assignment'
                }), 403
        
        assignment = db.assignments.find_one({'_id': ObjectId(assignment_id)})
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        return jsonify(serialize_doc(assignment))
    except Exception as e:
        logger.error(f"Get assignment detail error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# SUBMISSION ROUTES
# ==============================================

@app.route('/api/submissions', methods=['POST'])
@student_required
def create_submission():
    try:
        # Check fee payment
        db = get_db()
        if not check_fee_payment_status(db, session['user_id']):
            return jsonify({
                'error': 'Fee payment pending approval',
                'requires_fee_approval': True,
                'message': 'Please wait for fee payment approval before submitting assignments'
            }), 403
        
        data = request.json
        
        # Check if assignment exists and is not past due
        assignment = db.assignments.find_one({'_id': ObjectId(data['assignment_id'])})
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        if assignment['due_date'] < datetime.utcnow():
            return jsonify({'error': 'Submission is past due'}), 400
        
        # Check if already submitted
        existing = db.submissions.find_one({
            'assignment_id': ObjectId(data['assignment_id']),
            'student_id': ObjectId(session['user_id'])
        })
        
        if existing:
            return jsonify({'error': 'Already submitted this assignment'}), 400
        
        submission = {
            'assignment_id': ObjectId(data['assignment_id']),
            'student_id': ObjectId(session['user_id']),
            'content': data['content'],
            'submitted_at': datetime.utcnow(),
            'grade': None,
            'feedback': None
        }
        
        db.submissions.insert_one(submission)
        
        # Create notification for teacher
        teacher_courses = list(db.teacher_courses.find({'course_id': assignment['course_id']}))
        course = db.courses.find_one({'_id': assignment['course_id']})
        student = db.users.find_one({'_id': ObjectId(session['user_id'])})
        
        for teacher_course in teacher_courses:
            create_notification(
                db,
                str(teacher_course['teacher_id']),
                'New Submission',
                f'{student.get("first_name", "Student")} submitted {assignment["title"]} in {course.get("title", "Course")}',
                'submission',
                str(submission['_id'])
            )
        
        return jsonify({'message': 'Submission created successfully'})
    except Exception as e:
        logger.error(f"Create submission error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<assignment_id>/submissions', methods=['GET'])
@teacher_required
def get_submissions(assignment_id):
    try:
        db = get_db()
        
        submissions = list(db.submissions.find({'assignment_id': ObjectId(assignment_id)}))
        
        # Add student names
        for submission in submissions:
            student = db.users.find_one({'_id': submission['student_id']})
            if student:
                submission['student_name'] = f"{student.get('first_name', '')} {student.get('last_name', '')}"
        
        return jsonify(serialize_list(submissions))
    except Exception as e:
        logger.error(f"Get submissions error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/grade', methods=['POST'])
@teacher_required
def grade_submission():
    try:
        data = request.json
        db = get_db()
        
        # Update submission with grade
        db.submissions.update_one(
            {
                'assignment_id': ObjectId(data['assignment_id']),
                'student_id': ObjectId(data['student_id'])
            },
            {
                '$set': {
                    'grade': int(data['grade']),
                    'feedback': data.get('feedback', ''),
                    'graded_at': datetime.utcnow()
                }
            }
        )
        
        # Create notification for student
        assignment = db.assignments.find_one({'_id': ObjectId(data['assignment_id'])})
        course = db.courses.find_one({'_id': assignment['course_id']})
        teacher = db.users.find_one({'_id': ObjectId(session['user_id'])})
        
        create_notification(
            db,
            data['student_id'],
            'Assignment Graded',
            f'Your assignment "{assignment["title"]}" in {course.get("title", "Course")} has been graded by {teacher.get("first_name", "Teacher")} {teacher.get("last_name", "")}. Grade: {data["grade"]}',
            'grade',
            data['assignment_id']
        )
        
        return jsonify({'message': 'Grade submitted successfully'})
    except Exception as e:
        logger.error(f"Grade submission error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# ANNOUNCEMENT ROUTES
# ==============================================

@app.route('/api/announcements', methods=['GET', 'POST'])
@login_required
def announcements():
    db = get_db()
    
    if request.method == 'GET':
        try:
            # Check fee payment for students
            if session.get('role') == 'student':
                if not check_fee_payment_status(db, session['user_id']):
                    return jsonify({
                        'error': 'Fee payment pending approval',
                        'requires_fee_approval': True,
                        'message': 'Please wait for fee payment approval to access announcements'
                    }), 403
            
            announcements = list(db.announcements.find().sort('created_at', -1).limit(20))
            
            # Add teacher and course info
            for ann in announcements:
                teacher = db.users.find_one({'_id': ann['teacher_id']})
                if teacher:
                    ann['teacher_name'] = f"{teacher.get('first_name', '')} {teacher.get('last_name', '')}"
                
                course = db.courses.find_one({'_id': ann['course_id']})
                if course:
                    ann['course_title'] = course.get('title', '')
            
            return jsonify(serialize_list(announcements))
        except Exception as e:
            logger.error(f"Get announcements error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            if session.get('role') != 'teacher':
                return jsonify({'error': 'Teacher access required'}), 403
            
            data = request.json
            
            announcement = {
                'course_id': ObjectId(data['course_id']),
                'teacher_id': ObjectId(session['user_id']),
                'title': data['title'],
                'content': data['content'],
                'created_at': datetime.utcnow()
            }
            
            result = db.announcements.insert_one(announcement)
            
            # Create notifications for enrolled students
            enrollments = list(db.enrollments.find({'course_id': announcement['course_id']}))
            course = db.courses.find_one({'_id': announcement['course_id']})
            teacher = db.users.find_one({'_id': ObjectId(session['user_id'])})
            
            for enrollment in enrollments:
                create_notification(
                    db,
                    str(enrollment['student_id']),
                    'New Announcement',
                    f'New announcement "{announcement["title"]}" from {teacher.get("first_name", "Teacher")} in {course.get("title", "Course")}',
                    'announcement',
                    str(result.inserted_id)
                )
            
            return jsonify({'message': 'Announcement posted successfully'})
        except Exception as e:
            logger.error(f"Create announcement error: {e}")
            return jsonify({'error': str(e)}), 500

# ==============================================
# MATERIALS ROUTES
# ==============================================

@app.route('/api/materials', methods=['GET', 'POST'])
@login_required
def materials():
    db = get_db()
    
    if request.method == 'GET':
        try:
            course_id = request.args.get('course_id')
            query = {}
            
            if course_id:
                query['course_id'] = ObjectId(course_id)
            
            # Check fee payment for students
            if session.get('role') == 'student':
                if not check_fee_payment_status(db, session['user_id']):
                    return jsonify({
                        'error': 'Fee payment pending approval',
                        'requires_fee_approval': True,
                        'message': 'Please wait for fee payment approval to access materials'
                    }), 403
            
            materials = list(db.materials.find(query).sort('created_at', -1))
            
            # Add teacher info
            for mat in materials:
                teacher = db.users.find_one({'_id': mat['teacher_id']})
                if teacher:
                    mat['teacher_name'] = f"{teacher.get('first_name', '')} {teacher.get('last_name', '')}"
            
            return jsonify(serialize_list(materials))
        except Exception as e:
            logger.error(f"Get materials error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            if session.get('role') != 'teacher':
                return jsonify({'error': 'Teacher access required'}), 403
            
            data = request.json
            
            material = {
                'course_id': ObjectId(data['course_id']),
                'teacher_id': ObjectId(session['user_id']),
                'title': data['title'],
                'description': data.get('description', ''),
                'material_type': data['material_type'],
                'file_url': data.get('file_url', ''),
                'created_at': datetime.utcnow()
            }
            
            result = db.materials.insert_one(material)
            
            # Create notifications for enrolled students
            enrollments = list(db.enrollments.find({'course_id': material['course_id']}))
            course = db.courses.find_one({'_id': material['course_id']})
            
            for enrollment in enrollments:
                create_notification(
                    db,
                    str(enrollment['student_id']),
                    'New Course Material',
                    f'New material "{material["title"]}" added to {course.get("title", "Course")}',
                    'material',
                    str(result.inserted_id)
                )
            
            return jsonify({'message': 'Material added successfully'})
        except Exception as e:
            logger.error(f"Create material error: {e}")
            return jsonify({'error': str(e)}), 500

# ==============================================
# DISCUSSION ROUTES
# ==============================================

@app.route('/api/discussions', methods=['GET', 'POST'])
@login_required
def discussions():
    db = get_db()
    
    if request.method == 'GET':
        try:
            course_id = request.args.get('course_id')
            query = {}
            
            if course_id:
                query['course_id'] = ObjectId(course_id)
            
            # Check fee payment for students
            if session.get('role') == 'student':
                if not check_fee_payment_status(db, session['user_id']):
                    return jsonify({
                        'error': 'Fee payment pending approval',
                        'requires_fee_approval': True,
                        'message': 'Please wait for fee payment approval to access discussions'
                    }), 403
            
            posts = list(db.discussion_posts.find(query).sort('created_at', -1))
            
            # Add author info
            for post in posts:
                author = db.users.find_one({'_id': post['user_id']})
                if author:
                    post['author_name'] = f"{author.get('first_name', '')} {author.get('last_name', '')}"
                    post['role'] = author.get('role', '')
            
            return jsonify(serialize_list(posts))
        except Exception as e:
            logger.error(f"Get discussions error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            # Check fee payment for students
            if session.get('role') == 'student':
                if not check_fee_payment_status(db, session['user_id']):
                    return jsonify({
                        'error': 'Fee payment pending approval',
                        'requires_fee_approval': True,
                        'message': 'Please wait for fee payment approval before posting discussions'
                    }), 403
            
            data = request.json
            
            # Verify user is enrolled in/teaching this course
            course_id = ObjectId(data['course_id'])
            
            if session.get('role') == 'student':
                enrollment = db.enrollments.find_one({
                    'student_id': ObjectId(session['user_id']),
                    'course_id': course_id
                })
                if not enrollment:
                    return jsonify({'error': 'You are not enrolled in this course'}), 403
            elif session.get('role') == 'teacher':
                teacher_course = db.teacher_courses.find_one({
                    'teacher_id': ObjectId(session['user_id']),
                    'course_id': course_id
                })
                if not teacher_course:
                    return jsonify({'error': 'You are not assigned to this course'}), 403
            
            post = {
                'course_id': course_id,
                'user_id': ObjectId(session['user_id']),
                'title': data['title'],
                'content': data['content'],
                'created_at': datetime.utcnow()
            }
            
            db.discussion_posts.insert_one(post)
            
            return jsonify({'message': 'Discussion post created successfully'})
        except Exception as e:
            logger.error(f"Create discussion post error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/discussions/<post_id>/replies', methods=['GET', 'POST'])
@login_required
def discussion_replies(post_id):
    db = get_db()
    
    if request.method == 'GET':
        try:
            # Check fee payment for students
            if session.get('role') == 'student':
                if not check_fee_payment_status(db, session['user_id']):
                    return jsonify({
                        'error': 'Fee payment pending approval',
                        'requires_fee_approval': True,
                        'message': 'Please wait for fee payment approval to access discussions'
                    }), 403
            
            replies = list(db.discussion_replies.find({'post_id': ObjectId(post_id)}).sort('created_at', 1))
            
            # Add author info
            for reply in replies:
                author = db.users.find_one({'_id': reply['user_id']})
                if author:
                    reply['author_name'] = f"{author.get('first_name', '')} {author.get('last_name', '')}"
                    reply['role'] = author.get('role', '')
            
            return jsonify(serialize_list(replies))
        except Exception as e:
            logger.error(f"Get discussion replies error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            # Check fee payment for students
            if session.get('role') == 'student':
                if not check_fee_payment_status(db, session['user_id']):
                    return jsonify({
                        'error': 'Fee payment pending approval',
                        'requires_fee_approval': True,
                        'message': 'Please wait for fee payment approval before replying to discussions'
                    }), 403
            
            data = request.json
            
            # Verify user can access this discussion
            post = db.discussion_posts.find_one({'_id': ObjectId(post_id)})
            if not post:
                return jsonify({'error': 'Post not found'}), 404
            
            if session.get('role') == 'student':
                enrollment = db.enrollments.find_one({
                    'student_id': ObjectId(session['user_id']),
                    'course_id': post['course_id']
                })
                if not enrollment:
                    return jsonify({'error': 'You are not enrolled in this course'}), 403
            elif session.get('role') == 'teacher':
                teacher_course = db.teacher_courses.find_one({
                    'teacher_id': ObjectId(session['user_id']),
                    'course_id': post['course_id']
                })
                if not teacher_course:
                    return jsonify({'error': 'You are not assigned to this course'}), 403
            
            reply = {
                'post_id': ObjectId(post_id),
                'user_id': ObjectId(session['user_id']),
                'content': data['content'],
                'created_at': datetime.utcnow()
            }
            
            db.discussion_replies.insert_one(reply)
            
            # Notify post author if they're not the one replying
            if str(post['user_id']) != session['user_id']:
                post_author = db.users.find_one({'_id': post['user_id']})
                reply_author = db.users.find_one({'_id': ObjectId(session['user_id'])})
                
                create_notification(
                    db,
                    str(post['user_id']),
                    'New Reply to Your Post',
                    f'{reply_author.get("first_name", "Someone")} replied to your post "{post.get("title", "")}"',
                    'discussion_reply',
                    post_id
                )
            
            return jsonify({'message': 'Reply posted successfully'})
        except Exception as e:
            logger.error(f"Create discussion reply error: {e}")
            return jsonify({'error': str(e)}), 500

# ==============================================
# NOTIFICATION ROUTES
# ==============================================

@app.route('/api/notifications/<user_id>', methods=['GET'])
@login_required
def get_notifications(user_id):
    try:
        if session['user_id'] != user_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        notifications = list(db.notifications.find(
            {'user_id': ObjectId(user_id)}
        ).sort('created_at', -1))
        
        return jsonify(serialize_list(notifications))
    except Exception as e:
        logger.error(f"Get notifications error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        db = get_db()
        
        notification = db.notifications.find_one({'_id': ObjectId(notification_id)})
        if not notification:
            return jsonify({'error': 'Notification not found'}), 404
        
        if str(notification['user_id']) != session['user_id'] and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.notifications.update_one(
            {'_id': ObjectId(notification_id)},
            {'$set': {'is_read': True}}
        )
        
        return jsonify({'message': 'Notification marked as read'})
    except Exception as e:
        logger.error(f"Mark notification read error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/<user_id>/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read(user_id):
    try:
        if session['user_id'] != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        db.notifications.update_many(
            {'user_id': ObjectId(user_id), 'is_read': False},
            {'$set': {'is_read': True}}
        )
        
        return jsonify({'message': 'All notifications marked as read'})
    except Exception as e:
        logger.error(f"Mark all notifications read error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/<user_id>/clear-all', methods=['DELETE'])
@login_required
def clear_all_notifications(user_id):
    try:
        if session['user_id'] != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        db.notifications.delete_many({'user_id': ObjectId(user_id)})
        
        return jsonify({'message': 'All notifications cleared'})
    except Exception as e:
        logger.error(f"Clear all notifications error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# ADMIN ROUTES
# ==============================================

@app.route('/api/admin/students', methods=['GET'])
@admin_required
def admin_get_students():
    try:
        db = get_db()
        
        students = list(db.users.find({'role': 'student'}).sort('created_at', -1))
        
        # Add fee payment status
        for student in students:
            fee_payment = db.fee_payments.find_one({
                'student_id': student['_id'],
                'status': 'approved'
            })
            student['has_approved_fee_payment'] = fee_payment is not None
            
            # Get enrolled courses count
            enrollment_count = db.enrollments.count_documents({'student_id': student['_id']})
            student['enrollment_count'] = enrollment_count
        
        return jsonify(serialize_list(students))
    except Exception as e:
        logger.error(f"Admin get students error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/students/<student_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_manage_student(student_id):
    db = get_db()
    
    if request.method == 'PUT':
        try:
            data = request.json
            
            update_data = {}
            allowed_fields = ['first_name', 'last_name', 'email', 'student_id', 
                            'phone', 'address', 'date_of_birth', 'gender', 
                            'department', 'level', 'status', 'fee_payment_required']
            
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if 'password' in data and data['password']:
                update_data['password'] = generate_password_hash(data['password'])
            
            db.users.update_one(
                {'_id': ObjectId(student_id), 'role': 'student'},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Student updated successfully'})
        except Exception as e:
            logger.error(f"Admin update student error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            # Delete student and related data
            db.users.delete_one({'_id': ObjectId(student_id), 'role': 'student'})
            db.enrollments.delete_many({'student_id': ObjectId(student_id)})
            db.submissions.delete_many({'student_id': ObjectId(student_id)})
            db.fee_payments.delete_many({'student_id': ObjectId(student_id)})
            
            return jsonify({'message': 'Student deleted successfully'})
        except Exception as e:
            logger.error(f"Admin delete student error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/students/<student_id>/status', methods=['POST'])
@admin_required
def update_student_status(student_id):
    try:
        data = request.json
        db = get_db()
        
        db.users.update_one(
            {'_id': ObjectId(student_id), 'role': 'student'},
            {'$set': {'status': data['status']}}
        )
        
        return jsonify({'message': 'Student status updated successfully'})
    except Exception as e:
        logger.error(f"Update student status error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/teachers', methods=['GET', 'POST'])
@admin_required
def admin_teachers():
    db = get_db()
    
    if request.method == 'GET':
        try:
            teachers = list(db.users.find({'role': 'teacher'}).sort('created_at', -1))
            
            # Add course count for each teacher
            for teacher in teachers:
                course_count = db.teacher_courses.count_documents({'teacher_id': teacher['_id']})
                teacher['course_count'] = course_count
            
            return jsonify(serialize_list(teachers))
        except Exception as e:
            logger.error(f"Admin get teachers error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Check if teacher code already exists
            existing_code = db.users.find_one({'teacher_code': data['teacher_code']})
            if existing_code:
                return jsonify({'error': 'Teacher code already exists'}), 400
            
            # Check if email already exists
            existing_email = db.users.find_one({'email': data['email']})
            if existing_email:
                return jsonify({'error': 'Email already exists'}), 400
            
            teacher = {
                'email': data['email'],
                'password': generate_password_hash(data['password']),
                'first_name': data['first_name'],
                'last_name': data['last_name'],
                'role': 'teacher',
                'teacher_code': data['teacher_code'],
                'department': data.get('department', ''),
                'status': 'active',
                'created_at': datetime.utcnow()
            }
            
            result = db.users.insert_one(teacher)
            
            return jsonify({
                'message': 'Teacher account created successfully',
                'teacher_id': str(result.inserted_id)
            }), 201
        except Exception as e:
            logger.error(f"Admin create teacher error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/teachers/<teacher_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def admin_teacher_detail(teacher_id):
    db = get_db()
    
    if request.method == 'GET':
        try:
            teacher = db.users.find_one({'_id': ObjectId(teacher_id), 'role': 'teacher'})
            if not teacher:
                return jsonify({'error': 'Teacher not found'}), 404
            
            # Get teacher's courses
            teacher_courses = list(db.teacher_courses.find({'teacher_id': ObjectId(teacher_id)}))
            course_ids = [tc['course_id'] for tc in teacher_courses]
            courses = list(db.courses.find({'_id': {'$in': course_ids}}))
            
            # Get teacher's announcements
            announcements = list(db.announcements.find({'teacher_id': ObjectId(teacher_id)}).sort('created_at', -1).limit(10))
            
            # Get teacher's assignments
            assignments = list(db.assignments.find({'teacher_id': ObjectId(teacher_id)}).sort('created_at', -1).limit(10))
            
            return jsonify({
                'teacher': serialize_doc(teacher),
                'courses': serialize_list(courses),
                'announcements': serialize_list(announcements),
                'assignments': serialize_list(assignments)
            })
        except Exception as e:
            logger.error(f"Admin get teacher detail error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.json
            
            update_data = {}
            allowed_fields = ['first_name', 'last_name', 'email', 'teacher_code', 
                            'department', 'specialization', 'phone', 'address', 
                            'date_of_birth', 'gender', 'status']
            
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if 'password' in data and data['password']:
                update_data['password'] = generate_password_hash(data['password'])
            
            db.users.update_one(
                {'_id': ObjectId(teacher_id), 'role': 'teacher'},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Teacher updated successfully'})
        except Exception as e:
            logger.error(f"Admin update teacher error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            # Delete teacher and related data
            db.users.delete_one({'_id': ObjectId(teacher_id), 'role': 'teacher'})
            db.teacher_courses.delete_many({'teacher_id': ObjectId(teacher_id)})
            db.announcements.delete_many({'teacher_id': ObjectId(teacher_id)})
            db.assignments.delete_many({'teacher_id': ObjectId(teacher_id)})
            db.materials.delete_many({'teacher_id': ObjectId(teacher_id)})
            
            return jsonify({'message': 'Teacher deleted successfully'})
        except Exception as e:
            logger.error(f"Admin delete teacher error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/teachers/<teacher_id>/details', methods=['GET'])
@admin_required
def admin_teacher_details(teacher_id):
    try:
        db = get_db()
        
        teacher = db.users.find_one({'_id': ObjectId(teacher_id), 'role': 'teacher'})
        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404
        
        # Get teacher's courses
        teacher_courses = list(db.teacher_courses.find({'teacher_id': ObjectId(teacher_id)}))
        course_ids = [tc['course_id'] for tc in teacher_courses]
        courses = list(db.courses.find({'_id': {'$in': course_ids}}))
        
        # Get teacher's announcements
        announcements = list(db.announcements.find({'teacher_id': ObjectId(teacher_id)}).sort('created_at', -1).limit(10))
        
        # Get teacher's assignments
        assignments = list(db.assignments.find({'teacher_id': ObjectId(teacher_id)}).sort('created_at', -1).limit(10))
        
        return jsonify({
            'teacher': serialize_doc(teacher),
            'courses': serialize_list(courses),
            'announcements': serialize_list(announcements),
            'assignments': serialize_list(assignments)
        })
    except Exception as e:
        logger.error(f"Admin get teacher details error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/courses', methods=['GET', 'POST'])
@admin_required
def admin_courses():
    db = get_db()
    
    if request.method == 'GET':
        try:
            courses = list(db.courses.find().sort('created_at', -1))
            
            # Get teacher names for each course
            for course in courses:
                teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
                teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
                teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
                course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
                
                # Get enrollment count
                enrollment_count = db.enrollments.count_documents({'course_id': course['_id']})
                course['enrollment_count'] = enrollment_count
            
            return jsonify(serialize_list(courses))
        except Exception as e:
            logger.error(f"Admin get courses error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Check if course code already exists
            existing = db.courses.find_one({'course_code': data['course_code']})
            if existing:
                return jsonify({'error': 'Course code already exists'}), 400
            
            course = {
                'title': data['title'],
                'course_code': data['course_code'],
                'description': data['description'],
                'credits': int(data['credits']),
                'teacher_lock': bool(data.get('teacher_lock', True)),
                'status': 'active',
                'level': data.get('level', 'all'),
                'department': data.get('department', 'all'),
                'is_compulsory': data.get('is_compulsory', False),
                'created_at': datetime.utcnow()
            }
            
            result = db.courses.insert_one(course)
            
            # Auto-enroll students if it's a compulsory course
            if course['is_compulsory'] and course['level'] != 'all':
                # Find students in this level
                students = list(db.users.find({
                    'role': 'student',
                    'level': course['level']
                }))
                
                enrollments_to_insert = []
                for student in students:
                    enrollments_to_insert.append({
                        'student_id': student['_id'],
                        'course_id': result.inserted_id,
                        'enrolled_at': datetime.utcnow()
                    })
                
                if enrollments_to_insert:
                    try:
                        db.enrollments.insert_many(enrollments_to_insert, ordered=False)
                    except:
                        pass
                
                # Create notifications for enrolled students
                for student in students:
                    create_notification(
                        db,
                        str(student['_id']),
                        'Auto-enrolled in Compulsory Course',
                        f'You have been auto-enrolled in compulsory course: {course["title"]}',
                        'enrollment',
                        str(result.inserted_id)
                    )
            
            return jsonify({
                'message': 'Course created successfully',
                'course_id': str(result.inserted_id),
                'auto_enrolled_count': len(students) if course.get('is_compulsory') else 0
            }), 201
        except Exception as e:
            logger.error(f"Admin create course error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/courses/<course_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def admin_course_detail(course_id):
    db = get_db()
    
    if request.method == 'GET':
        try:
            course = db.courses.find_one({'_id': ObjectId(course_id)})
            if not course:
                return jsonify({'error': 'Course not found'}), 404
            
            # Get teacher names
            teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
            teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
            teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
            course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
            
            # Get enrollment count
            enrollment_count = db.enrollments.count_documents({'course_id': course['_id']})
            course['enrollment_count'] = enrollment_count
            
            # Get enrolled students
            enrollments = list(db.enrollments.find({'course_id': course['_id']}))
            student_ids = [e['student_id'] for e in enrollments]
            students = list(db.users.find({'_id': {'$in': student_ids}}))
            course['students'] = serialize_list(students)
            
            return jsonify(serialize_doc(course))
        except Exception as e:
            logger.error(f"Admin get course detail error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.json
            
            update_data = {}
            allowed_fields = ['title', 'course_code', 'description', 'credits', 
                            'teacher_lock', 'status', 'level', 'department', 
                            'is_compulsory']
            
            for field in allowed_fields:
                if field in data:
                    if field in ['credits', 'teacher_lock']:
                        update_data[field] = int(data[field]) if data[field] else 0
                    elif field == 'is_compulsory':
                        update_data[field] = bool(data[field])
                    else:
                        update_data[field] = data[field]
            
            db.courses.update_one(
                {'_id': ObjectId(course_id)},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Course updated successfully'})
        except Exception as e:
            logger.error(f"Admin update course error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            # Check if course has enrollments
            enrollment_count = db.enrollments.count_documents({'course_id': ObjectId(course_id)})
            
            if enrollment_count > 0:
                # Instead of deleting, deactivate the course
                db.courses.update_one(
                    {'_id': ObjectId(course_id)},
                    {'$set': {'status': 'inactive'}}
                )
                
                return jsonify({
                    'message': 'Course deactivated (has active enrollments)',
                    'deactivated': True
                })
            else:
                # Delete course and related data
                db.courses.delete_one({'_id': ObjectId(course_id)})
                db.teacher_courses.delete_many({'course_id': ObjectId(course_id)})
                db.announcements.delete_many({'course_id': ObjectId(course_id)})
                db.assignments.delete_many({'course_id': ObjectId(course_id)})
                db.materials.delete_many({'course_id': ObjectId(course_id)})
                db.discussion_posts.delete_many({'course_id': ObjectId(course_id)})
                
                return jsonify({'message': 'Course deleted successfully'})
        except Exception as e:
            logger.error(f"Admin delete course error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/compulsory-courses', methods=['GET', 'POST', 'PUT'])
@admin_required
def admin_compulsory_courses():
    db = get_db()
    
    if request.method == 'GET':
        try:
            courses = list(db.courses.find({'is_compulsory': True}).sort('level', 1))
            
            # Get enrollment counts
            for course in courses:
                enrollment_count = db.enrollments.count_documents({'course_id': course['_id']})
                course['enrollment_count'] = enrollment_count
            
            return jsonify(serialize_list(courses))
        except Exception as e:
            logger.error(f"Admin get compulsory courses error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Check if course code already exists
            existing = db.courses.find_one({'course_code': data['course_code']})
            if existing:
                return jsonify({'error': 'Course code already exists'}), 400
            
            course = {
                'title': data['title'],
                'course_code': data['course_code'],
                'description': data.get('description', ''),
                'credits': int(data['credits']),
                'teacher_lock': True,
                'status': 'active',
                'level': data['level'],
                'department': 'all',
                'is_compulsory': True,
                'created_at': datetime.utcnow()
            }
            
            result = db.courses.insert_one(course)
            
            # Auto-enroll students in this level
            students = list(db.users.find({
                'role': 'student',
                'level': course['level']
            }))
            
            enrollments_to_insert = []
            for student in students:
                enrollments_to_insert.append({
                    'student_id': student['_id'],
                    'course_id': result.inserted_id,
                    'enrolled_at': datetime.utcnow()
                })
            
            if enrollments_to_insert:
                try:
                    db.enrollments.insert_many(enrollments_to_insert, ordered=False)
                except:
                    pass
            
            # Create notifications for enrolled students
            for student in students:
                create_notification(
                    db,
                    str(student['_id']),
                    'Auto-enrolled in Compulsory Course',
                    f'You have been auto-enrolled in compulsory course: {course["title"]}',
                    'enrollment',
                    str(result.inserted_id)
                )
            
            return jsonify({
                'message': 'Compulsory course created successfully',
                'course_id': str(result.inserted_id),
                'auto_enrolled_count': len(students)
            }), 201
        except Exception as e:
            logger.error(f"Admin create compulsory course error: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.json
            
            course_id = data.get('id')
            if not course_id:
                return jsonify({'error': 'Course ID required'}), 400
            
            update_data = {}
            allowed_fields = ['title', 'course_code', 'description', 'credits', 'level']
            
            for field in allowed_fields:
                if field in data:
                    if field == 'credits':
                        update_data[field] = int(data[field])
                    else:
                        update_data[field] = data[field]
            
            db.courses.update_one(
                {'_id': ObjectId(course_id), 'is_compulsory': True},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Compulsory course updated successfully'})
        except Exception as e:
            logger.error(f"Admin update compulsory course error: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/compulsory-courses/<course_id>', methods=['DELETE'])
@admin_required
def delete_compulsory_course(course_id):
    try:
        db = get_db()
        
        # Check if course exists and is compulsory
        course = db.courses.find_one({'_id': ObjectId(course_id), 'is_compulsory': True})
        if not course:
            return jsonify({'error': 'Compulsory course not found'}), 404
        
        # Delete enrollments for this course
        db.enrollments.delete_many({'course_id': ObjectId(course_id)})
        
        # Delete the course
        db.courses.delete_one({'_id': ObjectId(course_id)})
        
        return jsonify({'message': 'Compulsory course deleted successfully'})
    except Exception as e:
        logger.error(f"Admin delete compulsory course error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/departments/deploy-courses', methods=['POST'])
@admin_required
def deploy_department_courses():
    try:
        data = request.json
        db = get_db()
        
        department = data['department']
        level = data['level']
        courses = data['courses']
        
        deployed_courses = []
        auto_enrolled_students = 0
        
        for course_data in courses:
            # Check if course already exists with this code
            existing_course = db.courses.find_one({'course_code': course_data['code']})
            
            if existing_course:
                # Update existing course
                db.courses.update_one(
                    {'_id': existing_course['_id']},
                    {'$set': {
                        'title': course_data['title'],
                        'description': course_data['description'],
                        'credits': course_data['credits'],
                        'department': department,
                        'level': level,
                        'status': 'active'
                    }}
                )
                course_id = existing_course['_id']
            else:
                # Create new course
                course = {
                    'title': course_data['title'],
                    'course_code': course_data['code'],
                    'description': course_data['description'],
                    'credits': course_data['credits'],
                    'teacher_lock': True,
                    'status': 'active',
                    'level': level,
                    'department': department,
                    'is_compulsory': False,
                    'created_at': datetime.utcnow()
                }
                
                result = db.courses.insert_one(course)
                course_id = result.inserted_id
            
            # Auto-enroll high school students in their department courses
            if level.startswith('HS'):
                students = list(db.users.find({
                    'role': 'student',
                    'level': level,
                    'department': department
                }))
                
                enrollments_to_insert = []
                for student in students:
                    # Check if already enrolled
                    existing_enrollment = db.enrollments.find_one({
                        'student_id': student['_id'],
                        'course_id': course_id
                    })
                    
                    if not existing_enrollment:
                        enrollments_to_insert.append({
                            'student_id': student['_id'],
                            'course_id': course_id,
                            'enrolled_at': datetime.utcnow()
                        })
                
                if enrollments_to_insert:
                    try:
                        db.enrollments.insert_many(enrollments_to_insert, ordered=False)
                        auto_enrolled_students += len(enrollments_to_insert)
                        
                        # Create notifications for enrolled students
                        for enrollment in enrollments_to_insert:
                            create_notification(
                                db,
                                str(enrollment['student_id']),
                                'Auto-enrolled in Department Course',
                                f'You have been auto-enrolled in department course: {course_data["title"]}',
                                'enrollment',
                                str(course_id)
                            )
                    except:
                        pass
            
            deployed_courses.append({
                'title': course_data['title'],
                'code': course_data['code'],
                'id': str(course_id)
            })
        
        return jsonify({
            'message': f'{len(deployed_courses)} courses deployed successfully for {department} department ({level})',
            'deployed_courses': deployed_courses,
            'auto_enrolled_students': auto_enrolled_students
        })
    except Exception as e:
        logger.error(f"Admin deploy department courses error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/departments/courses', methods=['GET'])
@admin_required
def get_department_courses():
    try:
        db = get_db()
        
        department = request.args.get('department')
        level = request.args.get('level')
        
        query = {'is_compulsory': False}
        
        if department:
            query['department'] = department
        if level:
            query['level'] = level
        
        courses = list(db.courses.find(query).sort('created_at', -1))
        
        # Add enrollment counts and teacher names
        for course in courses:
            enrollment_count = db.enrollments.count_documents({'course_id': course['_id']})
            course['enrolled_students'] = enrollment_count
            
            teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
            teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
            teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
            course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        return jsonify(serialize_list(courses))
    except Exception as e:
        logger.error(f"Admin get department courses error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/announcements', methods=['POST'])
@admin_required
def admin_create_announcement():
    try:
        data = request.json
        db = get_db()
        
        announcement = {
            'title': data['title'],
            'content': data['content'],
            'target': data['target'],  # 'teachers' or 'students'
            'admin_id': ObjectId(session['user_id']),
            'created_at': datetime.utcnow()
        }
        
        db.admin_announcements.insert_one(announcement)
        
        # Get admin name
        admin = db.users.find_one({'_id': ObjectId(session['user_id'])})
        admin_name = f"{admin.get('first_name', '')} {admin.get('last_name', '')}"
        
        # Create notifications for target users
        if data['target'] == 'teachers':
            teachers = list(db.users.find({'role': 'teacher', 'status': 'active'}))
            for teacher in teachers:
                create_notification(
                    db,
                    str(teacher['_id']),
                    f'Admin Announcement: {data["title"]}',
                    data['content'],
                    'admin_announcement',
                    str(announcement['_id'])
                )
        elif data['target'] == 'students':
            students = list(db.users.find({'role': 'student', 'status': 'active'}))
            for student in students:
                create_notification(
                    db,
                    str(student['_id']),
                    f'Admin Announcement: {data["title"]}',
                    data['content'],
                    'admin_announcement',
                    str(announcement['_id'])
                )
        
        return jsonify({'message': 'Announcement sent successfully'})
    except Exception as e:
        logger.error(f"Admin create announcement error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/announcements/recent', methods=['GET'])
@admin_required
def get_recent_admin_announcements():
    try:
        db = get_db()
        
        announcements = list(db.admin_announcements.find().sort('created_at', -1).limit(10))
        
        # Add admin names
        for ann in announcements:
            admin = db.users.find_one({'_id': ann['admin_id']})
            if admin:
                ann['admin_name'] = f"{admin.get('first_name', '')} {admin.get('last_name', '')}"
        
        return jsonify(serialize_list(announcements))
    except Exception as e:
        logger.error(f"Admin get recent announcements error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/pending-approvals', methods=['GET'])
@admin_required
def get_pending_approvals():
    try:
        db = get_db()
        
        approvals = list(db.course_approval_requests.find({'status': 'pending'}))
        
        result = []
        for approval in approvals:
            teacher = db.users.find_one({'_id': approval['teacher_id']})
            course = db.courses.find_one({'_id': approval['course_id']})
            current_teacher = None
            
            if approval.get('current_teacher_id'):
                current_teacher_doc = db.users.find_one({'_id': approval['current_teacher_id']})
                if current_teacher_doc:
                    current_teacher = f"{current_teacher_doc.get('first_name', '')} {current_teacher_doc.get('last_name', '')}"
            
            result.append({
                'request_id': str(approval['_id']),
                'teacher_id': str(approval['teacher_id']),
                'teacher_first_name': teacher.get('first_name', ''),
                'teacher_last_name': teacher.get('last_name', ''),
                'teacher_code': teacher.get('teacher_code', ''),
                'course_id': str(approval['course_id']),
                'course_title': course.get('title', ''),
                'course_code': course.get('course_code', ''),
                'current_teacher': current_teacher or 'Not assigned',
                'requested_at': approval['requested_at']
            })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Admin get pending approvals error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/approval-history', methods=['GET'])
@admin_required
def get_approval_history():
    try:
        db = get_db()
        
        approvals = list(db.course_approval_requests.find().sort('requested_at', -1).limit(50))
        
        result = []
        for approval in approvals:
            teacher = db.users.find_one({'_id': approval['teacher_id']})
            course = db.courses.find_one({'_id': approval['course_id']})
            admin = db.users.find_one({'_id': approval.get('admin_id')}) if approval.get('admin_id') else None
            
            result.append({
                'teacher_first_name': teacher.get('first_name', ''),
                'teacher_last_name': teacher.get('last_name', ''),
                'course_title': course.get('title', ''),
                'status': approval.get('status', 'pending'),
                'requested_at': approval['requested_at'],
                'reviewed_at': approval.get('reviewed_at'),
                'admin_name': f"{admin.get('first_name', '')} {admin.get('last_name', '')}" if admin else 'N/A',
                'admin_notes': approval.get('admin_notes', '')
            })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Admin get approval history error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/approve-course-request/<request_id>', methods=['POST'])
@admin_required
def approve_course_request(request_id):
    try:
        data = request.json
        db = get_db()
        
        approval_request = db.course_approval_requests.find_one({'_id': ObjectId(request_id)})
        if not approval_request:
            return jsonify({'error': 'Approval request not found'}), 404
        
        if data.get('action') == 'approve':
            # Check if course is already assigned to another teacher
            existing_teacher = db.teacher_courses.find_one({
                'course_id': approval_request['course_id']
            })
            
            if existing_teacher and existing_teacher['teacher_id'] != approval_request['teacher_id']:
                if not data.get('reassign'):
                    return jsonify({
                        'error': 'Course already assigned to another teacher',
                        'current_teacher': str(existing_teacher['teacher_id']),
                        'course_title': db.courses.find_one({'_id': approval_request['course_id']}).get('title', '')
                    }), 400
                
                # Remove existing teacher assignment
                db.teacher_courses.delete_one({
                    'teacher_id': existing_teacher['teacher_id'],
                    'course_id': approval_request['course_id']
                })
            
            # Assign course to requesting teacher
            teacher_course = {
                'teacher_id': approval_request['teacher_id'],
                'course_id': approval_request['course_id'],
                'assigned_at': datetime.utcnow()
            }
            
            db.teacher_courses.insert_one(teacher_course)
            
            # Update approval request
            db.course_approval_requests.update_one(
                {'_id': ObjectId(request_id)},
                {'$set': {
                    'status': 'approved',
                    'admin_id': ObjectId(session['user_id']),
                    'reviewed_at': datetime.utcnow(),
                    'admin_notes': data.get('notes', 'Approved by admin')
                }}
            )
            
            # Notify teacher
            teacher = db.users.find_one({'_id': approval_request['teacher_id']})
            course = db.courses.find_one({'_id': approval_request['course_id']})
            
            create_notification(
                db,
                str(approval_request['teacher_id']),
                'Course Request Approved',
                f'Your request to teach {course.get("title", "Course")} has been approved.',
                'approval',
                request_id
            )
            
            return jsonify({'message': 'Course request approved successfully'})
        
        elif data.get('action') == 'reject':
            # Update approval request
            db.course_approval_requests.update_one(
                {'_id': ObjectId(request_id)},
                {'$set': {
                    'status': 'rejected',
                    'admin_id': ObjectId(session['user_id']),
                    'reviewed_at': datetime.utcnow(),
                    'admin_notes': data.get('notes', 'Rejected by admin')
                }}
            )
            
            # Notify teacher
            teacher = db.users.find_one({'_id': approval_request['teacher_id']})
            course = db.courses.find_one({'_id': approval_request['course_id']})
            
            create_notification(
                db,
                str(approval_request['teacher_id']),
                'Course Request Rejected',
                f'Your request to teach {course.get("title", "Course")} has been rejected. Reason: {data.get("notes", "No reason provided")}',
                'approval',
                request_id
            )
            
            return jsonify({'message': 'Course request rejected successfully'})
        
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
    except Exception as e:
        logger.error(f"Admin approve course request error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/enrollments', methods=['GET'])
@admin_required
def admin_get_enrollments():
    try:
        db = get_db()
        
        enrollments = list(db.enrollments.find().sort('enrolled_at', -1))
        
        result = []
        for enrollment in enrollments:
            student = db.users.find_one({'_id': enrollment['student_id']})
            course = db.courses.find_one({'_id': enrollment['course_id']})
            
            if student and course:
                result.append({
                    'id': str(enrollment['_id']),
                    'student_id': str(student['_id']),
                    'first_name': student.get('first_name', ''),
                    'last_name': student.get('last_name', ''),
                    'student_id_display': student.get('student_id', ''),
                    'course_id': str(course['_id']),
                    'course_title': course.get('title', ''),
                    'course_code': course.get('course_code', ''),
                    'level': student.get('level', ''),
                    'department': student.get('department', ''),
                    'enrolled_at': enrollment['enrolled_at']
                })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Admin get enrollments error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/enrollments/search', methods=['GET'])
@admin_required
def search_enrollments():
    try:
        search_term = request.args.get('q', '').lower()
        db = get_db()
        
        # Search students by name, ID, or email
        student_query = {
            'role': 'student',
            '$or': [
                {'first_name': {'$regex': search_term, '$options': 'i'}},
                {'last_name': {'$regex': search_term, '$options': 'i'}},
                {'student_id': {'$regex': search_term, '$options': 'i'}},
                {'email': {'$regex': search_term, '$options': 'i'}}
            ]
        }
        
        students = list(db.users.find(student_query))
        student_ids = [s['_id'] for s in students]
        
        # Search courses by title or code
        course_query = {
            '$or': [
                {'title': {'$regex': search_term, '$options': 'i'}},
                {'course_code': {'$regex': search_term, '$options': 'i'}}
            ]
        }
        
        courses = list(db.courses.find(course_query))
        course_ids = [c['_id'] for c in courses]
        
        # Find enrollments
        enrollments = list(db.enrollments.find({
            '$or': [
                {'student_id': {'$in': student_ids}},
                {'course_id': {'$in': course_ids}}
            ]
        }).sort('enrolled_at', -1))
        
        result = []
        for enrollment in enrollments:
            student = db.users.find_one({'_id': enrollment['student_id']})
            course = db.courses.find_one({'_id': enrollment['course_id']})
            
            if student and course:
                result.append({
                    'id': str(enrollment['_id']),
                    'student_id': str(student['_id']),
                    'first_name': student.get('first_name', ''),
                    'last_name': student.get('last_name', ''),
                    'student_id_display': student.get('student_id', ''),
                    'course_id': str(course['_id']),
                    'course_title': course.get('title', ''),
                    'course_code': course.get('course_code', ''),
                    'level': student.get('level', ''),
                    'department': student.get('department', ''),
                    'enrolled_at': enrollment['enrolled_at']
                })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Admin search enrollments error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/enrollments/<enrollment_id>', methods=['DELETE'])
@admin_required
def admin_remove_enrollment(enrollment_id):
    try:
        db = get_db()
        
        enrollment = db.enrollments.find_one({'_id': ObjectId(enrollment_id)})
        if not enrollment:
            return jsonify({'error': 'Enrollment not found'}), 404
        
        db.enrollments.delete_one({'_id': ObjectId(enrollment_id)})
        
        # Notify student
        student = db.users.find_one({'_id': enrollment['student_id']})
        course = db.courses.find_one({'_id': enrollment['course_id']})
        
        if student and course:
            create_notification(
                db,
                str(enrollment['student_id']),
                'Removed from Course',
                f'You have been removed from {course.get("title", "Course")} by administrator.',
                'enrollment',
                str(course['_id'])
            )
        
        return jsonify({'message': 'Student removed from course successfully'})
    except Exception as e:
        logger.error(f"Admin remove enrollment error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/students/<student_id>/enrollments', methods=['GET'])
@admin_required
def get_student_enrollments(student_id):
    try:
        db = get_db()
        
        enrollments = list(db.enrollments.find({'student_id': ObjectId(student_id)}))
        
        result = []
        for enrollment in enrollments:
            course = db.courses.find_one({'_id': enrollment['course_id']})
            
            if course:
                # Get teacher name
                teacher_course = db.teacher_courses.find_one({'course_id': course['_id']})
                teacher_name = 'Not assigned'
                if teacher_course:
                    teacher = db.users.find_one({'_id': teacher_course['teacher_id']})
                    if teacher:
                        teacher_name = f"{teacher.get('first_name', '')} {teacher.get('last_name', '')}"
                
                result.append({
                    'id': str(enrollment['_id']),
                    'title': course.get('title', ''),
                    'course_code': course.get('course_code', ''),
                    'credits': course.get('credits', 0),
                    'teacher_name': teacher_name,
                    'status': course.get('status', 'active'),
                    'enrolled_at': enrollment['enrolled_at']
                })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Admin get student enrollments error: {e}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/admin/clear-all-courses', methods=['DELETE'])
@admin_required
def clear_all_courses():
    try:
        db = get_db()
        
        # Get count of courses before deletion
        course_count = db.courses.count_documents({})
        
        # Delete all courses and related data
        db.courses.delete_many({})
        db.teacher_courses.delete_many({})
        db.enrollments.delete_many({})
        db.announcements.delete_many({})
        db.assignments.delete_many({})
        db.materials.delete_many({})
        db.discussion_posts.delete_many({})
        db.discussion_replies.delete_many({})
        db.submissions.delete_many({})
        
        # Reinitialize compulsory courses
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
        
        inserted_count = 0
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
                inserted_count += 1
        
        return jsonify({
            'message': f'All courses cleared and {inserted_count} compulsory courses reinitialized',
            'deleted_count': course_count,
            'inserted_count': inserted_count
        })
    except Exception as e:
        logger.error(f"Admin clear all courses error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/fee-management', methods=['GET'])
@admin_required
def admin_fee_management():
    try:
        db = get_db()
        
        # Get all fee payments with student info
        payments = list(db.fee_payments.find().sort('payment_date', -1))
        
        result = []
        for payment in payments:
            student = db.users.find_one({'_id': payment['student_id']})
            if student:
                payment['student_name'] = f"{student.get('first_name', '')} {student.get('last_name', '')}"
                payment['student_id_display'] = student.get('student_id', '')
                payment['student_level'] = student.get('level', '')
                payment['student_department'] = student.get('department', '')
                payment['student_email'] = student.get('email', '')
            
            if payment.get('created_by'):
                creator = db.users.find_one({'_id': payment['created_by']})
                if creator:
                    payment['created_by_name'] = f"{creator.get('first_name', '')} {creator.get('last_name', '')}"
            
            if payment.get('approved_by'):
                approver = db.users.find_one({'_id': payment['approved_by']})
                if approver:
                    payment['approved_by_name'] = f"{approver.get('first_name', '')} {approver.get('last_name', '')}"
            
            result.append(serialize_doc(payment))
        
        # Get summary statistics
        total_payments = len(payments)
        approved_payments = len([p for p in payments if p.get('status') == 'approved'])
        pending_payments = len([p for p in payments if p.get('status') == 'pending'])
        rejected_payments = len([p for p in payments if p.get('status') == 'rejected'])
        total_amount = sum(p['amount'] for p in payments if p.get('status') == 'approved')
        
        # Get students with pending fee payments
        students_with_pending_fees = list(db.users.find({
            'role': 'student',
            'fee_payment_required': True
        }))
        
        students_list = []
        for student in students_with_pending_fees:
            student_payments = list(db.fee_payments.find({
                'student_id': student['_id'],
                'status': 'approved'
            }))
            has_approved_payment = len(student_payments) > 0
            
            students_list.append({
                'id': str(student['_id']),
                'name': f"{student.get('first_name', '')} {student.get('last_name', '')}",
                'student_id': student.get('student_id', ''),
                'level': student.get('level', ''),
                'department': student.get('department', ''),
                'email': student.get('email', ''),
                'has_approved_payment': has_approved_payment,
                'last_payment_date': student_payments[0]['payment_date'].isoformat() if student_payments else None,
                'last_payment_amount': student_payments[0]['amount'] if student_payments else 0
            })
        
        return jsonify({
            'payments': result,
            'statistics': {
                'total_payments': total_payments,
                'approved_payments': approved_payments,
                'pending_payments': pending_payments,
                'rejected_payments': rejected_payments,
                'total_amount': total_amount
            },
            'students_with_fees': students_list
        })
    except Exception as e:
        logger.error(f"Admin fee management error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/fee-payments/summary', methods=['GET'])
@admin_required
def fee_payments_summary():
    try:
        db = get_db()
        
        # Get current academic year
        current_year = datetime.now().year
        
        # Get payments by status
        payments = list(db.fee_payments.find({
            'academic_year': current_year
        }))
        
        # Calculate statistics by month
        monthly_stats = {}
        for payment in payments:
            month = payment['payment_date'].strftime('%Y-%m')
            if month not in monthly_stats:
                monthly_stats[month] = {
                    'total': 0,
                    'approved': 0,
                    'pending': 0,
                    'rejected': 0
                }
            
            monthly_stats[month]['total'] += payment['amount']
            if payment['status'] == 'approved':
                monthly_stats[month]['approved'] += payment['amount']
            elif payment['status'] == 'pending':
                monthly_stats[month]['pending'] += payment['amount']
            elif payment['status'] == 'rejected':
                monthly_stats[month]['rejected'] += payment['amount']
        
        # Get payments by level
        level_stats = {}
        for payment in payments:
            student = db.users.find_one({'_id': payment['student_id']})
            if student:
                level = student.get('level', 'Unknown')
                if level not in level_stats:
                    level_stats[level] = {
                        'total': 0,
                        'count': 0
                    }
                level_stats[level]['total'] += payment['amount']
                level_stats[level]['count'] += 1
        
        # Get recent payments
        recent_payments = list(db.fee_payments.find()
                              .sort('payment_date', -1)
                              .limit(10))
        
        recent_list = []
        for payment in recent_payments:
            student = db.users.find_one({'_id': payment['student_id']})
            if student:
                recent_list.append({
                    'id': str(payment['_id']),
                    'student_name': f"{student.get('first_name', '')} {student.get('last_name', '')}",
                    'student_id': student.get('student_id', ''),
                    'amount': payment['amount'],
                    'status': payment['status'],
                    'payment_date': payment['payment_date'].isoformat(),
                    'receipt_number': payment.get('receipt_number', '')
                })
        
        return jsonify({
            'monthly_stats': monthly_stats,
            'level_stats': level_stats,
            'recent_payments': recent_list,
            'current_year': current_year
        })
    except Exception as e:
        logger.error(f"Fee payments summary error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/students/<student_id>/toggle-fee-requirement', methods=['POST'])
@admin_required
def toggle_student_fee_requirement(student_id):
    try:
        db = get_db()
        
        student = db.users.find_one({'_id': ObjectId(student_id), 'role': 'student'})
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        current_status = student.get('fee_payment_required', True)
        new_status = not current_status
        
        db.users.update_one(
            {'_id': ObjectId(student_id)},
            {'$set': {'fee_payment_required': new_status}}
        )
        
        action = 'enabled' if new_status else 'disabled'
        return jsonify({
            'message': f'Fee payment requirement {action} for student',
            'fee_payment_required': new_status
        })
    except Exception as e:
        logger.error(f"Toggle student fee requirement error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# MISCELLANEOUS ROUTES
# ==============================================

@app.route('/api/courses/<course_id>/students', methods=['GET'])
@login_required
def get_course_students(course_id):
    try:
        db = get_db()
        
        # Check if user has access to this course
        if session.get('role') == 'student':
            enrollment = db.enrollments.find_one({
                'student_id': ObjectId(session['user_id']),
                'course_id': ObjectId(course_id)
            })
            if not enrollment:
                return jsonify({'error': 'Unauthorized'}), 403
        elif session.get('role') == 'teacher':
            teacher_course = db.teacher_courses.find_one({
                'teacher_id': ObjectId(session['user_id']),
                'course_id': ObjectId(course_id)
            })
            if not teacher_course:
                return jsonify({'error': 'Unauthorized'}), 403
        
        enrollments = list(db.enrollments.find({'course_id': ObjectId(course_id)}))
        student_ids = [e['student_id'] for e in enrollments]
        students = list(db.users.find({'_id': {'$in': student_ids}, 'role': 'student'}))
        
        return jsonify(serialize_list(students))
    except Exception as e:
        logger.error(f"Get course students error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/teachers/<teacher_id>/courses/<course_id>/students/<student_id>', methods=['DELETE'])
@teacher_required
def teacher_remove_student(teacher_id, course_id, student_id):
    try:
        if session['user_id'] != teacher_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        # Verify teacher is assigned to this course
        teacher_course = db.teacher_courses.find_one({
            'teacher_id': ObjectId(teacher_id),
            'course_id': ObjectId(course_id)
        })
        
        if not teacher_course:
            return jsonify({'error': 'Teacher not assigned to this course'}), 403
        
        # Remove enrollment
        result = db.enrollments.delete_one({
            'student_id': ObjectId(student_id),
            'course_id': ObjectId(course_id)
        })
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Student not enrolled in this course'}), 404
        
        # Notify student
        student = db.users.find_one({'_id': ObjectId(student_id)})
        course = db.courses.find_one({'_id': ObjectId(course_id)})
        
        if student and course:
            create_notification(
                db,
                student_id,
                'Removed from Course',
                f'You have been removed from {course.get("title", "Course")} by your teacher.',
                'enrollment',
                course_id
            )
        
        return jsonify({'message': 'Student removed from course successfully'})
    except Exception as e:
        logger.error(f"Teacher remove student error: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================
# ERROR HANDLING
# ==============================================

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Server Error: {error}')
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f'Unhandled Error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500

# ==============================================
# MAIN ENTRY POINT
# ==============================================

def signal_handler(sig, frame):
    """Handle graceful shutdown"""
    print('\n👋 Shutting down gracefully...')
    # Additional cleanup if needed
    sys.exit(0)

if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize database
        init_db()
        
        # Determine environment
        debug_mode = os.environ.get('FLASK_ENV') == 'development'
        
        # Configure for production/development
        app.config['SESSION_COOKIE_SECURE'] = not debug_mode
        app.config['DEBUG'] = debug_mode
        
        # Get port and host from environment or use defaults
        port = int(os.environ.get('PORT', 5000))
        host = os.environ.get('HOST', '0.0.0.0')
        
        print("\n" + "="*60)
        print("🎓 SCHOOL LEARNING MANAGEMENT SYSTEM (MongoDB)")
        print("="*60)
        print(f"\n🏃 Running in {'DEBUG' if debug_mode else 'PRODUCTION'} mode")
        print(f"🌐 Server URL: http://{host}:{port}")
        print("\n🔐 Login Credentials:")
        print("   👑 Admin:      admin@school.edu / admin123")
        print("   👨‍🏫 Teacher:   teacher@school.edu / teacher123")
        print("   👨‍🎓 Students:  Register on the portal")
        print("\n💰 Fee Payment System:")
        print("   • Students need fee payment approval to access courses")
        print("   • Admin can record and approve fee payments")
        print("   • Students locked until admin approves fees")
        print("\n📚 Level System:")
        print("   🏫 Middle School: MS1, MS2, MS3")
        print("   🎓 High School:   HS1, HS2, HS3 (Department required)")
        print("\n📖 Compulsory Courses:")
        print("   1. Mathematics")
        print("   2. English Language")
        print("   3. Data Processing")
        print("\n🔧 Health Check:")
        print(f"   🌐 http://{host}:{port}/api/health")
        print("\n" + "="*60 + "\n")
        
        # Run the application
        app.run(
            debug=debug_mode,
            port=port,
            host=host,
            threaded=True
        )
        
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Fatal error starting server: {e}")
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
else:
    # For production deployment (e.g., Vercel, Gunicorn)
    init_db()
    logger.info("✅ Application initialized for production deployment")