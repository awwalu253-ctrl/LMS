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
from pymongo.server_api import ServerApi
from bson import ObjectId
from bson.json_util import dumps, loads
from urllib.parse import quote_plus
from dotenv import load_dotenv
import json
from datetime import datetime
from bson import ObjectId

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
        print(f"🔧 Connecting to MongoDB Atlas...")
        
        try:
            server_api = ServerApi('1')
            g.client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                server_api=server_api
            )
            g.db = g.client[DATABASE_NAME]
            g.client.admin.command('ping')
            print("✅ MongoDB connected successfully!")
            
        except Exception as e:
            print(f"❌ Standard connection failed: {e}")
            try:
                print("🔄 Trying alternative connection method...")
                g.client = MongoClient(
                    MONGO_URI,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=5000
                )
                g.db = g.client[DATABASE_NAME]
                g.client.admin.command('ping')
                print("✅ Alternative connection successful!")
                
            except Exception as e2:
                print(f"❌ Alternative connection failed: {e2}")
                raise Exception(f"MongoDB connection failed: {e2}")
    
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
    return json.loads(json.dumps(doc, cls=JSONEncoder))

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
        
        print(f"✅ Auto-enrolled student {student_id} in {len(compulsory_courses)} compulsory courses for level {level}")
        
    except Exception as e:
        print(f"⚠️ Error auto-enrolling student: {e}")

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

def init_db():
    with app.app_context():
        try:
            db = get_db()
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
            
            user_data = serialize_doc(user)
            user_data.pop('password', None)
            
            return jsonify(user_data)
        
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

# ==============================================
# STUDENT ROUTES
# ==============================================

@app.route('/api/students/<student_id>/courses', methods=['GET'])
@login_required
def get_student_courses(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/students/<student_id>/subject-combination', methods=['GET'])
@login_required
def get_student_subject_combination(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/students/<student_id>/grades', methods=['GET'])
@login_required
def get_student_grades(student_id):
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
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
        return jsonify({'error': str(e)}), 500

# ==============================================
# COURSE ROUTES
# ==============================================

@app.route('/api/courses', methods=['GET'])
@login_required
def get_all_courses():
    try:
        db = get_db()
        courses = list(db.courses.find({'status': 'active'}))
        
        for course in courses:
            teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
            teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
            teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
            course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        return jsonify(serialize_list(courses))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/courses/for-teacher', methods=['GET'])
@teacher_required
def get_courses_for_teacher():
    try:
        db = get_db()
        teacher = db.users.find_one({'_id': ObjectId(session['user_id'])})
        
        # Get courses for teacher's department OR compulsory courses (department='all')
        courses = list(db.courses.find({
            '$or': [
                {'department': teacher.get('department', '')},
                {'department': 'all'}
            ],
            'status': 'active'
        }))
        
        for course in courses:
            teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
            teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
            teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
            course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        return jsonify(serialize_list(courses))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/courses/<course_id>', methods=['GET'])
@login_required
def get_course(course_id):
    try:
        db = get_db()
        course = db.courses.find_one({'_id': ObjectId(course_id)})
        
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        
        # Get teacher info
        teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
        teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
        teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
        course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        return jsonify(serialize_doc(course))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/courses/<course_id>/students', methods=['GET'])
@login_required
def get_course_students(course_id):
    try:
        db = get_db()
        
        enrollments = list(db.enrollments.find({'course_id': ObjectId(course_id)}))
        student_ids = [ObjectId(enrollment['student_id']) for enrollment in enrollments]
        students = list(db.users.find({'_id': {'$in': student_ids}}))
        
        return jsonify(serialize_list(students))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==============================================
# ENROLLMENT ROUTES
# ==============================================

@app.route('/api/enroll', methods=['POST'])
@student_required
def enroll_in_course():
    try:
        data = request.json
        db = get_db()
        
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
        return jsonify({'error': str(e)}), 500

# ==============================================
# TEACHER ROUTES
# ==============================================

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
        return jsonify({'error': str(e)}), 500

@app.route('/api/teachers/<teacher_id>/assign-course', methods=['POST'])
@teacher_required
def assign_course_to_teacher(teacher_id):
    try:
        if session['user_id'] != teacher_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.json
        db = get_db()
        
        # Check if course exists
        course = db.courses.find_one({'_id': ObjectId(data['course_id'])})
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        
        # Check if course is teacher locked and already has a teacher
        if course.get('teacher_lock'):
            existing_teacher = db.teacher_courses.find_one({'course_id': ObjectId(data['course_id'])})
            if existing_teacher:
                # Create approval request
                approval_request = {
                    'teacher_id': ObjectId(teacher_id),
                    'course_id': ObjectId(data['course_id']),
                    'status': 'pending',
                    'requested_at': datetime.utcnow()
                }
                db.course_approval_requests.insert_one(approval_request)
                
                return jsonify({
                    'requires_approval': True,
                    'message': 'Course requires admin approval (already assigned to another teacher)'
                })
        
        # Assign course to teacher
        assignment = {
            'teacher_id': ObjectId(teacher_id),
            'course_id': ObjectId(data['course_id']),
            'assigned_at': datetime.utcnow()
        }
        
        try:
            db.teacher_courses.insert_one(assignment)
        except DuplicateKeyError:
            return jsonify({'error': 'Already assigned to this course'}), 400
        
        return jsonify({'message': 'Course assigned successfully'})
    except Exception as e:
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
            return jsonify({'error': 'Assignment not found'}), 404
        
        return jsonify({'message': 'Course unassigned successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/teachers/<teacher_id>/courses/<course_id>/students/<student_id>', methods=['DELETE'])
@teacher_required
def remove_student_from_course(teacher_id, course_id, student_id):
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
            return jsonify({'error': 'You are not assigned to this course'}), 403
        
        # Remove enrollment
        result = db.enrollments.delete_one({
            'student_id': ObjectId(student_id),
            'course_id': ObjectId(course_id)
        })
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Student not enrolled in this course'}), 404
        
        # Create notification for student
        course = db.courses.find_one({'_id': ObjectId(course_id)})
        student = db.users.find_one({'_id': ObjectId(student_id)})
        teacher = db.users.find_one({'_id': ObjectId(teacher_id)})
        
        create_notification(
            db, 
            student_id,
            'Removed from Course',
            f'You have been removed from {course.get("title")} by {teacher.get("first_name")} {teacher.get("last_name")}',
            'course',
            course_id
        )
        
        return jsonify({'message': 'Student removed from course successfully'})
    except Exception as e:
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
            # Get all announcements for courses the user is enrolled in/teaching
            if session.get('role') == 'student':
                enrollments = list(db.enrollments.find({'student_id': ObjectId(session['user_id'])}))
                course_ids = [ObjectId(enrollment['course_id']) for enrollment in enrollments]
                announcements_list = list(db.announcements.find({
                    'course_id': {'$in': course_ids}
                }).sort('created_at', -1).limit(50))
            elif session.get('role') == 'teacher':
                teacher_courses = list(db.teacher_courses.find({'teacher_id': ObjectId(session['user_id'])}))
                course_ids = [tc['course_id'] for tc in teacher_courses]
                announcements_list = list(db.announcements.find({
                    'course_id': {'$in': course_ids}
                }).sort('created_at', -1).limit(50))
            else:
                announcements_list = list(db.announcements.find().sort('created_at', -1).limit(50))
            
            # Add course and teacher info
            for announcement in announcements_list:
                course = db.courses.find_one({'_id': announcement['course_id']})
                teacher = db.users.find_one({'_id': announcement['teacher_id']})
                
                if course:
                    announcement['course_title'] = course.get('title', '')
                if teacher:
                    announcement['teacher_name'] = f"{teacher.get('first_name', '')} {teacher.get('last_name', '')}"
            
            return jsonify(serialize_list(announcements_list))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Verify teacher is assigned to this course
            if session.get('role') == 'teacher':
                teacher_course = db.teacher_courses.find_one({
                    'teacher_id': ObjectId(session['user_id']),
                    'course_id': ObjectId(data['course_id'])
                })
                
                if not teacher_course:
                    return jsonify({'error': 'You are not assigned to this course'}), 403
            
            announcement = {
                'course_id': ObjectId(data['course_id']),
                'teacher_id': ObjectId(session['user_id']),
                'title': data['title'],
                'content': data['content'],
                'created_at': datetime.utcnow()
            }
            
            result = db.announcements.insert_one(announcement)
            
            # Create notifications for enrolled students
            enrollments = list(db.enrollments.find({'course_id': ObjectId(data['course_id'])}))
            course = db.courses.find_one({'_id': ObjectId(data['course_id'])})
            
            for enrollment in enrollments:
                create_notification(
                    db,
                    str(enrollment['student_id']),
                    'New Announcement',
                    f'New announcement in {course.get("title", "Course")}: {data["title"]}',
                    'announcement',
                    str(result.inserted_id)
                )
            
            return jsonify({'message': 'Announcement created successfully'})
        except Exception as e:
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
            
            assignments_list = list(db.assignments.find(query).sort('created_at', -1))
            return jsonify(serialize_list(assignments_list))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Verify teacher is assigned to this course
            if session.get('role') == 'teacher':
                teacher_course = db.teacher_courses.find_one({
                    'teacher_id': ObjectId(session['user_id']),
                    'course_id': ObjectId(data['course_id'])
                })
                
                if not teacher_course:
                    return jsonify({'error': 'You are not assigned to this course'}), 403
            
            assignment = {
                'course_id': ObjectId(data['course_id']),
                'teacher_id': ObjectId(session['user_id']),
                'title': data['title'],
                'description': data['description'],
                'due_date': datetime.fromisoformat(data['due_date'].replace('Z', '+00:00')),
                'max_points': data['max_points'],
                'created_at': datetime.utcnow()
            }
            
            result = db.assignments.insert_one(assignment)
            
            # Create notifications for enrolled students
            enrollments = list(db.enrollments.find({'course_id': ObjectId(data['course_id'])}))
            course = db.courses.find_one({'_id': ObjectId(data['course_id'])})
            
            for enrollment in enrollments:
                create_notification(
                    db,
                    str(enrollment['student_id']),
                    'New Assignment',
                    f'New assignment in {course.get("title", "Course")}: {data["title"]}',
                    'assignment',
                    str(result.inserted_id)
                )
            
            return jsonify({'message': 'Assignment created successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<assignment_id>', methods=['GET'])
@login_required
def get_assignment(assignment_id):
    try:
        db = get_db()
        assignment = db.assignments.find_one({'_id': ObjectId(assignment_id)})
        
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        return jsonify(serialize_doc(assignment))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<assignment_id>/submissions', methods=['GET'])
@login_required
def get_assignment_submissions(assignment_id):
    try:
        db = get_db()
        
        # Verify user has access (teacher of course or student who submitted)
        assignment = db.assignments.find_one({'_id': ObjectId(assignment_id)})
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        if session.get('role') == 'teacher':
            teacher_course = db.teacher_courses.find_one({
                'teacher_id': ObjectId(session['user_id']),
                'course_id': assignment['course_id']
            })
            
            if not teacher_course:
                return jsonify({'error': 'You are not assigned to this course'}), 403
        
        submissions = list(db.submissions.find({'assignment_id': ObjectId(assignment_id)}))
        
        # Add student names
        for submission in submissions:
            student = db.users.find_one({'_id': submission['student_id']})
            if student:
                submission['student_name'] = f"{student.get('first_name', '')} {student.get('last_name', '')}"
        
        return jsonify(serialize_list(submissions))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==============================================
# SUBMISSION ROUTES
# ==============================================

@app.route('/api/submissions', methods=['POST'])
@student_required
def create_submission():
    try:
        data = request.json
        db = get_db()
        
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/grade', methods=['POST'])
@teacher_required
def grade_submission():
    try:
        data = request.json
        db = get_db()
        
        # Verify teacher is assigned to this course
        assignment = db.assignments.find_one({'_id': ObjectId(data['assignment_id'])})
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        teacher_course = db.teacher_courses.find_one({
            'teacher_id': ObjectId(session['user_id']),
            'course_id': assignment['course_id']
        })
        
        if not teacher_course:
            return jsonify({'error': 'You are not assigned to this course'}), 403
        
        # Update submission
        result = db.submissions.update_one(
            {
                'assignment_id': ObjectId(data['assignment_id']),
                'student_id': ObjectId(data['student_id'])
            },
            {
                '$set': {
                    'grade': data['grade'],
                    'feedback': data.get('feedback', ''),
                    'graded_at': datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Submission not found'}), 404
        
        # Create notification for student
        assignment = db.assignments.find_one({'_id': ObjectId(data['assignment_id'])})
        teacher = db.users.find_one({'_id': ObjectId(session['user_id'])})
        
        create_notification(
            db,
            data['student_id'],
            'Assignment Graded',
            f'Your submission for {assignment.get("title", "Assignment")} has been graded by {teacher.get("first_name", "Teacher")}',
            'grade',
            data['assignment_id']
        )
        
        return jsonify({'message': 'Grade submitted successfully'})
    except Exception as e:
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
            if not course_id:
                return jsonify({'error': 'Course ID required'}), 400
            
            posts = list(db.discussion_posts.find({
                'course_id': ObjectId(course_id)
            }).sort('created_at', -1))
            
            # Add author info
            for post in posts:
                author = db.users.find_one({'_id': post['user_id']})
                if author:
                    post['author_name'] = f"{author.get('first_name', '')} {author.get('last_name', '')}"
                    post['role'] = author.get('role', '')
            
            return jsonify(serialize_list(posts))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
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
            return jsonify({'error': str(e)}), 500

@app.route('/api/discussions/<post_id>/replies', methods=['GET', 'POST'])
@login_required
def discussion_replies(post_id):
    db = get_db()
    
    if request.method == 'GET':
        try:
            replies = list(db.discussion_replies.find({
                'post_id': ObjectId(post_id)
            }).sort('created_at', 1))
            
            # Add author info
            for reply in replies:
                author = db.users.find_one({'_id': reply['user_id']})
                if author:
                    reply['author_name'] = f"{author.get('first_name', '')} {author.get('last_name', '')}"
                    reply['role'] = author.get('role', '')
            
            return jsonify(serialize_list(replies))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Verify user has access to the discussion
            post = db.discussion_posts.find_one({'_id': ObjectId(post_id)})
            if not post:
                return jsonify({'error': 'Discussion post not found'}), 404
            
            course_id = post['course_id']
            
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
            
            reply = {
                'post_id': ObjectId(post_id),
                'user_id': ObjectId(session['user_id']),
                'content': data['content'],
                'created_at': datetime.utcnow()
            }
            
            db.discussion_replies.insert_one(reply)
            
            # Create notification for post author
            if str(post['user_id']) != session['user_id']:
                create_notification(
                    db,
                    str(post['user_id']),
                    'New Reply',
                    f'Someone replied to your discussion post: {post["title"]}',
                    'discussion',
                    post_id
                )
            
            return jsonify({'message': 'Reply posted successfully'})
        except Exception as e:
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
            if not course_id:
                return jsonify({'error': 'Course ID required'}), 400
            
            materials_list = list(db.materials.find({
                'course_id': ObjectId(course_id)
            }).sort('created_at', -1))
            
            # Add teacher info
            for material in materials_list:
                teacher = db.users.find_one({'_id': material['teacher_id']})
                if teacher:
                    material['teacher_name'] = f"{teacher.get('first_name', '')} {teacher.get('last_name', '')}"
            
            return jsonify(serialize_list(materials_list))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Verify teacher is assigned to this course
            if session.get('role') == 'teacher':
                teacher_course = db.teacher_courses.find_one({
                    'teacher_id': ObjectId(session['user_id']),
                    'course_id': ObjectId(data['course_id'])
                })
                
                if not teacher_course:
                    return jsonify({'error': 'You are not assigned to this course'}), 403
            
            material = {
                'course_id': ObjectId(data['course_id']),
                'teacher_id': ObjectId(session['user_id']),
                'title': data['title'],
                'description': data.get('description', ''),
                'material_type': data['material_type'],
                'file_url': data.get('url', ''),
                'created_at': datetime.utcnow()
            }
            
            db.materials.insert_one(material)
            
            # Create notifications for enrolled students
            enrollments = list(db.enrollments.find({'course_id': ObjectId(data['course_id'])}))
            course = db.courses.find_one({'_id': ObjectId(data['course_id'])})
            
            for enrollment in enrollments:
                create_notification(
                    db,
                    str(enrollment['student_id']),
                    'New Course Material',
                    f'New material added to {course.get("title", "Course")}: {data["title"]}',
                    'material',
                    str(material['_id'])
                )
            
            return jsonify({'message': 'Material added successfully'})
        except Exception as e:
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
        notifications = list(db.notifications.find({
            'user_id': ObjectId(user_id)
        }).sort('created_at', -1))
        
        return jsonify(serialize_list(notifications))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        db = get_db()
        
        notification = db.notifications.find_one({'_id': ObjectId(notification_id)})
        if not notification:
            return jsonify({'error': 'Notification not found'}), 404
        
        if str(notification['user_id']) != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.notifications.update_one(
            {'_id': ObjectId(notification_id)},
            {'$set': {'is_read': True}}
        )
        
        return jsonify({'message': 'Notification marked as read'})
    except Exception as e:
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
        return jsonify(serialize_list(students))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/students/<student_id>/status', methods=['POST'])
@admin_required
def admin_update_student_status(student_id):
    try:
        data = request.json
        db = get_db()
        
        db.users.update_one(
            {'_id': ObjectId(student_id), 'role': 'student'},
            {'$set': {'status': data['status']}}
        )
        
        return jsonify({'message': 'Student status updated successfully'})
    except Exception as e:
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
                             'department', 'level', 'status', 'phone', 'address', 
                             'gender', 'date_of_birth']
            
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if 'password' in data and data['password']:
                update_data['password'] = generate_password_hash(data['password'])
            
            db.users.update_one(
                {'_id': ObjectId(student_id)},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Student updated successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            # Delete student's enrollments
            db.enrollments.delete_many({'student_id': ObjectId(student_id)})
            # Delete student's submissions
            db.submissions.delete_many({'student_id': ObjectId(student_id)})
            # Delete student
            db.users.delete_one({'_id': ObjectId(student_id)})
            
            return jsonify({'message': 'Student deleted successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/teachers', methods=['GET', 'POST'])
@admin_required
def admin_manage_teachers():
    db = get_db()
    
    if request.method == 'GET':
        try:
            teachers = list(db.users.find({'role': 'teacher'}).sort('created_at', -1))
            
            # Add course count for each teacher
            for teacher in teachers:
                course_count = db.teacher_courses.count_documents({'teacher_id': teacher['_id']})
                teacher['course_count'] = course_count
                
                # Get assigned courses
                teacher_courses = list(db.teacher_courses.find({'teacher_id': teacher['_id']}))
                course_ids = [tc['course_id'] for tc in teacher_courses]
                courses = list(db.courses.find({'_id': {'$in': course_ids}}))
                teacher['assigned_courses'] = serialize_list(courses)
            
            return jsonify(serialize_list(teachers))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Check if email already exists
            existing_user = db.users.find_one({'email': data['email']})
            if existing_user:
                return jsonify({'error': 'Email already exists'}), 400
            
            # Check if teacher code already exists
            existing_code = db.users.find_one({'teacher_code': data.get('teacher_code')})
            if existing_code:
                return jsonify({'error': 'Teacher code already exists'}), 400
            
            # Hash password
            hashed_password = generate_password_hash(data['password'])
            
            # Create teacher document
            teacher_data = {
                'email': data['email'],
                'password': hashed_password,
                'first_name': data['first_name'],
                'last_name': data['last_name'],
                'role': 'teacher',
                'teacher_code': data['teacher_code'],
                'department': data.get('department', ''),
                'specialization': data.get('specialization', ''),
                'status': 'active',
                'created_at': datetime.utcnow()
            }
            
            # Add optional fields if present
            optional_fields = ['phone', 'address', 'date_of_birth', 'gender']
            for field in optional_fields:
                if field in data:
                    teacher_data[field] = data[field]
            
            # Insert into database
            result = db.users.insert_one(teacher_data)
            teacher_id = str(result.inserted_id)
            
            return jsonify({
                'message': 'Teacher account created successfully',
                'teacher_id': teacher_id,
                'teacher_code': data['teacher_code']
            }), 201
            
        except DuplicateKeyError as e:
            return jsonify({'error': 'Duplicate key error. Email or teacher code already exists.'}), 400
        except Exception as e:
            return jsonify({'error': f'Failed to create teacher account: {str(e)}'}), 500

@app.route('/api/admin/teachers/<teacher_id>/details', methods=['GET'])
@admin_required
def admin_get_teacher_details(teacher_id):
    try:
        db = get_db()
        
        # Get teacher info
        teacher = db.users.find_one({'_id': ObjectId(teacher_id)})
        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404
        
        # Get assigned courses
        teacher_courses = list(db.teacher_courses.find({'teacher_id': ObjectId(teacher_id)}))
        course_ids = [tc['course_id'] for tc in teacher_courses]
        courses = list(db.courses.find({'_id': {'$in': course_ids}}))
        
        # Get recent announcements by this teacher
        recent_announcements = list(db.announcements.find(
            {'teacher_id': ObjectId(teacher_id)}).sort('created_at', -1).limit(5))
        
        # Get recent assignments by this teacher
        recent_assignments = list(db.assignments.find(
            {'teacher_id': ObjectId(teacher_id)}).sort('created_at', -1).limit(5))
        
        return jsonify({
            'teacher': serialize_doc(teacher),
            'courses': serialize_list(courses),
            'announcements': serialize_list(recent_announcements),
            'assignments': serialize_list(recent_assignments)
        })
    except Exception as e:
        return jsonify({'error': f'Failed to fetch teacher details: {str(e)}'}), 500

@app.route('/api/admin/teachers/<teacher_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_update_teacher(teacher_id):
    db = get_db()
    
    if request.method == 'PUT':
        try:
            data = request.json
            
            # Check if teacher exists
            teacher = db.users.find_one({'_id': ObjectId(teacher_id), 'role': 'teacher'})
            if not teacher:
                return jsonify({'error': 'Teacher not found'}), 404
            
            # Update data
            update_data = {}
            
            # Basic fields
            basic_fields = ['first_name', 'last_name', 'email', 'teacher_code', 
                           'department', 'specialization', 'phone', 'address', 
                           'date_of_birth', 'gender', 'status']
            
            for field in basic_fields:
                if field in data:
                    update_data[field] = data[field]
            
            # Update password if provided
            if 'password' in data and data['password']:
                update_data['password'] = generate_password_hash(data['password'])
            
            # Check for duplicate email
            if 'email' in update_data:
                existing_email = db.users.find_one({
                    'email': update_data['email'],
                    '_id': {'$ne': ObjectId(teacher_id)}
                })
                if existing_email:
                    return jsonify({'error': 'Email already in use by another user'}), 400
            
            # Check for duplicate teacher code
            if 'teacher_code' in update_data:
                existing_code = db.users.find_one({
                    'teacher_code': update_data['teacher_code'],
                    '_id': {'$ne': ObjectId(teacher_id)}
                })
                if existing_code:
                    return jsonify({'error': 'Teacher code already in use by another teacher'}), 400
            
            # Update teacher
            db.users.update_one(
                {'_id': ObjectId(teacher_id)},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Teacher account updated successfully'})
        except Exception as e:
            return jsonify({'error': f'Failed to update teacher: {str(e)}'}), 500
    
    elif request.method == 'DELETE':
        try:
            # Check if teacher exists
            teacher = db.users.find_one({'_id': ObjectId(teacher_id), 'role': 'teacher'})
            if not teacher:
                return jsonify({'error': 'Teacher not found'}), 404
            
            # Remove teacher from all courses
            db.teacher_courses.delete_many({'teacher_id': ObjectId(teacher_id)})
            
            # Delete teacher account
            db.users.delete_one({'_id': ObjectId(teacher_id)})
            
            return jsonify({'message': 'Teacher account deleted successfully'})
        except Exception as e:
            return jsonify({'error': f'Failed to delete teacher: {str(e)}'}), 500

@app.route('/api/admin/courses', methods=['GET', 'POST'])
@admin_required
def admin_manage_courses():
    db = get_db()
    
    if request.method == 'GET':
        try:
            courses = list(db.courses.find().sort('created_at', -1))
            
            # Add teacher info for each course
            for course in courses:
                teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
                teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
                teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
                course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
            
            return jsonify(serialize_list(courses))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Check if course code already exists
            existing_course = db.courses.find_one({'course_code': data['course_code']})
            if existing_course:
                return jsonify({'error': 'Course code already exists'}), 400
            
            course_data = {
                'title': data['title'],
                'course_code': data['course_code'],
                'description': data.get('description', ''),
                'credits': data['credits'],
                'teacher_lock': bool(data.get('teacher_lock', True)),
                'status': 'active',
                'level': data.get('level', 'all'),
                'department': data.get('department', 'all'),
                'is_compulsory': data.get('is_compulsory', False),
                'created_at': datetime.utcnow()
            }
            
            result = db.courses.insert_one(course_data)
            
            return jsonify({
                'message': 'Course created successfully',
                'course_id': str(result.inserted_id)
            }), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/courses/<course_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_update_course(course_id):
    db = get_db()
    
    if request.method == 'PUT':
        try:
            data = request.json
            
            update_data = {}
            allowed_fields = ['title', 'course_code', 'description', 'credits', 
                             'teacher_lock', 'status', 'level', 'department', 'is_compulsory']
            
            for field in allowed_fields:
                if field in data:
                    if field == 'teacher_lock':
                        update_data[field] = bool(data[field])
                    else:
                        update_data[field] = data[field]
            
            # Check for duplicate course code
            if 'course_code' in update_data:
                existing_course = db.courses.find_one({
                    'course_code': update_data['course_code'],
                    '_id': {'$ne': ObjectId(course_id)}
                })
                if existing_course:
                    return jsonify({'error': 'Course code already in use by another course'}), 400
            
            db.courses.update_one(
                {'_id': ObjectId(course_id)},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Course updated successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            # Check if course has enrollments
            enrollment_count = db.enrollments.count_documents({'course_id': ObjectId(course_id)})
            
            if enrollment_count > 0:
                # Deactivate course instead of deleting
                db.courses.update_one(
                    {'_id': ObjectId(course_id)},
                    {'$set': {'status': 'inactive'}}
                )
                return jsonify({
                    'deactivated': True,
                    'message': 'Course deactivated (has active enrollments)'
                })
            else:
                # Delete course and related data
                db.teacher_courses.delete_many({'course_id': ObjectId(course_id)})
                db.announcements.delete_many({'course_id': ObjectId(course_id)})
                db.assignments.delete_many({'course_id': ObjectId(course_id)})
                db.materials.delete_many({'course_id': ObjectId(course_id)})
                db.discussion_posts.delete_many({'course_id': ObjectId(course_id)})
                db.courses.delete_one({'_id': ObjectId(course_id)})
                
                return jsonify({'message': 'Course deleted successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
@app.route('/api/courses/<course_id>/admin-details', methods=['GET'])
@admin_required
def get_course_admin_details(course_id):
    try:
        db = get_db()
        course = db.courses.find_one({'_id': ObjectId(course_id)})
        
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        
        # Get teacher info
        teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
        teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
        teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
        course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
        
        # Get enrollment count
        enrollment_count = db.enrollments.count_documents({'course_id': course['_id']})
        course['enrollment_count'] = enrollment_count
        
        return jsonify(serialize_doc(course))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/compulsory-courses', methods=['GET', 'POST', 'PUT'])
@admin_required
def admin_compulsory_courses():
    db = get_db()
    
    if request.method == 'GET':
        try:
            # Group compulsory courses by level
            compulsory_courses = list(db.courses.find({'is_compulsory': True}).sort('level', 1))
            
            courses_by_level = {}
            for course in compulsory_courses:
                level = course.get('level', 'Unknown')
                if level not in courses_by_level:
                    courses_by_level[level] = []
                courses_by_level[level].append(serialize_doc(course))
            
            return jsonify(courses_by_level)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Check if course code exists
            existing_course = db.courses.find_one({'course_code': data['course_code']})
            if existing_course:
                return jsonify({'error': 'Course code already exists'}), 400
            
            course_data = {
                'title': data['title'],
                'course_code': data['course_code'],
                'description': data.get('description', ''),
                'credits': data['credits'],
                'teacher_lock': True,
                'status': 'active',
                'level': data['level'],
                'department': 'all',
                'is_compulsory': True,
                'created_at': datetime.utcnow()
            }
            
            result = db.courses.insert_one(course_data)
            course_id = result.inserted_id
            
            # Auto-enroll students in this level
            if data.get('auto_enroll', True):
                students = list(db.users.find({
                    'role': 'student',
                    'level': data['level']
                }))
                
                enrollments = []
                for student in students:
                    enrollments.append({
                        'student_id': student['_id'],
                        'course_id': course_id,
                        'enrolled_at': datetime.utcnow()
                    })
                
                if enrollments:
                    db.enrollments.insert_many(enrollments, ordered=False)
                
                return jsonify({
                    'message': f'Compulsory course created and {len(students)} students auto-enrolled',
                    'auto_enrolled_count': len(students)
                })
            
            return jsonify({
                'message': 'Compulsory course created successfully',
                'auto_enrolled_count': 0
            })
        except Exception as e:
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
                    update_data[field] = data[field]
            
            # Check for duplicate course code
            if 'course_code' in update_data:
                existing_course = db.courses.find_one({
                    'course_code': update_data['course_code'],
                    '_id': {'$ne': ObjectId(course_id)}
                })
                if existing_course:
                    return jsonify({'error': 'Course code already in use by another course'}), 400
            
            db.courses.update_one(
                {'_id': ObjectId(course_id)},
                {'$set': update_data}
            )
            
            return jsonify({'message': 'Compulsory course updated successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/admin/compulsory-courses/<course_id>', methods=['DELETE'])
@admin_required
def admin_delete_compulsory_course(course_id):
    try:
        db = get_db()
        
        # Check if course exists and is compulsory
        course = db.courses.find_one({'_id': ObjectId(course_id), 'is_compulsory': True})
        if not course:
            return jsonify({'error': 'Compulsory course not found'}), 404
        
        # Remove enrollments for this course
        db.enrollments.delete_many({'course_id': ObjectId(course_id)})
        
        # Delete the course
        db.courses.delete_one({'_id': ObjectId(course_id)})
        
        return jsonify({'message': 'Compulsory course deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/departments/courses', methods=['GET'])
@admin_required
def admin_get_department_courses():
    try:
        department = request.args.get('department')
        level = request.args.get('level')
        
        if not department or not level:
            return jsonify({'error': 'Department and level required'}), 400
        
        db = get_db()
        
        query = {
            'department': department,
            'level': level,
            'is_compulsory': False
        }
        
        courses = list(db.courses.find(query).sort('created_at', -1))
        
        # Add additional info for each course
        for course in courses:
            # Get teacher info
            teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
            teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
            teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
            course['teacher_names'] = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers])
            
            # Get enrollment count
            enrollment_count = db.enrollments.count_documents({'course_id': course['_id']})
            course['enrolled_students'] = enrollment_count
        
        return jsonify(serialize_list(courses))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/departments/deploy-courses', methods=['POST'])
@admin_required
def admin_deploy_department_courses():
    try:
        data = request.json
        db = get_db()
        
        department = data['department']
        level = data['level']
        courses_data = data['courses']
        
        deployed_courses = []
        auto_enrolled_count = 0
        
        for course_data in courses_data:
            # Check if course already exists
            existing_course = db.courses.find_one({
                'course_code': course_data['code'],
                'department': department,
                'level': level
            })
            
            if existing_course:
                # Update existing course
                db.courses.update_one(
                    {'_id': existing_course['_id']},
                    {'$set': {
                        'title': course_data['title'],
                        'description': course_data['description'],
                        'credits': course_data['credits'],
                        'teacher_lock': course_data.get('teacher_lock', True),
                        'status': 'active'
                    }}
                )
                course_id = existing_course['_id']
            else:
                # Create new course
                course_doc = {
                    'title': course_data['title'],
                    'course_code': course_data['code'],
                    'description': course_data['description'],
                    'credits': course_data['credits'],
                    'teacher_lock': course_data.get('teacher_lock', True),
                    'status': 'active',
                    'level': level,
                    'department': department,
                    'is_compulsory': False,
                    'created_at': datetime.utcnow()
                }
                
                result = db.courses.insert_one(course_doc)
                course_id = result.inserted_id
            
            # For HS levels, auto-enroll students
            if level.startswith('HS'):
                students = list(db.users.find({
                    'role': 'student',
                    'level': level,
                    'department': department
                }))
                
                for student in students:
                    # Check if already enrolled
                    existing_enrollment = db.enrollments.find_one({
                        'student_id': student['_id'],
                        'course_id': course_id
                    })
                    
                    if not existing_enrollment:
                        enrollment = {
                            'student_id': student['_id'],
                            'course_id': course_id,
                            'enrolled_at': datetime.utcnow()
                        }
                        db.enrollments.insert_one(enrollment)
                        auto_enrolled_count += 1
            
            deployed_courses.append(course_data['title'])
        
        return jsonify({
            'message': f'Successfully deployed {len(deployed_courses)} courses for {department} department ({level})',
            'deployed_courses': deployed_courses,
            'auto_enrolled_students': auto_enrolled_count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/clear-all-courses', methods=['DELETE'])
@admin_required
def admin_clear_all_courses():
    try:
        db = get_db()
        
        # Count before deletion
        course_count = db.courses.count_documents({})
        
        # Delete all courses and related data
        db.courses.delete_many({})
        db.teacher_courses.delete_many({})
        db.enrollments.delete_many({})
        db.announcements.delete_many({})
        db.assignments.delete_many({})
        db.submissions.delete_many({})
        db.materials.delete_many({})
        db.discussion_posts.delete_many({})
        db.discussion_replies.delete_many({})
        
        return jsonify({
            'message': f'Successfully cleared all {course_count} courses and related data',
            'courses_cleared': course_count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/enrollments', methods=['GET'])
@admin_required
def admin_get_all_enrollments():
    try:
        db = get_db()
        
        enrollments = list(db.enrollments.find().sort('enrolled_at', -1))
        
        # Add student and course info
        result = []
        for enrollment in enrollments:
            student = db.users.find_one({'_id': enrollment['student_id']})
            course = db.courses.find_one({'_id': enrollment['course_id']})
            
            if student and course:
                result.append({
                    'id': str(enrollment['_id']),
                    'first_name': student.get('first_name', ''),
                    'last_name': student.get('last_name', ''),
                    'student_id': student.get('student_id', ''),
                    'email': student.get('email', ''),
                    'level': student.get('level', ''),
                    'department': student.get('department', ''),
                    'course_title': course.get('title', ''),
                    'course_code': course.get('course_code', ''),
                    'enrolled_at': enrollment.get('enrolled_at')
                })
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/enrollments/search', methods=['GET'])
@admin_required
def admin_search_enrollments():
    try:
        search_term = request.args.get('q', '')
        db = get_db()
        
        # Search in students and courses
        students = list(db.users.find({
            'role': 'student',
            '$or': [
                {'first_name': {'$regex': search_term, '$options': 'i'}},
                {'last_name': {'$regex': search_term, '$options': 'i'}},
                {'email': {'$regex': search_term, '$options': 'i'}},
                {'student_id': {'$regex': search_term, '$options': 'i'}}
            ]
        }))
        
        courses = list(db.courses.find({
            '$or': [
                {'title': {'$regex': search_term, '$options': 'i'}},
                {'course_code': {'$regex': search_term, '$options': 'i'}}
            ]
        }))
        
        student_ids = [s['_id'] for s in students]
        course_ids = [c['_id'] for c in courses]
        
        query = {'$or': []}
        if student_ids:
            query['$or'].append({'student_id': {'$in': student_ids}})
        if course_ids:
            query['$or'].append({'course_id': {'$in': course_ids}})
        
        if not query['$or']:
            return jsonify([])
        
        enrollments = list(db.enrollments.find(query).sort('enrolled_at', -1))
        
        # Add student and course info
        result = []
        for enrollment in enrollments:
            student = db.users.find_one({'_id': enrollment['student_id']})
            course = db.courses.find_one({'_id': enrollment['course_id']})
            
            if student and course:
                result.append({
                    'id': str(enrollment['_id']),
                    'first_name': student.get('first_name', ''),
                    'last_name': student.get('last_name', ''),
                    'student_id': student.get('student_id', ''),
                    'email': student.get('email', ''),
                    'level': student.get('level', ''),
                    'department': student.get('department', ''),
                    'course_title': course.get('title', ''),
                    'course_code': course.get('course_code', ''),
                    'enrolled_at': enrollment.get('enrolled_at')
                })
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/enrollments/<enrollment_id>', methods=['DELETE'])
@admin_required
def admin_delete_enrollment(enrollment_id):
    try:
        db = get_db()
        
        result = db.enrollments.delete_one({'_id': ObjectId(enrollment_id)})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Enrollment not found'}), 404
        
        return jsonify({'message': 'Enrollment deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/students/<student_id>/enrollments', methods=['GET'])
@admin_required
def admin_get_student_enrollments(student_id):
    try:
        db = get_db()
        
        enrollments = list(db.enrollments.find({'student_id': ObjectId(student_id)}))
        
        result = []
        for enrollment in enrollments:
            course = db.courses.find_one({'_id': enrollment['course_id']})
            
            if course:
                # Get teacher info
                teacher_courses = list(db.teacher_courses.find({'course_id': course['_id']}))
                teacher_ids = [tc['teacher_id'] for tc in teacher_courses]
                teachers = list(db.users.find({'_id': {'$in': teacher_ids}}))
                teacher_name = ', '.join([f"{t['first_name']} {t['last_name']}" for t in teachers]) if teachers else 'Not assigned'
                
                result.append({
                    'id': str(enrollment['_id']),
                    'title': course.get('title', ''),
                    'course_code': course.get('course_code', ''),
                    'credits': course.get('credits', 0),
                    'teacher_name': teacher_name,
                    'status': course.get('status', '')
                })
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/announcements', methods=['POST'])
@admin_required
def admin_create_announcement():
    try:
        data = request.json
        db = get_db()
        
        admin = db.users.find_one({'_id': ObjectId(session['user_id'])})
        
        announcement = {
            'title': data['title'],
            'content': data['content'],
            'target': data['target'],  # 'teachers' or 'students'
            'admin_id': ObjectId(session['user_id']),
            'admin_name': f"{admin.get('first_name', '')} {admin.get('last_name', '')}",
            'created_at': datetime.utcnow()
        }
        
        result = db.admin_announcements.insert_one(announcement)
        
        # Create notifications for target users
        if data['target'] == 'teachers':
            users = list(db.users.find({'role': 'teacher', 'status': 'active'}))
        else:  # students
            users = list(db.users.find({'role': 'student', 'status': 'active'}))
        
        for user in users:
            create_notification(
                db,
                str(user['_id']),
                f'Admin Announcement: {data["title"]}',
                data['content'],
                'admin_announcement',
                str(result.inserted_id)
            )
        
        return jsonify({'message': 'Announcement sent successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/announcements/recent', methods=['GET'])
@admin_required
def admin_get_recent_announcements():
    try:
        db = get_db()
        
        announcements = list(db.admin_announcements.find().sort('created_at', -1).limit(10))
        
        return jsonify(serialize_list(announcements))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/pending-approvals', methods=['GET'])
@admin_required
def admin_get_pending_approvals():
    try:
        db = get_db()
        
        approvals = list(db.course_approval_requests.find({'status': 'pending'}).sort('requested_at', -1))
        
        result = []
        for approval in approvals:
            teacher = db.users.find_one({'_id': approval['teacher_id']})
            course = db.courses.find_one({'_id': approval['course_id']})
            
            if teacher and course:
                # Check if course has current teacher
                current_teacher = db.teacher_courses.find_one({'course_id': approval['course_id']})
                current_teacher_name = 'Not assigned'
                if current_teacher:
                    current_teacher_user = db.users.find_one({'_id': current_teacher['teacher_id']})
                    if current_teacher_user:
                        current_teacher_name = f"{current_teacher_user['first_name']} {current_teacher_user['last_name']}"
                
                result.append({
                    'request_id': str(approval['_id']),
                    'teacher_first_name': teacher.get('first_name', ''),
                    'teacher_last_name': teacher.get('last_name', ''),
                    'teacher_code': teacher.get('teacher_code', ''),
                    'course_title': course.get('title', ''),
                    'course_code': course.get('course_code', ''),
                    'current_teacher': current_teacher_name,
                    'requested_at': approval.get('requested_at')
                })
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/approve-course-request/<request_id>', methods=['POST'])
@admin_required
def admin_approve_course_request(request_id):
    try:
        data = request.json
        db = get_db()
        
        # Get the approval request
        approval = db.course_approval_requests.find_one({'_id': ObjectId(request_id)})
        if not approval:
            return jsonify({'error': 'Approval request not found'}), 404
        
        if data['action'] == 'approve':
            # Check if course has current teacher
            current_teacher = db.teacher_courses.find_one({'course_id': approval['course_id']})
            
            if current_teacher and not data.get('reassign', False):
                # Course already has a teacher, need reassignment confirmation
                current_teacher_user = db.users.find_one({'_id': current_teacher['teacher_id']})
                course = db.courses.find_one({'_id': approval['course_id']})
                
                return jsonify({
                    'error': 'Course already assigned',
                    'current_teacher': f"{current_teacher_user.get('first_name', '')} {current_teacher_user.get('last_name', '')}",
                    'course_title': course.get('title', '') if course else ''
                }), 409
            
            # Remove current teacher if reassigning
            if current_teacher:
                db.teacher_courses.delete_one({'course_id': approval['course_id']})
            
            # Assign course to requesting teacher
            assignment = {
                'teacher_id': approval['teacher_id'],
                'course_id': approval['course_id'],
                'assigned_at': datetime.utcnow()
            }
            
            try:
                db.teacher_courses.insert_one(assignment)
            except DuplicateKeyError:
                pass
            
            # Update approval status
            db.course_approval_requests.update_one(
                {'_id': ObjectId(request_id)},
                {'$set': {
                    'status': 'approved',
                    'reviewed_at': datetime.utcnow(),
                    'admin_id': ObjectId(session['user_id']),
                    'admin_notes': data.get('notes', '')
                }}
            )
            
            # Create notification for teacher
            course = db.courses.find_one({'_id': approval['course_id']})
            create_notification(
                db,
                str(approval['teacher_id']),
                'Course Request Approved',
                f'Your request to teach {course.get("title", "course")} has been approved',
                'approval',
                str(approval['course_id'])
            )
            
            return jsonify({'message': 'Course request approved successfully'})
        
        elif data['action'] == 'reject':
            # Update approval status
            db.course_approval_requests.update_one(
                {'_id': ObjectId(request_id)},
                {'$set': {
                    'status': 'rejected',
                    'reviewed_at': datetime.utcnow(),
                    'admin_id': ObjectId(session['user_id']),
                    'admin_notes': data.get('notes', '')
                }}
            )
            
            # Create notification for teacher
            course = db.courses.find_one({'_id': approval['course_id']})
            create_notification(
                db,
                str(approval['teacher_id']),
                'Course Request Rejected',
                f'Your request to teach {course.get("title", "course")} has been rejected',
                'approval',
                str(approval['course_id'])
            )
            
            return jsonify({'message': 'Course request rejected successfully'})
        
        else:
            return jsonify({'error': 'Invalid action'}), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/approval-history', methods=['GET'])
@admin_required
def admin_get_approval_history():
    try:
        db = get_db()
        
        approvals = list(db.course_approval_requests.find().sort('requested_at', -1))
        
        result = []
        for approval in approvals:
            teacher = db.users.find_one({'_id': approval['teacher_id']})
            course = db.courses.find_one({'_id': approval['course_id']})
            admin = db.users.find_one({'_id': approval.get('admin_id')}) if approval.get('admin_id') else None
            
            if teacher and course:
                result.append({
                    'teacher_first_name': teacher.get('first_name', ''),
                    'teacher_last_name': teacher.get('last_name', ''),
                    'course_title': course.get('title', ''),
                    'status': approval.get('status', ''),
                    'requested_at': approval.get('requested_at'),
                    'reviewed_at': approval.get('reviewed_at'),
                    'admin_name': f"{admin.get('first_name', '')} {admin.get('last_name', '')}" if admin else '',
                    'admin_notes': approval.get('admin_notes', '')
                })
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/backup', methods=['GET'])
@admin_required
def admin_backup_database():
    try:
        db = get_db()
        
        # Get all collections data
        backup_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'collections': {}
        }
        
        collections = ['users', 'courses', 'teacher_courses', 'enrollments', 
                      'announcements', 'assignments', 'submissions', 'materials',
                      'discussion_posts', 'discussion_replies', 'notifications',
                      'admin_announcements', 'course_approval_requests']
        
        for collection_name in collections:
            collection = db[collection_name]
            documents = list(collection.find())
            backup_data['collections'][collection_name] = serialize_list(documents)
        
        # Return as JSON
        from flask import make_response
        response = make_response(json.dumps(backup_data, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=lms_backup_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
        
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/reset', methods=['POST'])
@admin_required
def admin_reset_system():
    try:
        db = get_db()
        
        # Keep admin accounts
        admins = list(db.users.find({'role': 'admin'}))
        
        # Clear all data except admin accounts
        collections_to_clear = ['courses', 'teacher_courses', 'enrollments', 
                              'announcements', 'assignments', 'submissions', 'materials',
                              'discussion_posts', 'discussion_replies', 'notifications',
                              'admin_announcements', 'course_approval_requests']
        
        # Clear student and teacher accounts
        db.users.delete_many({'role': {'$in': ['student', 'teacher']}})
        
        # Clear other collections
        for collection_name in collections_to_clear:
            db[collection_name].delete_many({})
        
        return jsonify({'message': 'System reset successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==============================================
# MAIN ENTRY POINT
# ==============================================

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("🎓 SCHOOL LEARNING MANAGEMENT SYSTEM (MongoDB)")
    print("="*60)
    print("\n📌 Open your browser and go to:")
    print("   ➡️  http://localhost:5000")
    print("\n🔐 Login Credentials:")
    print("   👑 Admin:      admin@school.edu / admin123")
    print("   👨‍🏫 Teacher:   teacher@school.edu / teacher123")
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