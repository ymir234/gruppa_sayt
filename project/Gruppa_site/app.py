import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from functools import wraps
import secrets
import re
import time
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
import shutil
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import sqlite3
from contextlib import contextmanager

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Xavfsizlik sozlamalari
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=1800,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Rasm formatlari
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 16 * 1024 * 1024
if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application startup')
# Brute force himoyasi
failed_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 900

def allowed_file(filename):
    if not filename:
        return False
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_locked_out(ip):
    if ip in failed_attempts:
        if failed_attempts[ip]['count'] >= MAX_LOGIN_ATTEMPTS:
            time_elapsed = time.time() - failed_attempts[ip]['time']
            if time_elapsed < LOCKOUT_TIME:
                return True
            else:
                del failed_attempts[ip]
    return False
# Eski get_db_connection ni o'chirib, faqat yangisini ishlating
@contextmanager
def get_db_connection():
    conn = sqlite3.connect('mysite.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Barcha conn = get_db_connection() larni shu bilan almashtiring
def record_failed_attempt(ip):
    if ip not in failed_attempts:
        failed_attempts[ip] = {'count': 0, 'time': time.time()}
    failed_attempts[ip]['count'] += 1
    failed_attempts[ip]['time'] = time.time()

def clear_failed_attempts(ip):
    if ip in failed_attempts:
        del failed_attempts[ip]

def validate_phone(phone):
    pattern = r'^\+998[0-9]{9}$|^998[0-9]{9}$|^[0-9]{9}$'
    return bool(re.match(pattern, phone))

def sanitize_input(text):
    if not text:
        return text
    return str(text).replace('<', '&lt;').replace('>', '&gt;')

def format_subject(subject, lesson_type):
    if subject == "Dinshunoslik":
        if lesson_type not in ["Amaliy", "Seminar"]:
            lesson_type = "Amaliy"
    else:
        if lesson_type not in ["Ma'ruza", "Amaliy"]:
            lesson_type = "Ma'ruza"
    return f"{subject} ({lesson_type})"

# login_required dekoratorini yangilang
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            flash("Iltimos, avval tizimga kiring!", "danger")
            return redirect(url_for("admin_login_page"))
        
        # Session muddatini tekshirish
        login_time = session.get('login_time', 0)
        session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']
        
        # timedelta ni songa aylantirish (sekundlarda)
        if isinstance(session_lifetime, timedelta):
            session_lifetime_seconds = session_lifetime.total_seconds()
        else:
            session_lifetime_seconds = session_lifetime
            
        if time.time() - login_time > session_lifetime_seconds:
            session.clear()
            flash("Session muddati tugadi. Iltimos, qayta kiring!", "warning")
            return redirect(url_for("admin_login_page"))
            
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            flash("Iltimos, avval tizimga kiring!", "danger")
            return redirect(url_for("admin_login_page"))
        
        if session.get("admin_role") != "superadmin":
            flash("Sizda bu amalni bajarish uchun ruxsat yo'q!", "danger")
            return redirect(url_for("admin_panel"))
            
        return f(*args, **kwargs)
    return decorated_function
# Session muddatini boshqarish (app.py ning boshiga, init_db() dan oldin)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Productionda True qiling
    PERMANENT_SESSION_LIFETIME=1800,  # 30 daqiqa
    SESSION_COOKIE_SAMESITE='Lax'
)
# app.py ga qo'shing
def enhanced_password_validation(password):
    """Kuchliroq parol tekshiruvi"""
    if len(password) < 10:
        return "Parol kamida 10 ta belgidan iborat bo'lishi kerak"
    if not re.search(r"[A-Z]", password):
        return "Parol kamida 1 ta katta harfdan iborat bo'lishi kerak"
    if not re.search(r"[a-z]", password):
        return "Parol kamida 1 ta kichik harfdan iborat bo'lishi kerak"
    if not re.search(r"[0-9]", password):
        return "Parol kamida 1 ta raqamdan iborat bo'lishi kerak"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Parol kamida 1 ta maxsus belgidan iborat bo'lishi kerak"
    if re.search(r"(.)\1{2,}", password):
        return "Parolda bir xil belgilar ketma-ket takrorlanmasligi kerak"
    return None

# app.py ga qo'shing


# csrf = CSRFProtect()
# csrf.init_app(app)

# Barcha POST formlariga CSRF token qo'shing
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

# Error handling decorator (init_db() dan oldin)
def safe_db_operation(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.Error as e:
            flash('Database xatosi yuz berdi', 'danger')
            print(f"Database error: {e}")
            return redirect(url_for('admin_panel'))
        except Exception as e:
            flash('Xatolik yuz berdi', 'danger')
            print(f"Error: {e}")
            return redirect(url_for('admin_panel'))
    return wrapper

# File upload yaxshilash (allowed_file() funksiyasidan keyin)
import re

def secure_filename(filename):
    """Fayl nomini xavfsizlashtirish"""
    if not filename:
        return ""
    # Faqat harflar, raqamlar, nuqta va chiziqcha qoldirish
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    return filename

def check_file_limits(files, max_files=5, max_total_size=50*1024*1024):
    """Fayl chegaralarini tekshirish"""
    if len(files) > max_files:
        raise ValueError(f"Maksimum {max_files} ta fayl yuklash mumkin")
    
    total_size = 0
    for file in files:
        file.seek(0, 2)  # Oxiriga o'tish
        file_size = file.tell()
        file.seek(0)  # Boshiga qaytish
        total_size += file_size
    
    if total_size > max_total_size:
        raise ValueError("Jami fayl hajmi 50MB dan oshmasligi kerak")
    
    return True
def save_uploaded_file(file, prefix):
    if file and file.filename:
        print(f"DEBUG: Original filename: {file.filename}")  # Debug
        print(f"DEBUG: File content type: {file.content_type}")  # Debug
        
        if not allowed_file(file.filename):
            raise ValueError("Faqat rasm fayllari (PNG, JPG, JPEG, GIF) yuklash mumkin")
        
        # Fayl hajmini tekshirish
        file.seek(0, 2)  # Oxiriga o'tish
        file_size = file.tell()
        file.seek(0)  # Boshiga qaytish
        
        print(f"DEBUG: File size: {file_size} bytes")  # Debug
        
        if file_size > MAX_FILE_SIZE:
            raise ValueError("Rasm hajmi 16MB dan kichik bo'lishi kerak")
        
        if file_size == 0:
            raise ValueError("Fayl bo'sh")
        
        # Xavfsiz fayl nomi
        original_filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        filename = f"{prefix}_{timestamp}_{original_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        print(f"DEBUG: Saving to: {filepath}")  # Debug
        
        # Upload papkasini tekshirish
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
            print(f"DEBUG: Created upload directory: {app.config['UPLOAD_FOLDER']}")
        
        file.save(filepath)
        
        # Fayl saqlanganini tekshirish
        if os.path.exists(filepath):
            print(f"DEBUG: File saved successfully: {filepath}")
            return filename
        else:
            raise ValueError("Fayl saqlanmadi")
    
    return None
# Database yaratish
def init_db():
    conn = sqlite3.connect('mysite.db')
    c = conn.cursor()
    
    # Talabalar jadvali
    # Talabalar loginlari jadvali
    # Talaba login blokirovkasi jadvali
    c.execute('''CREATE TABLE IF NOT EXISTS student_login_blocks
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              student_id INTEGER UNIQUE NOT NULL,
              failed_attempts INTEGER DEFAULT 0,
              blocked_until TIMESTAMP,
              FOREIGN KEY (student_id) REFERENCES students (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS student_logins
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS students
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  first_name TEXT NOT NULL,
                  last_name TEXT NOT NULL,
                  phone TEXT NOT NULL,
                  social_media TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Yangiliklar jadvali
    c.execute('''CREATE TABLE IF NOT EXISTS news
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  content TEXT NOT NULL,
                  images TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Galereya jadvali
    c.execute('''CREATE TABLE IF NOT EXISTS gallery
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  description TEXT,
                  image TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Dars jadvali jadvali
    c.execute('''CREATE TABLE IF NOT EXISTS schedule
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  day TEXT NOT NULL,
                  time TEXT NOT NULL,
                  subject TEXT NOT NULL,
                  room TEXT NOT NULL,
                  teacher TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Aloqa ma'lumotlari jadvali
    c.execute('''CREATE TABLE IF NOT EXISTS contacts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  position TEXT NOT NULL,
                  phone TEXT NOT NULL,
                  telegram TEXT,
                  email TEXT,
                  address TEXT,
                  work_hours TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Adminlar jadvali
    c.execute('''CREATE TABLE IF NOT EXISTS admins
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  role TEXT NOT NULL DEFAULT 'admin',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_login TIMESTAMP)''')
    
    # Login log jadvali
    c.execute('''CREATE TABLE IF NOT EXISTS login_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  ip_address TEXT NOT NULL,
                  success BOOLEAN NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS feedbacks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  contact TEXT,
                  message TEXT NOT NULL,
                  type TEXT NOT NULL,
                  is_anonymous BOOLEAN DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()
    
    try:
        # Mavjud adminlarni tekshirish
        existing_admin = c.execute('SELECT * FROM admins WHERE username = ?', ('admin',)).fetchone()
        
        if not existing_admin:
            # YANGI ADMIN QO'SHISH
            c.execute("INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)",
                     ('admin', generate_password_hash('Admin123!'), 'superadmin'))
            
            print("=" * 50)
            print("✅ YANGI ADMIN HISOB QAYDSI YARATILDI!")
            print("👤 Login: admin")
            print("🔑 Parol: Admin123!")
            print("⚠️  Eslatma: Parolni darhol o'zgartiring!")
            print("=" * 50)
        
        # Boshlang'ich aloqa ma'lumotlari
        contacts_data = [
            ('Aziz Abdurahmonov', 'Guruh Sardori', '+998901234567', '@aziz_cyber', '', 'Toshkent shahar, Yunusobod tumani', ''),
            ('Javohir Rahimov', 'Tyutor - Guruh Rahbari', '+998977890123', '@javohir_tutor', 'j.rahimov@uni.uz', '', 'Dushanba-Juma, 14:00-16:00'),
            ('Dilnoza Xolmirzayeva', 'Ma\'naviyat Yetakchisi', '+998955678901', '@dilnoza_m', '', '', ''),
            ('Fakultet Dekanati', 'Fakultet Dekanati', '+998711234567', '', '', 'Bosh korpus, 2-qavat', 'Ish vaqti: 9:00-18:00')
        ]
        
        for contact in contacts_data:
            existing_contact = c.execute('SELECT * FROM contacts WHERE name = ? AND position = ?', 
                                       (contact[0], contact[1])).fetchone()
            if not existing_contact:
                c.execute('''INSERT INTO contacts 
                            (name, position, phone, telegram, email, address, work_hours) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)''', contact)
        
    except Exception as e:
        print(f"Xatolik admin qo'shishda: {e}")
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('mysite.db')
    conn.row_factory = sqlite3.Row
    return conn

def log_login_attempt(username, ip_address, success):
    conn = get_db_connection()
    conn.execute('INSERT INTO login_logs (username, ip_address, success) VALUES (?, ?, ?)',
                (username, ip_address, success))
    conn.commit()
    conn.close()

def validate_password(password):
    if len(password) < 8:
        return "Parol kamida 8 ta belgidan iborat bo'lishi kerak"
    if not re.search(r"[A-Z]", password):
        return "Parol kamida 1 ta katta harfdan iborat bo'lishi kerak"
    if not re.search(r"[a-z]", password):
        return "Parol kamida 1 ta kichik harfdan iborat bo'lishi kerak"
    if not re.search(r"[0-9]", password):
        return "Parol kamida 1 ta raqamdan iborat bo'lishi kerak"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Parol kamida 1 ta maxsus belgidan iborat bo'lishi kerak"
    return None

# ========== ASOSIY ROUTE'LAR ==========
@app.route("/")
def index():
    return render_template("index.html")

# students route'ini yangilang
@app.route("/students")
def students():
    conn = get_db_connection()
    # Familiya bo'yicha alfavit tartibida saralash
    students = conn.execute('SELECT * FROM students ORDER BY last_name, first_name').fetchall()
    conn.close()
    return render_template("students.html", students=students)

@app.route("/news")
def news():
    conn = get_db_connection()
    news = conn.execute('SELECT * FROM news ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template("news.html", news=news)

@app.route("/gallery")
def gallery():
    conn = get_db_connection()
    gallery = conn.execute('SELECT * FROM gallery ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template("gallery.html", gallery=gallery)

@app.route("/schedule")
def schedule():
    conn = get_db_connection()
    schedule = conn.execute('''SELECT * FROM schedule ORDER BY 
                           CASE 
                               WHEN day = "Dushanba" THEN 1
                               WHEN day = "Seshanba" THEN 2
                               WHEN day = "Chorshanba" THEN 3
                               WHEN day = "Payshanba" THEN 4
                               WHEN day = "Juma" THEN 5
                               WHEN day = "Shanba" THEN 6
                           END, time''').fetchall()
    conn.close()
    return render_template("schedule.html", schedule=schedule)
# app.py fayliga qo'shing
@app.route("/admin/edit_student_credentials/<int:student_id>", methods=["GET", "POST"])
@login_required
def edit_student_credentials(student_id):
    conn = get_db_connection()
    
    if request.method == "POST":
        new_login = sanitize_input(request.form.get("login", "").strip())
        new_password = request.form.get("password", "").strip()
        
        # Login mavjudligini tekshirish
        existing_login = conn.execute(
            'SELECT * FROM student_logins WHERE username = ? AND student_id != ?', 
            (new_login, student_id)
        ).fetchone()
        
        if existing_login:
            flash("Bu login allaqachon band!", "danger")
            return redirect(url_for("edit_student_credentials", student_id=student_id))
        
        # Yangilash
        if new_login:
            conn.execute(
                'UPDATE student_logins SET username = ? WHERE student_id = ?',
                (new_login, student_id)
            )
        
        if new_password:
            if len(new_password) < 8:
                flash("Parol kamida 8 ta belgidan iborat bo'lishi kerak!", "danger")
                return redirect(url_for("edit_student_credentials", student_id=student_id))
            
            conn.execute(
                'UPDATE student_logins SET password_hash = ? WHERE student_id = ?',
                (generate_password_hash(new_password), student_id)
            )
        
        # Blokirovkani tozalash
        conn.execute('DELETE FROM student_login_blocks WHERE student_id = ?', (student_id,))
        
        conn.commit()
        conn.close()
        
        flash("Login va parol muvaffaqiyatli yangilandi!", "success")
        return redirect(url_for("admin_panel"))
    
    else:
        # Talaba ma'lumotlarini olish
        student = conn.execute(
            'SELECT s.*, sl.username FROM students s LEFT JOIN student_logins sl ON s.id = sl.student_id WHERE s.id = ?',
            (student_id,)
        ).fetchone()
        
        conn.close()
        
        if not student:
            flash("Talaba topilmadi!", "danger")
            return redirect(url_for("admin_panel"))
        
        return render_template("edit_credentials.html", student=student)
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    conn = get_db_connection()
    
    if request.method == "POST":
        name = sanitize_input(request.form.get("name", ""))
        contact = sanitize_input(request.form.get("contact", ""))
        message = sanitize_input(request.form.get("message", ""))
        feedback_type = request.form.get("type", "")
        is_anonymous = bool(request.form.get("anonymous"))
        
        if not name or not message or not feedback_type:
            flash("Iltimos, barcha kerakli maydonlarni to'ldiring!", "danger")
            return redirect(url_for("feedback"))
        
        # Agar anonim bo'lsa, ismni yashirish
        if is_anonymous:
            name = "Anonim"
        
        conn.execute('''INSERT INTO feedbacks (name, contact, message, type, is_anonymous) 
                       VALUES (?, ?, ?, ?, ?)''',
                    (name, contact, message, feedback_type, is_anonymous))
        conn.commit()
        conn.close()
        
        flash("Fikringiz muvaffaqiyatli yuborildi! Rahmat.", "success")
        return redirect(url_for("feedback"))
    
    # Admin uchun fikrlar ro'yxati
    feedbacks = []
    if session.get("admin"):
        feedbacks = conn.execute('SELECT * FROM feedbacks ORDER BY created_at DESC').fetchall()
    
    conn.close()
    return render_template("feedback.html", feedbacks=feedbacks)

# Fikr o'chirish (admin uchun)
@app.route("/admin/delete_feedback/<int:id>", methods=["DELETE"])
@login_required
def delete_feedback(id):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM feedbacks WHERE id = ?', (id,))
        conn.commit()
        success = True
    except Exception as e:
        success = False
        print(f"Error deleting feedback: {e}")
    finally:
        conn.close()
    
    return jsonify({"success": success})


@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = request.remote_addr
        
        conn = get_db_connection()
        
        # Talaba loginini tekshirish
        student_login = conn.execute('''
            SELECT sl.*, s.first_name, s.last_name, slb.failed_attempts, slb.blocked_until
            FROM student_logins sl 
            JOIN students s ON sl.student_id = s.id 
            LEFT JOIN student_login_blocks slb ON sl.student_id = slb.student_id
            WHERE sl.username = ? AND sl.is_active = 1
        ''', (username,)).fetchone()
        
        # Blokirovka tekshirish
        if student_login and student_login['blocked_until']:
            blocked_until = datetime.fromisoformat(student_login['blocked_until'])
            if datetime.now() < blocked_until:
                remaining_time = (blocked_until - datetime.now()).seconds // 60
                flash(f"Login bloklangan! {remaining_time} daqiqadan keyin qayta urinib ko'ring.", "danger")
                conn.close()
                return render_template("student_login.html")
        
        if student_login and check_password_hash(student_login['password_hash'], password):
            # Muvaffaqiyatli kirish - blokirovkani tozalash
            conn.execute('DELETE FROM student_login_blocks WHERE student_id = ?', 
                        (student_login['student_id'],))
            
            session["student"] = True
            session["student_id"] = student_login['student_id']
            session["student_name"] = f"{student_login['first_name']} {student_login['last_name']}"
            session["student_username"] = student_login['username']
            
            # Last login yangilash
            conn.execute('UPDATE student_logins SET last_login = CURRENT_TIMESTAMP WHERE id = ?', 
                        (student_login['id'],))
            conn.commit()
            conn.close()
            
            flash(f"Xush kelibsiz, {session['student_name']}!", "success")
            return redirect(url_for("student_dashboard"))
        else:
            # Muvaffaqiyatsiz urinish
            if student_login:
                # Blokirovka jadvalini yangilash
                block_data = conn.execute('SELECT * FROM student_login_blocks WHERE student_id = ?', 
                                        (student_login['student_id'],)).fetchone()
                
                if block_data:
                    new_attempts = block_data['failed_attempts'] + 1
                    if new_attempts >= 5:
                        # 10 daqiqa blokirovka
                        blocked_until = datetime.now() + timedelta(minutes=10)
                        conn.execute('''UPDATE student_login_blocks 
                                      SET failed_attempts = ?, blocked_until = ? 
                                      WHERE student_id = ?''',
                                   (new_attempts, blocked_until.isoformat(), student_login['student_id']))
                        flash("Juda ko'p muvaffaqiyatsiz urinishlar! Login 10 daqiqaga bloklandi.", "danger")
                    else:
                        conn.execute('UPDATE student_login_blocks SET failed_attempts = ? WHERE student_id = ?',
                                   (new_attempts, student_login['student_id']))
                else:
                    conn.execute('INSERT INTO student_login_blocks (student_id, failed_attempts) VALUES (?, 1)',
                               (student_login['student_id'],))
                
                conn.commit()
            else:
                flash("Login yoki parol noto'g'ri!", "danger")
            
            conn.close()
    
    return render_template("student_login.html")
@app.route("/admin/change_student_password", methods=["POST"])
@superadmin_required
def change_student_password():
    try:
        student_id = request.form["student_id"]
        new_password = request.form["new_password"]
        
        # Parol validatsiyasi
        if len(new_password) < 8:
            return jsonify({"success": False, "message": "Parol kamida 8 ta belgidan iborat bo'lishi kerak"})
        
        conn = get_db_connection()
        
        # Talaba login mavjudligini tekshirish
        student_login = conn.execute('SELECT * FROM student_logins WHERE student_id = ?', (student_id,)).fetchone()
        
        if not student_login:
            conn.close()
            return jsonify({"success": False, "message": "Talaba logini topilmadi"})
        
        # Parolni yangilash
        conn.execute('UPDATE student_logins SET password_hash = ? WHERE student_id = ?',
                    (generate_password_hash(new_password), student_id))
        
        # Blokirovkani tozalash
        conn.execute('DELETE FROM student_login_blocks WHERE student_id = ?', (student_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Parol muvaffaqiyatli yangilandi!"})
        
    except Exception as e:
        print(f"Error changing password: {e}")
        return jsonify({"success": False, "message": "Xatolik yuz berdi"})
    
@app.route("/admin/delete_student_login/<int:id>")
@superadmin_required
def delete_student_login(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM student_logins WHERE id = ?', (id,))
    conn.execute('DELETE FROM student_login_blocks WHERE student_id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash("Talaba logini o'chirildi!", "success")
    return redirect(url_for("admin_panel"))

@app.route("/student/dashboard")
def student_dashboard():
    if "student" not in session:
        return redirect(url_for("student_login"))
    
    conn = get_db_connection()
    student_info = conn.execute('''
        SELECT s.*, sl.username, sl.last_login 
        FROM students s 
        JOIN student_logins sl ON s.id = sl.student_id 
        WHERE s.id = ?
    ''', (session["student_id"],)).fetchone()
    conn.close()
    
    return render_template("student_dashboard.html", student=student_info)

@app.route("/student/logout")
def student_logout():
    session.pop("student", None)
    session.pop("student_id", None)
    session.pop("student_name", None)
    session.pop("student_username", None)
    flash("Tizimdan chiqdingiz!", "info")
    return redirect(url_for("student_login"))
@app.route("/admin/generate_student_login", methods=["POST"])
@login_required
def generate_student_login():
    student_id = request.form["student_id"]
    username = sanitize_input(request.form["username"])
    password = request.form["password"]
    
    conn = get_db_connection()
    
    # Login mavjudligini tekshirish
    existing = conn.execute('SELECT * FROM student_logins WHERE username = ? OR student_id = ?', 
                           (username, student_id)).fetchone()
    
    if existing:
        flash("Bu talaba uchun login allaqachon mavjud yoki bu login band!", "danger")
    else:
        password_error = validate_password(password)
        if password_error:
            flash(password_error, "danger")
        else:
            conn.execute('INSERT INTO student_logins (student_id, username, password_hash) VALUES (?, ?, ?)',
                        (student_id, username, generate_password_hash(password)))
            conn.commit()
            flash("Talaba logini muvaffaqiyatli yaratildi!", "success")
    
    conn.close()
    return redirect(url_for("admin_panel"))

@app.route("/contact")
def contact():
    conn = get_db_connection()
    contacts = conn.execute('SELECT * FROM contacts ORDER BY id').fetchall()
    conn.close()
    return render_template("contact.html", contacts=contacts)

# ========== ADMIN ROUTE'LARI ==========
@app.route("/admin", methods=["GET", "POST"])
def admin_login_page():
    if "admin" in session:
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = request.remote_addr
        
        if is_locked_out(ip_address):
            remaining_time = LOCKOUT_TIME - (time.time() - failed_attempts[ip_address]['time'])
            flash(f"Juda ko'p muvaffaqiyatsiz urinishlar! Iltimos, {int(remaining_time/60)} daqiqadan keyin qayta urinib ko'ring.", "danger")
            log_login_attempt(username, ip_address, False)
            return render_template("admin_login.html")
        
        if not username or not password:
            flash("Iltimos, login va parolni kiriting!", "danger")
            log_login_attempt(username, ip_address, False)
            record_failed_attempt(ip_address)
            return render_template("admin_login.html")
        
        if any(char in username for char in ['\'', '"', ';', '--']):
            flash("Noto'g'ri login formati!", "danger")
            log_login_attempt(username, ip_address, False)
            record_failed_attempt(ip_address)
            return render_template("admin_login.html")
        
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
        
        if admin and check_password_hash(admin['password_hash'], password):
            session["admin"] = True
            session["admin_role"] = admin['role']
            session["admin_username"] = admin['username']
            session["login_time"] = time.time()
            
            try:
                conn.execute('UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE username = ?', (username,))
            except sqlite3.OperationalError:
                pass
            
            conn.commit()
            conn.close()
            
            clear_failed_attempts(ip_address)
            log_login_attempt(username, ip_address, True)
            flash(f"Xush kelibsiz, {admin['username']}!", "success")
            return redirect(url_for("admin_panel"))
        else:
            conn.close()
            record_failed_attempt(ip_address)
            log_login_attempt(username, ip_address, False)
            attempts_left = MAX_LOGIN_ATTEMPTS - failed_attempts[ip_address]['count']
            
            if attempts_left > 0:
                flash(f"Login yoki parol noto'g'ri! {attempts_left} ta urinish qoldi.", "danger")
            else:
                flash("Juda ko'p muvaffaqiyatsiz urinishlar! Iltimos, 15 daqiqadan keyin qayta urinib ko'ring.", "danger")

    return render_template("admin_login.html")

@app.route("/admin/panel")
@login_required
def admin_panel():
    conn = get_db_connection()
    students = conn.execute('SELECT * FROM students ORDER BY last_name, first_name').fetchall()    
    news = conn.execute('SELECT * FROM news ORDER BY created_at DESC').fetchall()
    gallery = conn.execute('SELECT * FROM gallery ORDER BY created_at DESC').fetchall()
    schedule = conn.execute('SELECT * FROM schedule').fetchall()
    contacts = conn.execute('SELECT * FROM contacts ORDER BY id').fetchall()
    admins = conn.execute('SELECT * FROM admins').fetchall()
    
    # Talaba loginlari
    student_logins = {}
    login_data = conn.execute('''
        SELECT sl.*, s.first_name, s.last_name 
        FROM student_logins sl 
        JOIN students s ON sl.student_id = s.id
    ''').fetchall()
    
    for login in login_data:
        student_logins[login['student_id']] = login
    
    # Statistika ma'lumotlari (faqat modal uchun)
    stats = {
        'total_students': len(students),
        'total_news': len(news),
        'total_gallery': len(gallery),
        'recent_logins': conn.execute('''
            SELECT ll.*, COALESCE(a.username, sl.username) as display_username
            FROM login_logs ll 
            LEFT JOIN admins a ON ll.username = a.username 
            LEFT JOIN student_logins sl ON ll.username = sl.username 
            ORDER BY ll.timestamp DESC LIMIT 10
        ''').fetchall()
    }
    feedbacks_count = conn.execute('SELECT COUNT(*) FROM feedbacks').fetchone()[0]
    conn.close()
    
    return render_template("admin_panel.html", 
                         students=students, 
                         news=news, 
                         gallery=gallery, 
                         schedule=schedule,
                         contacts=contacts,
                         admins=admins,
                         student_logins=student_logins,
                         stats=stats,
                         feedbacks_count=feedbacks_count) # stats ni qo'shish

# Talaba loginlari sonini qaytarish
@app.route("/admin/login_stats")
@login_required
def login_stats():
    conn = get_db_connection()
    
    total_students = conn.execute('SELECT COUNT(*) FROM students').fetchone()[0]
    students_with_login = conn.execute('SELECT COUNT(*) FROM student_logins').fetchone()[0]
    students_without_login = total_students - students_with_login
    
    conn.close()
    
    return jsonify({
        'total_students': total_students,
        'with_login': students_with_login,
        'without_login': students_without_login
    })
@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("Tizimdan chiqdingiz!", "info")
    return redirect(url_for("admin_login_page"))
# app.py ga yangi route qo'shing
@app.route("/admin/stats")
@login_required
def admin_stats():
    conn = get_db_connection()
    
    stats = {
        'total_students': conn.execute('SELECT COUNT(*) FROM students').fetchone()[0],
        'total_news': conn.execute('SELECT COUNT(*) FROM news').fetchone()[0],
        'total_gallery': conn.execute('SELECT COUNT(*) FROM gallery').fetchone()[0],
        'recent_logins': conn.execute('SELECT username, ip_address, timestamp FROM login_logs WHERE success = 1 ORDER BY timestamp DESC LIMIT 10').fetchall()
    }
    
    conn.close()
    return render_template("admin_stats.html", stats=stats)
@app.route("/admin/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        
        password_error = validate_password(new_password)
        if password_error:
            flash(password_error, "danger")
            return render_template("change_password.html")
        
        if new_password != confirm_password:
            flash("Yangi parollar mos kelmadi!", "danger")
            return render_template("change_password.html")
        
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session["admin_username"],)).fetchone()
        
        if not check_password_hash(admin['password_hash'], old_password):
            flash("Eski parol noto'g'ri!", "danger")
        else:
            if check_password_hash(admin['password_hash'], new_password):
                flash("Yangi parol eski parol bilan bir xil bo'lmasligi kerak!", "danger")
            else:
                conn.execute('UPDATE admins SET password_hash = ? WHERE username = ?',
                            (generate_password_hash(new_password), session["admin_username"]))
                conn.commit()
                flash("Parol muvaffaqiyatli yangilandi ✅", "success")
        
        conn.close()
        return redirect(url_for("admin_panel"))

    return render_template("change_password.html")

# ========== TALABALAR BO'LIMI ==========
@app.route("/admin/add_student", methods=["POST"])
@login_required
def add_student():
    if request.method == "POST":
        # Avval familiya, keyin ism
        last_name = sanitize_input(request.form["last_name"])
        first_name = sanitize_input(request.form["first_name"])
        phone = request.form["phone"]
        
        if not validate_phone(phone):
            flash("Noto'g'ri telefon raqami formati!", "danger")
            return redirect(url_for("admin_panel"))
        
        if not phone.startswith('+998'):
            phone = '+998' + phone
        
        social_media = []
        telegram = request.form.get("telegram", "").strip()
        instagram = request.form.get("instagram", "").strip()
        facebook = request.form.get("facebook", "").strip()
        
        if telegram:
            social_media.append(f"telegram:{telegram.lstrip('@')}")
        if instagram:
            social_media.append(f"instagram:{instagram}")
        if facebook:
            social_media.append(f"facebook:{facebook}")
        
        social_media_str = "|".join(social_media) if social_media else None
        
        conn = get_db_connection()
        conn.execute('INSERT INTO students (first_name, last_name, phone, social_media) VALUES (?, ?, ?, ?)',
                    (first_name, last_name, phone, social_media_str))
        conn.commit()
        conn.close()
        
        flash("Talaba muvaffaqiyatli qo'shildi!", "success")
        return redirect(url_for("admin_panel"))
# Talaba tahrirlash route'i
@app.route("/admin/edit_student/<int:id>", methods=["GET", "POST"])
@login_required
def edit_student(id):
    conn = get_db_connection()
    
    if request.method == "POST":
        # Ma'lumotlarni yangilash
        last_name = sanitize_input(request.form["last_name"])
        first_name = sanitize_input(request.form["first_name"])
        phone = request.form["phone"]
        
        if not validate_phone(phone):
            flash("Noto'g'ri telefon raqami formati!", "danger")
            return redirect(url_for("admin_panel"))
        
        if not phone.startswith('+998'):
            phone = '+998' + phone
        
        social_media = []
        telegram = request.form.get("telegram", "").strip()
        instagram = request.form.get("instagram", "").strip()
        facebook = request.form.get("facebook", "").strip()
        
        if telegram:
            social_media.append(f"telegram:{telegram.lstrip('@')}")
        if instagram:
            social_media.append(f"instagram:{instagram}")
        if facebook:
            social_media.append(f"facebook:{facebook}")
        
        social_media_str = "|".join(social_media) if social_media else None
        
        conn.execute('UPDATE students SET first_name = ?, last_name = ?, phone = ?, social_media = ? WHERE id = ?',
                    (first_name, last_name, phone, social_media_str, id))
        conn.commit()
        conn.close()
        
        flash("Talaba ma'lumotlari muvaffaqiyatli yangilandi!", "success")
        return redirect(url_for("admin_panel"))
    
    else:
        # GET so'rovi - talaba ma'lumotlarini olish
        student = conn.execute('SELECT * FROM students WHERE id = ?', (id,)).fetchone()
        conn.close()
        
        if not student:
            flash("Talaba topilmadi!", "danger")
            return redirect(url_for("admin_panel"))
        
        return render_template("edit_student.html", student=student)
    
@app.route("/admin/delete_student/<int:id>")
@login_required
def delete_student(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM students WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash("Talaba o'chirildi!", "success")
    return redirect(url_for("admin_panel"))

# ========== YANGILIKLAR BO'LIMI ==========
def save_uploaded_file(file, prefix):
    if file and file.filename:
        if not allowed_file(file.filename):
            raise ValueError("Faqat rasm fayllari (PNG, JPG, JPEG, GIF) yuklash mumkin")
        
        if len(file.read()) > MAX_FILE_SIZE:
            raise ValueError("Rasm hajmi 16MB dan kichik bo'lishi kerak")
        
        file.seek(0)
        
        filename = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return None
@app.route("/admin/backup")
@superadmin_required
def create_backup():
    """Ma'lumotlar bazasini zaxiralash"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{timestamp}.db"
        shutil.copy2('mysite.db', f'backups/{backup_filename}')
        
        # Faqat oxirgi 10 ta backup ni saqlash
        backups = sorted([f for f in os.listdir('backups') if f.startswith('backup_')])
        if len(backups) > 10:
            for old_backup in backups[:-10]:
                os.remove(f'backups/{old_backup}')
        
        flash("Backup muvaffaqiyatli yaratildi!", "success")
    except Exception as e:
        flash(f"Backup yaratishda xatolik: {str(e)}", "danger")
    
    return redirect(url_for('admin_panel'))


@app.route("/admin/add_news", methods=["POST"])
@login_required
def add_news():
    if request.method == "POST":
        title = sanitize_input(request.form["title"])
        content = sanitize_input(request.form["content"])
        images = request.files.getlist("images")  # getlist() bilan bir nechta fayl olish
        
        print(f"DEBUG: Received {len(images)} images for news")  # Debug
        
        if not title or not content:
            flash("Sarlavha va matn maydonlari to'ldirilishi shart!", "danger")
            return redirect(url_for("admin_panel"))
        
        image_filenames = []
        for i, image in enumerate(images[:5]):  # Maksimal 5 ta rasm
            if image and image.filename:  # Faqat haqiqiy fayllarni qayta ishlash
                try:
                    filename = save_uploaded_file(image, f"news_{i}")
                    if filename:
                        image_filenames.append(filename)
                        print(f"DEBUG: Saved news image {i+1}: {filename}")
                except ValueError as e:
                    flash(str(e), "danger")
                    return redirect(url_for("admin_panel"))
        
        print(f"DEBUG: Total news images saved: {len(image_filenames)}")  # Debug
        
        # Barcha rasmlarni bitta stringga birlashtirish
        images_string = ','.join(image_filenames) if image_filenames else None
        
        conn = get_db_connection()
        conn.execute('INSERT INTO news (title, content, images) VALUES (?, ?, ?)',
                    (title, content, images_string))
        conn.commit()
        conn.close()
        
        if image_filenames:
            flash(f"Yangilik muvaffaqiyatli qo'shildi! ({len(image_filenames)} ta rasm bilan)", "success")
        else:
            flash("Yangilik muvaffaqiyatli qo'shildi! (rasmsiz)", "success")
            
        return redirect(url_for("admin_panel"))
        
@app.route("/admin/delete_news/<int:id>")
@login_required
def delete_news(id):
    conn = get_db_connection()
    
    news_item = conn.execute('SELECT images FROM news WHERE id = ?', (id,)).fetchone()
    if news_item and news_item['images']:
        for image in news_item['images'].split(','):
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
            if os.path.exists(image_path):
                os.remove(image_path)
    
    conn.execute('DELETE FROM news WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash("Yangilik o'chirildi!", "success")
    return redirect(url_for("admin_panel"))

# ========== GALEREYA BO'LIMI ==========
# csrf = CSRFProtect()
# csrf.init_app(app)

@app.route("/admin/add_gallery", methods=["POST"])
@login_required
def add_gallery():
    if request.method == "POST":
        title = sanitize_input(request.form.get("title", ""))
        description = sanitize_input(request.form.get("description", ""))
        images = request.files.getlist("images")  # getlist() bilan bir nechta fayl olish
        
        print(f"DEBUG: Received {len(images)} gallery images")  # Debug
        
        if not title:
            flash("Sarlavha maydoni to'ldirilishi shart!", "danger")
            return redirect(url_for("admin_panel"))
        
        if not images or all(img.filename == '' for img in images):
            flash("Iltimos, kamida bitta rasm faylini tanlang!", "danger")
            return redirect(url_for("admin_panel"))
        
        saved_images = []
        for i, image in enumerate(images[:5]):  # Maksimal 5 ta rasm
            if image and image.filename:
                try:
                    filename = save_uploaded_file(image, f"gallery_{i}")
                    if filename:
                        saved_images.append(filename)
                        print(f"DEBUG: Saved gallery image {i+1}: {filename}")
                except ValueError as e:
                    flash(str(e), "danger")
                    return redirect(url_for("admin_panel"))
        
        print(f"DEBUG: Total gallery images saved: {len(saved_images)}")  # Debug
        
        if saved_images:
            conn = get_db_connection()
            # FAQAT BITTA YOZUV YARATISH - barcha rasmlar bitta yozuvda
            images_string = ','.join(saved_images)
            conn.execute('INSERT INTO gallery (title, description, image) VALUES (?, ?, ?)',
                        (title, description, images_string))
            conn.commit()
            conn.close()
            
            flash(f"Galereyaga {len(saved_images)} ta rasm bilan yangi yozuv qo'shildi! ✅", "success")
        else:
            flash("Hech qanday rasm yuklanmadi!", "danger")
        
        return redirect(url_for("admin_panel"))
                
@app.route("/admin/delete_gallery/<int:id>")
@login_required
def delete_gallery(id):
    conn = get_db_connection()
    
    gallery_item = conn.execute('SELECT image FROM gallery WHERE id = ?', (id,)).fetchone()
    if gallery_item and gallery_item['image']:
        # Barcha rasmlarni o'chirish
        for image in gallery_item['image'].split(','):
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
            if os.path.exists(image_path):
                os.remove(image_path)
    
    conn.execute('DELETE FROM gallery WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash("Galereya yozuvi va barcha rasmlari o'chirildi!", "success")
    return redirect(url_for("admin_panel"))

# ========== DARS JADVALI BO'LIMI ==========
@app.route("/admin/add_schedule", methods=["POST"])
@login_required
def add_schedule():
    if request.method == "POST":
        day = request.form["day"]
        time_slot = request.form["time_slot"]
        subject = request.form["subject"]
        lesson_type = request.form["lesson_type"]
        room = sanitize_input(request.form["room"])
        teacher = sanitize_input(request.form["teacher"])
        
        if not all([day, time_slot, subject, lesson_type, room, teacher]):
            flash("Iltimos, barcha maydonlarni to'ldiring!", "danger")
            return redirect(url_for("admin_panel"))
        
        full_subject = format_subject(subject, lesson_type)
        
        conn = get_db_connection()
        conn.execute('INSERT INTO schedule (day, time, subject, room, teacher) VALUES (?, ?, ?, ?, ?)',
                    (day, time_slot, full_subject, room, teacher))
        conn.commit()
        conn.close()
        
        flash("Dars muvaffaqiyatli qo'shildi!", "success")
        return redirect(url_for("admin_panel"))

@app.route("/admin/delete_schedule/<int:id>")
@login_required
def delete_schedule(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM schedule WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash("Dars o'chirildi!", "success")
    return redirect(url_for("admin_panel"))

# ========== ALOQA BO'LIMI ==========
@app.route("/admin/add_contact", methods=["POST"])
@login_required
def add_contact():
    if request.method == "POST":
        name = sanitize_input(request.form["name"])
        position = sanitize_input(request.form["position"])
        phone = request.form["phone"]
        telegram = sanitize_input(request.form.get("telegram", ""))
        email = sanitize_input(request.form.get("email", ""))
        address = sanitize_input(request.form.get("address", ""))
        work_hours = sanitize_input(request.form.get("work_hours", ""))
        
        if not validate_phone(phone):
            flash("Noto'g'ri telefon raqami formati!", "danger")
            return redirect(url_for("admin_panel"))
        
        if not phone.startswith('+998'):
            phone = '+998' + phone
        
        conn = get_db_connection()
        conn.execute('''INSERT INTO contacts 
                       (name, position, phone, telegram, email, address, work_hours) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (name, position, phone, telegram, email, address, work_hours))
        conn.commit()
        conn.close()
        
        flash("Aloqa ma'lumoti muvaffaqiyatli qo'shildi!", "success")
        return redirect(url_for("admin_panel"))

@app.route("/admin/delete_contact/<int:id>", methods=["DELETE"])
@login_required
def delete_contact(id):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM contacts WHERE id = ?', (id,))
        conn.commit()
        success = True
    except Exception as e:
        success = False
        print(f"Error deleting contact: {e}")
    finally:
        conn.close()
    
    return jsonify({"success": success})

@app.route("/admin/delete_all_contacts")
@login_required
def delete_all_contacts():
    conn = get_db_connection()
    conn.execute('DELETE FROM contacts')
    conn.commit()
    conn.close()
    
    flash("Barcha aloqa ma'lumotlari o'chirildi!", "success")
    return redirect(url_for("admin_panel"))

# ========== ADMINLAR BO'LIMI ==========
@app.route("/admin/add_admin", methods=["POST"])
@superadmin_required
def add_admin():
    if request.method == "POST":
        username = sanitize_input(request.form["username"])
        password = request.form["password"]
        role = request.form["role"]
        
        if not username or len(username) < 3:
            flash("Login kamida 3 ta belgidan iborat bo'lishi kerak!", "danger")
            return redirect(url_for("admin_panel"))
        
        password_error = validate_password(password)
        if password_error:
            flash(password_error, "danger")
            return redirect(url_for("admin_panel"))
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)',
                        (username, generate_password_hash(password), role))
            conn.commit()
            flash("Yangi admin muvaffaqiyatli qo'shildi!", "success")
        except sqlite3.IntegrityError:
            flash("Bunday login allaqachon mavjud!", "danger")
        finally:
            conn.close()
        
        return redirect(url_for("admin_panel"))

@app.route("/admin/delete_admin/<int:id>")
@superadmin_required
def delete_admin(id):
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (id,)).fetchone()
    
    if admin and admin['role'] == 'superadmin' and admin['username'] != session.get('admin_username'):
        flash("Superadminni o'chirish mumkin emas!", "danger")
    else:
        conn.execute('DELETE FROM admins WHERE id = ? AND role != "superadmin"', (id,))
        conn.commit()
        flash("Admin o'chirildi!", "success")
    
    conn.close()
    return redirect(url_for("admin_panel"))

# Xato handlerlari
@app.errorhandler(404)
def not_found_error(error):
    return "<h1>404 - Sahifa topilmadi</h1><p>Siz qidirgan sahifa mavjud emas.</p>", 404

@app.errorhandler(500)
def internal_error(error):
    return "<h1>500 - Server xatosi</h1><p>Ichki server xatosi yuz berdi.</p>", 500

@app.errorhandler(413)
def too_large(error):
    flash("Yuklanayotgan fayl hajmi juda katta!", "danger")
    return redirect(request.referrer or url_for('admin_panel'))

@app.route('/favicon.ico')
def favicon():
    return '', 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5004))
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    if not os.path.exists('backups'):  # ✅ Yangi qator
        os.makedirs('backups')
    if not os.path.exists('logs'):     # ✅ Yangi qator
        os.makedirs('logs')
    init_db()
    app.run(debug=False, host='0.0.0.0', port=port)
