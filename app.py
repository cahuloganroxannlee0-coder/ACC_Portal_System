import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "acc_portal.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
MAX_FILE_SIZE = 5 * 1024 * 1024

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "acc-portal-dev-secret-change-me")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        student_id TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS student_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        birth_date TEXT NOT NULL,
        sex TEXT NOT NULL,
        address TEXT NOT NULL,
        contact_number TEXT NOT NULL,
        course TEXT NOT NULL,
        year_level TEXT NOT NULL,
        id_filename TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scholarship_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scholarship_type TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    admin = conn.execute("SELECT id FROM users WHERE email = ?", ("admin@acc.edu.ph",)).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (full_name,email,student_id,password_hash,role) VALUES (?,?,?,?,?)",
            ("ACC Administrator", "admin@acc.edu.ph", "ADMIN-001",
             generate_password_hash("admin123"), "admin")
        )
    conn.commit()
    conn.close()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Administrator access is required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.context_processor
def inject_user():
    return {"current_user": session.get("full_name")}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        student_id = request.form.get("student_id", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not all([full_name, email, student_id, password, confirm]):
            flash("Please complete all required fields.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (full_name,email,student_id,password_hash) VALUES (?,?,?,?)",
                (full_name, email, student_id, generate_password_hash(password))
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Email or Student ID is already registered.", "danger")
            conn.close()
            return render_template("register.html")
        conn.close()
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    registration = conn.execute(
        "SELECT * FROM student_applications WHERE user_id=? ORDER BY id DESC LIMIT 1",
        (session["user_id"],)
    ).fetchone()
    scholarships = conn.execute(
        "SELECT * FROM scholarship_applications WHERE user_id=? ORDER BY id DESC",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", user=user, registration=registration, scholarships=scholarships)

@app.route("/student-registration", methods=["GET", "POST"])
@login_required
def student_registration():
    if request.method == "POST":
        fields = ["birth_date", "sex", "address", "contact_number", "course", "year_level"]
        values = {f: request.form.get(f, "").strip() for f in fields}
        id_file = request.files.get("valid_id")

        if not all(values.values()) or not id_file or id_file.filename == "":
            flash("Please complete the form and attach a valid ID.", "danger")
            return render_template("student_registration.html")

        if not allowed_file(id_file.filename):
            flash("Valid ID must be PDF, JPG, JPEG, or PNG.", "danger")
            return render_template("student_registration.html")

        # Give uploaded files a server-generated name rather than trusting the original name.
        ext = id_file.filename.rsplit(".", 1)[1].lower()
        filename = f"user_{session['user_id']}_{os.urandom(8).hex()}.{ext}"
        id_file.save(os.path.join(UPLOAD_FOLDER, filename))

        conn = get_db()
        old = conn.execute(
            "SELECT id, id_filename FROM student_applications WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (session["user_id"],)
        ).fetchone()
        conn.execute(
            """INSERT INTO student_applications
            (user_id,birth_date,sex,address,contact_number,course,year_level,id_filename)
            VALUES (?,?,?,?,?,?,?,?)""",
            (session["user_id"], values["birth_date"], values["sex"], values["address"],
             values["contact_number"], values["course"], values["year_level"], filename)
        )
        conn.commit()
        conn.close()
        flash("Student registration/application submitted successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("student_registration.html")

@app.route("/scholarship", methods=["GET", "POST"])
@login_required
def scholarship():
    if request.method == "POST":
        scholarship_type = request.form.get("scholarship_type", "").strip()
        reason = request.form.get("reason", "").strip()
        if not scholarship_type or not reason:
            flash("Please complete the scholarship application.", "danger")
            return render_template("scholarship.html")
        conn = get_db()
        conn.execute(
            "INSERT INTO scholarship_applications (user_id,scholarship_type,reason) VALUES (?,?,?)",
            (session["user_id"], scholarship_type, reason)
        )
        conn.commit()
        conn.close()
        flash("Scholarship application submitted successfully.", "success")
        return redirect(url_for("dashboard"))
    return render_template("scholarship.html")

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()
    students = conn.execute("""
        SELECT u.id,u.full_name,u.email,u.student_id,
               sa.id AS application_id,sa.course,sa.year_level,sa.status,sa.id_filename,sa.created_at
        FROM users u
        LEFT JOIN student_applications sa ON sa.user_id=u.id
        WHERE u.role='student'
        ORDER BY u.id DESC
    """).fetchall()
    scholarships = conn.execute("""
        SELECT s.id,s.scholarship_type,s.reason,s.status,s.created_at,u.full_name,u.email
        FROM scholarship_applications s
        JOIN users u ON u.id=s.user_id
        ORDER BY s.id DESC
    """).fetchall()
    conn.close()
    return render_template("admin.html", students=students, scholarships=scholarships)

@app.route("/admin/application/<int:application_id>/<status>")
@login_required
@admin_required
def update_application(application_id, status):
    if status not in {"Approved", "Rejected", "Pending"}:
        flash("Invalid status.", "danger")
        return redirect(url_for("admin_dashboard"))
    conn = get_db()
    conn.execute("UPDATE student_applications SET status=? WHERE id=?", (status, application_id))
    conn.commit()
    conn.close()
    flash("Student application status updated.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/scholarship/<int:scholarship_id>/<status>")
@login_required
@admin_required
def update_scholarship(scholarship_id, status):
    if status not in {"Approved", "Rejected", "Pending"}:
        flash("Invalid status.", "danger")
        return redirect(url_for("admin_dashboard"))
    conn = get_db()
    conn.execute("UPDATE scholarship_applications SET status=? WHERE id=?", (status, scholarship_id))
    conn.commit()
    conn.close()
    flash("Scholarship status updated.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/uploads/<filename>")
@login_required
@admin_required
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Maximum size is 5 MB.", "danger")
    return redirect(url_for("student_registration"))

init_db()

if __name__ == "__main__":
    app.run(debug=True)
