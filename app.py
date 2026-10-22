import os
import sqlite3
import secrets
from datetime import datetime, date
from functools import wraps
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory, g

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "trustvault.db"
UPLOAD_DIR = BASE_DIR / "private_uploads"
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg", "csv", "xlsx", "pptx"}
MAX_FILE_BYTES = 10 * 1024 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("TRUSTVAULT_SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_FILE_BYTES + 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Enable only when deployed behind HTTPS:
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
UPLOAD_DIR.mkdir(exist_ok=True)

def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db

def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL,
            description TEXT DEFAULT '',
            owner_id INTEGER NOT NULL REFERENCES users(id),
            size_bytes INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            access_level TEXT NOT NULL CHECK(access_level IN ('read','edit')),
            granted_by INTEGER NOT NULL REFERENCES users(id),
            granted_at TEXT NOT NULL,
            UNIQUE(document_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            document_id INTEGER,
            target_user_id INTEGER,
            details TEXT DEFAULT '',
            occurred_at TEXT NOT NULL
        );
        """)
        admin_user = os.environ.get("TRUSTVAULT_ADMIN_USER", "admin")
        admin_password = os.environ.get("TRUSTVAULT_ADMIN_PASSWORD", "ChangeMe!123")
        existing = db.execute("SELECT id FROM users WHERE username=?", (admin_user,)).fetchone()
        if not existing:
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       (admin_user, generate_password_hash(admin_password), "admin", now()))
            print(f"[TrustVault] Initial admin: {admin_user} / {admin_password}")
        db.commit()

def now():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def audit(action, document_id=None, target_user_id=None, details=""):
    actor = session.get("user_id")
    with connect_db() as db:
        db.execute("""INSERT INTO audit_logs(actor_id,action,document_id,target_user_id,details,occurred_at)
                      VALUES(?,?,?,?,?,?)""",
                   (actor, action, document_id, target_user_id, details[:500], now()))
        db.commit()

def current_user():
    if "user_id" not in session:
        return None
    if "user" not in g:
        with connect_db() as db:
            g.user = db.execute("SELECT id,username,role FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return g.user

@app.before_request
def load_user():
    g.user = None
    if session.get("user_id"):
        with connect_db() as db:
            g.user = db.execute("SELECT id,username,role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if g.user is None:
            session.clear()

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please sign in first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user()["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def get_document(document_id):
    with connect_db() as db:
        doc = db.execute("""SELECT d.*, u.username AS owner_name FROM documents d
                            JOIN users u ON u.id=d.owner_id WHERE d.id=?""", (document_id,)).fetchone()
    if doc is None:
        abort(404)
    return doc

def access_level(document_id, user):
    if not user:
        return None
    doc = get_document(document_id)
    if doc["owner_id"] == user["id"]:
        return "owner"
    with connect_db() as db:
        permission = db.execute("SELECT access_level FROM permissions WHERE document_id=? AND user_id=?",
                                (document_id, user["id"])).fetchone()
    return permission["access_level"] if permission else None

def require_document_access(document_id, edit=False):
    user = current_user()
    level = access_level(document_id, user)
    if level is None:
        audit("ACCESS_DENIED", document_id, details="Attempted document access")
        abort(403)
    if edit and level not in ("owner", "edit"):
        audit("EDIT_DENIED", document_id, details="Attempted document edit")
        abort(403)
    return get_document(document_id)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("documents"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 40 or not username.replace("_", "").isalnum():
            flash("Username must be 3–40 characters and contain only letters, numbers or underscores.", "danger")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "danger")
        else:
            try:
                with connect_db() as db:
                    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                               (username, generate_password_hash(password), "viewer", now()))
                    db.commit()
                flash("Account created. An administrator can promote you to Document Owner if needed.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            audit("LOGIN", details="Successful sign-in")
            return redirect(url_for("documents"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("LOGOUT", details="Signed out")
    session.clear()
    return redirect(url_for("index"))

@app.route("/documents")
@login_required
def documents():
    user = current_user()
    query = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    owner = request.args.get("owner", "").strip()
    from_date = request.args.get("from_date", "").strip()
    to_date = request.args.get("to_date", "").strip()
    sql = """SELECT DISTINCT d.*, u.username AS owner_name,
             CASE WHEN d.owner_id=? THEN 'owner' ELSE p.access_level END AS my_access
             FROM documents d JOIN users u ON u.id=d.owner_id
             LEFT JOIN permissions p ON p.document_id=d.id AND p.user_id=?
             WHERE (d.owner_id=? OR p.user_id=?)"""
    params = [user["id"], user["id"], user["id"], user["id"]]
    if query:
        sql += " AND (d.original_name LIKE ? OR d.description LIKE ?)"
        params += [f"%{query}%", f"%{query}%"]
    if category:
        sql += " AND d.category=?"
        params.append(category)
    if owner:
        sql += " AND u.username LIKE ?"
        params.append(f"%{owner}%")
    if from_date:
        sql += " AND substr(d.uploaded_at,1,10)>=?"
        params.append(from_date)
    if to_date:
        sql += " AND substr(d.uploaded_at,1,10)<=?"
        params.append(to_date)
    sql += " ORDER BY d.uploaded_at DESC"
    with connect_db() as db:
        docs = db.execute(sql, params).fetchall()
        categories = [r["category"] for r in db.execute(
            """SELECT DISTINCT d.category FROM documents d
               LEFT JOIN permissions p ON p.document_id=d.id AND p.user_id=?
               WHERE d.owner_id=? OR p.user_id=? ORDER BY d.category""",
            (user["id"], user["id"], user["id"])).fetchall()]
    return render_template("documents.html", documents=docs, categories=categories,
                           filters={"q":query,"category":category,"owner":owner,"from_date":from_date,"to_date":to_date})

@app.route("/documents/upload", methods=["GET", "POST"])
@roles_required("owner", "admin")
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        if not file or not file.filename:
            flash("Choose a file to upload.", "danger")
        elif not allowed_file(file.filename):
            flash("File type not allowed. Allowed: " + ", ".join(sorted(ALLOWED_EXTENSIONS)), "danger")
        elif not category or len(category) > 60:
            flash("Enter a category up to 60 characters.", "danger")
        else:
            file.stream.seek(0, os.SEEK_END)
            size = file.stream.tell()
            file.stream.seek(0)
            if size == 0 or size > MAX_FILE_BYTES:
                flash("File must be between 1 byte and 10 MB.", "danger")
            else:
                original = secure_filename(file.filename)[:180]
                stored = secrets.token_hex(16) + "." + original.rsplit(".",1)[1].lower()
                file.save(UPLOAD_DIR / stored)
                with connect_db() as db:
                    cur = db.execute("""INSERT INTO documents(original_name,stored_name,category,description,owner_id,size_bytes,uploaded_at,updated_at)
                                        VALUES(?,?,?,?,?,?,?,?)""",
                                     (original, stored, category, description[:500], current_user()["id"], size, now(), now()))
                    doc_id = cur.lastrowid
                    db.commit()
                audit("UPLOAD", doc_id, details=f"Uploaded {original}")
                flash("Document uploaded privately.", "success")
                return redirect(url_for("documents"))
    return render_template("upload.html")

@app.route("/documents/<int:document_id>")
@login_required
def document_detail(document_id):
    doc = require_document_access(document_id)
    with connect_db() as db:
        grants = db.execute("""SELECT p.*,u.username FROM permissions p JOIN users u ON u.id=p.user_id
                               WHERE p.document_id=? ORDER BY u.username""", (document_id,)).fetchall() if doc["owner_id"] == current_user()["id"] else []
    return render_template("document_detail.html", doc=doc, grants=grants,
                           can_edit=access_level(document_id,current_user()) in ("owner","edit"),
                           is_owner=doc["owner_id"] == current_user()["id"])

@app.route("/documents/<int:document_id>/download")
@login_required
def download(document_id):
    doc = require_document_access(document_id)
    audit("DOWNLOAD", document_id, details=f"Downloaded {doc['original_name']}")
    return send_from_directory(UPLOAD_DIR, doc["stored_name"], as_attachment=True, download_name=doc["original_name"])

@app.route("/documents/<int:document_id>/edit", methods=["POST"])
@login_required
def edit_document(document_id):
    doc = require_document_access(document_id, edit=True)
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "").strip()
    description = request.form.get("description", "").strip()
    if not name or len(name) > 180 or not category or len(category) > 60:
        flash("Name (1–180 chars) and category (1–60 chars) are required.", "danger")
    else:
        with connect_db() as db:
            db.execute("UPDATE documents SET original_name=?,category=?,description=?,updated_at=? WHERE id=?",
                       (secure_filename(name) or name, category, description[:500], now(), document_id))
            db.commit()
        audit("EDIT", document_id, details="Updated document metadata")
        flash("Document details updated.", "success")
    return redirect(url_for("document_detail", document_id=document_id))

@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@login_required
def delete_document(document_id):
    doc = get_document(document_id)
    if doc["owner_id"] != current_user()["id"]:
        audit("DELETE_DENIED", document_id, details="Attempted deletion without ownership")
        abort(403)
    with connect_db() as db:
        db.execute("DELETE FROM documents WHERE id=?", (document_id,))
        db.commit()
    try:
        (UPLOAD_DIR / doc["stored_name"]).unlink(missing_ok=True)
    except OSError:
        pass
    audit("DELETE", document_id, details=f"Deleted {doc['original_name']}")
    flash("Document deleted.", "success")
    return redirect(url_for("documents"))

@app.route("/documents/<int:document_id>/permissions", methods=["POST"])
@login_required
def manage_permission(document_id):
    doc = get_document(document_id)
    if doc["owner_id"] != current_user()["id"]:
        audit("PERMISSION_CHANGE_DENIED", document_id, details="Non-owner attempted permission change")
        abort(403)
    username = request.form.get("username", "").strip()
    level = request.form.get("access_level", "read")
    operation = request.form.get("operation", "grant")
    with connect_db() as db:
        target = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not target:
            flash("No user found with that username.", "danger")
        elif target["id"] == doc["owner_id"]:
            flash("The owner already has full control.", "warning")
        elif operation == "revoke":
            db.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?", (document_id,target["id"]))
            db.commit()
            audit("PERMISSION_REVOKE", document_id, target["id"], f"Revoked access for {username}")
            flash(f"Access revoked for {username}.", "success")
        elif level not in ("read", "edit"):
            flash("Invalid permission level.", "danger")
        else:
            db.execute("""INSERT INTO permissions(document_id,user_id,access_level,granted_by,granted_at)
                          VALUES(?,?,?,?,?) ON CONFLICT(document_id,user_id)
                          DO UPDATE SET access_level=excluded.access_level,granted_by=excluded.granted_by,granted_at=excluded.granted_at""",
                       (document_id,target["id"],level,current_user()["id"],now()))
            db.commit()
            audit("PERMISSION_GRANT", document_id, target["id"], f"Granted {level} access to {username}")
            flash(f"{level.title()} access granted to {username}.", "success")
    return redirect(url_for("document_detail", document_id=document_id))

@app.route("/admin")
@roles_required("admin")
def admin_dashboard():
    with connect_db() as db:
        users = db.execute("SELECT id,username,role,created_at FROM users ORDER BY username").fetchall()
        logs = db.execute("""SELECT a.*,u.username AS actor_name,t.username AS target_name,d.original_name
                             FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
                             LEFT JOIN users t ON t.id=a.target_user_id
                             LEFT JOIN documents d ON d.id=a.document_id
                             ORDER BY a.id DESC LIMIT 250""").fetchall()
        stats = {
            "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "documents": db.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
            "events": db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0],
        }
    return render_template("admin.html", users=users, logs=logs, stats=stats)

@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@roles_required("admin")
def change_role(user_id):
    role = request.form.get("role")
    if role not in ("owner","viewer","admin"):
        abort(400)
    if user_id == current_user()["id"] and role != "admin":
        flash("You cannot remove your own administrator role.", "danger")
    else:
        with connect_db() as db:
            target = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
            if not target:
                abort(404)
            db.execute("UPDATE users SET role=? WHERE id=?", (role,user_id))
            db.commit()
        audit("ROLE_CHANGE", details=f"Changed {target['username']} role to {role}")
        flash(f"Role updated for {target['username']}.", "success")
    return redirect(url_for("admin_dashboard"))

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You do not have permission to access this resource."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The requested resource was not found."), 404

@app.errorhandler(413)
def too_large(_):
    return render_template("error.html", code=413, message="Upload too large. Maximum file size is 10 MB."), 413

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
