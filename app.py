import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "signup.db"
SECRET_KEY_FILE = BASE_DIR / ".secret_key"

# PBKDF2-HMAC-SHA256 parameters (OWASP 2023 recommendation: 600,000 iterations)
HASH_ITERATIONS = 600_000
SALT_BYTES = 16

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 8


def load_secret_key():
    """Use SECRET_KEY from the environment, or a random key persisted to a local file."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    if not SECRET_KEY_FILE.exists():
        SECRET_KEY_FILE.write_text(secrets.token_hex(32))
        SECRET_KEY_FILE.chmod(0o600)
    return SECRET_KEY_FILE.read_text().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


# ---------- Database ----------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_salt BLOB    NOT NULL,
                password_hash BLOB    NOT NULL,
                created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


# ---------- Password hashing ----------

def hash_password(password, salt=None):
    """Return (salt, hash) for the password, generating a fresh random salt if none is given."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, HASH_ITERATIONS)
    return salt, digest


def verify_password(password, salt, expected_hash):
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, expected_hash)


# ---------- CSRF protection ----------

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
            abort(400, "Invalid or missing CSRF token.")


# ---------- Current user ----------

@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def log_in(user_id):
    session.clear()  # prevent session fixation
    session["user_id"] = user_id


# ---------- Routes ----------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not USERNAME_RE.fullmatch(username):
            error = "Username must be 3–32 characters: letters, numbers, '_', '.', or '-'."
        elif len(password) < MIN_PASSWORD_LENGTH:
            error = f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        elif password != confirm:
            error = "Passwords do not match."

        if error is None:
            salt, digest = hash_password(password)
            db = get_db()
            try:
                cur = db.execute(
                    "INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)",
                    (username, salt, digest),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "That username is already taken."
            else:
                log_in(cur.lastrowid)
                flash(f"Welcome, {username}! Your account has been created.")
                return redirect(url_for("index"))

        flash(error, "error")
        return render_template("register.html", username=username), 400

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT id, username, password_salt, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is not None and verify_password(password, user["password_salt"], user["password_hash"]):
            log_in(user["id"])
            flash(f"Logged in as {user['username']}.")
            return redirect(url_for("index"))

        # Same message whether the username or password was wrong
        flash("Invalid username or password.", "error")
        return render_template("login.html", username=username), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
