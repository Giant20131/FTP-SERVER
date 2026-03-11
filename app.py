import importlib
import json
import secrets
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    abort,
)
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = (BASE_DIR / "uploads").resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
META_FILE = UPLOAD_DIR / ".meta.json"

# pass.py is a reserved keyword, so we import it via importlib.
passmod = importlib.import_module("pass")
WEB_USER = passmod.WEB_USER
WEB_PASS_HASH = passmod.WEB_PASS_HASH
verify_password = passmod.verify_password

WEB_SECRET = "change-me"
START_FTP = False
MAX_UPLOAD_MB = 50
SECURE_COOKIES_AUTO = True
TRUST_PROXY = False
SESSION_MINUTES = 30
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300

FTP_USER = WEB_USER
FTP_PASS = "admin123"
FTP_HOST = "0.0.0.0"
FTP_PORT = 2121

WEB_HOST = "0.0.0.0"
WEB_PORT = 5000


app = Flask(__name__)
app.secret_key = WEB_SECRET
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_MINUTES)

if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_login_attempts = {}


# ---------- FTP SERVER ----------

def start_ftp_server():
    authorizer = DummyAuthorizer()
    # Full permissions in the upload directory.
    authorizer.add_user(FTP_USER, FTP_PASS, str(UPLOAD_DIR), perm="elradfmwMT")

    handler = FTPHandler
    handler.authorizer = authorizer

    server = FTPServer((FTP_HOST, FTP_PORT), handler)
    server.serve_forever()


def ensure_logged_in():
    if not session.get("logged_in"):
        return redirect(url_for("login", next=request.path))
    return None


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf(form):
    token = form.get("csrf_token", "")
    return token and token == session.get("csrf_token")


def safe_path(rel_path: str) -> Path:
    target = (UPLOAD_DIR / rel_path).resolve()
    if not str(target).startswith(str(UPLOAD_DIR)):
        raise ValueError("Invalid path")
    return target


def load_meta():
    if not META_FILE.exists():
        return {}
    try:
        data = json.loads(META_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(data, dict):
        return {k: str(v) for k, v in data.items()}
    return {}


def save_meta(meta: dict):
    temp = META_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    temp.replace(META_FILE)


def set_description(rel_path: str, description: str):
    meta = load_meta()
    if description:
        meta[rel_path] = description
    else:
        meta.pop(rel_path, None)
    save_meta(meta)


def unique_file_path(filename: str) -> Path:
    target = UPLOAD_DIR / filename
    if not target.exists():
        return target
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    counter = 1
    while True:
        candidate = UPLOAD_DIR / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def list_files():
    meta = load_meta()
    files = []
    for path in UPLOAD_DIR.rglob("*"):
        if path.is_file() and path != META_FILE:
            stat = path.stat()
            rel_path = path.relative_to(UPLOAD_DIR).as_posix()
            files.append(
                {
                    "rel_path": rel_path,
                    "name": path.name,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime),
                    "ext": path.suffix.lower().lstrip("."),
                    "description": meta.get(rel_path, ""),
                }
            )
    return files


def parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _prune_attempts(ip: str):
    now = time.time()
    window_start = now - LOGIN_WINDOW_SECONDS
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if t > window_start]
    _login_attempts[ip] = attempts
    return attempts


def is_rate_limited(ip: str) -> bool:
    attempts = _prune_attempts(ip)
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failed_attempt(ip: str):
    attempts = _prune_attempts(ip)
    attempts.append(time.time())
    _login_attempts[ip] = attempts


def clear_attempts(ip: str):
    _login_attempts.pop(ip, None)


def is_https_request() -> bool:
    if request.is_secure:
        return True
    if TRUST_PROXY:
        proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        return proto == "https"
    return False


@app.before_request
def set_cookie_security():
    if SECURE_COOKIES_AUTO:
        app.config["SESSION_COOKIE_SECURE"] = is_https_request()
    else:
        app.config["SESSION_COOKIE_SECURE"] = False


@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    if is_https_request() and SECURE_COOKIES_AUTO:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return resp


@app.errorhandler(413)
def request_too_large(_error):
    return "File too large.", 413


# ---------- WEB UI ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not validate_csrf(request.form):
            return abort(400)
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if TRUST_PROXY:
            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
        else:
            ip = request.remote_addr or "unknown"
        if is_rate_limited(ip):
            return render_template("login.html", error="Too many attempts. Try again later.", csrf_token=get_csrf_token())

        if username == WEB_USER and verify_password(password, WEB_PASS_HASH):
            session.clear()
            session["logged_in"] = True
            session["csrf_token"] = get_csrf_token()
            session.permanent = True
            clear_attempts(ip)
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        record_failed_attempt(ip)
        return render_template("login.html", error="Invalid credentials", csrf_token=get_csrf_token())
    return render_template("login.html", error=None, csrf_token=get_csrf_token())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    gate = ensure_logged_in()
    if gate:
        return gate

    q = (request.args.get("q") or "").strip().lower()
    ext = (request.args.get("ext") or "").strip().lower()
    date_from = parse_date(request.args.get("from", ""))
    date_to = parse_date(request.args.get("to", ""))

    items = list_files()

    if q:
        items = [
            i
            for i in items
            if q in i["name"].lower()
            or q in i["rel_path"].lower()
            or q in i["description"].lower()
        ]

    if ext:
        items = [i for i in items if i["ext"] == ext]

    if date_from:
        items = [i for i in items if i["modified"].date() >= date_from]

    if date_to:
        items = [i for i in items if i["modified"].date() <= date_to]

    items.sort(key=lambda x: x["modified"], reverse=True)

    extensions = sorted({i["ext"] for i in list_files() if i["ext"]})

    for i in items:
        i["modified_str"] = i["modified"].strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "index.html",
        items=items,
        extensions=extensions,
        q=q,
        ext=ext,
        date_from=date_from.isoformat() if date_from else "",
        date_to=date_to.isoformat() if date_to else "",
        csrf_token=get_csrf_token(),
    )


@app.route("/upload", methods=["POST"])
def upload():
    gate = ensure_logged_in()
    if gate:
        return gate

    if not validate_csrf(request.form):
        return abort(400)

    file = request.files.get("file")
    if not file or not file.filename:
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    if not filename:
        return redirect(url_for("index"))

    description = (request.form.get("description") or "").strip()
    target = unique_file_path(filename)
    file.save(target)

    rel_path = target.relative_to(UPLOAD_DIR).as_posix()
    if description:
        set_description(rel_path, description)

    return redirect(url_for("index"))


@app.route("/download/<path:rel_path>")
def download(rel_path):
    gate = ensure_logged_in()
    if gate:
        return gate

    try:
        target = safe_path(rel_path)
    except ValueError:
        return abort(400)

    if target == META_FILE or rel_path.startswith("."):
        return abort(404)

    if not target.exists() or not target.is_file():
        return abort(404)

    return send_file(target, as_attachment=True)


if __name__ == "__main__":
    if START_FTP:
        ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
        ftp_thread.start()

    app.run(host=WEB_HOST, port=WEB_PORT)
