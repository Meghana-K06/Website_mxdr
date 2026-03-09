import os
import subprocess
from flask import Blueprint, render_template, request, redirect, session
from db.init_db import get_db

bank_bp = Blueprint('bank', __name__)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

# ── Dashboard ──────────────────────────────────────────────────────────────────
@bank_bp.route('/dashboard')
@login_required
def dashboard():
    conn   = get_db()
    users  = conn.execute('SELECT * FROM users').fetchall()
    txns   = conn.execute(
        'SELECT * FROM transactions ORDER BY created_at DESC LIMIT 10'
    ).fetchall()
    conn.close()
    return render_template('dashboard.html', users=users, transactions=txns)

# ── Search — VULNERABLE to SQLi ───────────────────────────────────────────────
@bank_bp.route('/search')
@login_required
def search():
    q       = request.args.get('q', '')
    results = []
    error   = None
    if q:
        try:
            conn = get_db()
            # ⚠️  VULNERABLE: raw f-string interpolation
            results = conn.execute(
                f"SELECT * FROM users WHERE username LIKE '%{q}%' OR full_name LIKE '%{q}%'"
            ).fetchall()
            conn.close()
        except Exception as e:
            error = str(e)
    return render_template('search.html', results=results, query=q, error=error)

# ── Messages — VULNERABLE to XSS ──────────────────────────────────────────────
@bank_bp.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    conn = get_db()
    if request.method == 'POST':
        username = request.form.get('username', '')
        message  = request.form.get('message', '')
        # ⚠️  VULNERABLE: raw message stored and rendered unescaped
        conn.execute(
            'INSERT INTO messages (username, message) VALUES (?, ?)',
            (username, message)
        )
        conn.commit()
        conn.close()
        return redirect('/messages')

    msgs = conn.execute(
        'SELECT * FROM messages ORDER BY created_at DESC'
    ).fetchall()
    conn.close()
    return render_template('messages.html', messages=msgs)

# ── File Viewer — VULNERABLE to Path Traversal ────────────────────────────────
@bank_bp.route('/files')
@login_required
def files():
    file_path = request.args.get('file', '')
    content   = None
    error     = None
    if file_path:
        try:
            # ⚠️  VULNERABLE: no path sanitization whatsoever
            with open(file_path, 'r') as f:
                content = f.read()
        except Exception as e:
            error = str(e)
    return render_template('files.html', content=content, file=file_path, error=error)

# ── Ping Tool — VULNERABLE to Command Injection ───────────────────────────────
@bank_bp.route('/ping')
@login_required
def ping():
    host   = request.args.get('host', '')
    output = None
    if host:
        try:
            # ⚠️  VULNERABLE: shell=True with unsanitized input
            result = subprocess.run(
                f'ping -c 2 {host}',
                shell=True, capture_output=True,
                text=True, timeout=6
            )
            output = result.stdout or result.stderr
        except Exception as e:
            output = str(e)
    return render_template('ping.html', output=output, host=host)
