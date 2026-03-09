from flask import Blueprint, render_template, request, redirect, session
from collections import defaultdict
import time
from db.init_db import get_db

auth_bp = Blueprint('auth', __name__)

# Brute force tracking
login_attempts: dict = defaultdict(list)
BRUTE_THRESHOLD = 5
WINDOW_SECONDS  = 300   # 5 minutes

@auth_bp.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html', error=None)

@auth_bp.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    ip       = request.remote_addr
    now      = time.time()

    # Clean old attempts outside window
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < WINDOW_SECONDS]
    login_attempts[ip].append(now)
    attempt_count = len(login_attempts[ip])

    conn   = get_db()
    cursor = conn.cursor()

    # ⚠️  INTENTIONALLY VULNERABLE — raw f-string = SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except Exception as e:
        conn.close()
        return render_template('login.html', error=f'DB Error: {e}')
    finally:
        conn.close()

    if user:
        session['user'] = dict(user)
        login_attempts[ip] = []   # reset on success
        return redirect('/dashboard')

    if attempt_count >= BRUTE_THRESHOLD:
        error = f'⚠️ Too many failed attempts ({attempt_count}). Account may be locked.'
    else:
        error = f'Invalid credentials. Attempt {attempt_count}/{BRUTE_THRESHOLD}.'

    return render_template('login.html', error=error)

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect('/login')
