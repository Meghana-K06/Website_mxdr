import json
import os
import re
from datetime import datetime, timezone
from functools import wraps
from flask import request, g
import time

LOG_FILE = os.path.join(
    os.path.dirname(__file__), '../../logs/access.log'
)

# ── Attack pattern detection ───────────────────────────────────────────────────

PATTERNS = {
    'SQLI': [
        r"'", r'--', r';', r'\bUNION\b.*\bSELECT\b', r'\bOR\b\s+1\s*=\s*1',
        r'\bDROP\b.*\bTABLE\b', r'\bINSERT\b.*\bINTO\b',
        r'\bSELECT\b.*\bFROM\b', r'SLEEP\s*\(', r'BENCHMARK\s*\(',
        r'\bAND\b\s+\d+\s*=\s*\d+', r'xp_cmdshell', r'information_schema',
    ],
    'XSS': [
        r'<script', r'javascript:', r'onerror\s*=', r'onload\s*=',
        r'alert\s*\(', r'<img[^>]+src', r'<svg', r'document\.cookie',
        r'\.exec\s*\(', r'<iframe', r'onmouseover\s*=', r'eval\s*\(',
    ],
    'PATH_TRAVERSAL': [
        r'\.\./','r\.\.\\\\', r'%2e%2e', r'/etc/passwd', r'/etc/shadow',
        r'/windows/system32', r'%252e', r'\.\.%2f', r'%2e%2e%2f',
    ],
    'CMDI': [
        r';\s*\w', r'\|\s*\w', r'&&', r'\$\(', r'`[^`]+`',
        r'\bnc\b\s', r'\bwget\b\s', r'\bcurl\b\s', r'\bbash\b\s',
        r'/bin/sh', r'/bin/bash', r'cmd\.exe', r'powershell',
    ],
    'BRUTE_FORCE': [
        r'login', r'signin', r'auth',
    ],
}

def detect_attack_hints(req_data: str, path: str, method: str) -> list[str]:
    hints = []
    data  = req_data.lower()

    for attack_type, patterns in PATTERNS.items():
        if attack_type == 'BRUTE_FORCE':
            # Only flag on POST to login endpoints
            if method == 'POST' and any(re.search(p, path, re.I) for p in patterns):
                hints.append('BRUTE_FORCE_ATTEMPT')
            continue
        for pattern in patterns:
            if re.search(pattern, data, re.IGNORECASE):
                hints.append(attack_type)
                break

    return list(set(hints))

def get_client_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return (
        request.headers.get('X-Real-IP') or
        request.remote_addr or
        'unknown'
    )

# ── Middleware ─────────────────────────────────────────────────────────────────

def setup_logging(app):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    @app.before_request
    def before():
        g.start_time = time.time()

    @app.after_request
    def after(response):
        duration_ms = int((time.time() - g.start_time) * 1000)
        ip          = get_client_ip()

        # Collect all request data for pattern matching
        req_data = ' '.join([
            request.url,
            json.dumps(request.form.to_dict()),
            json.dumps(request.args.to_dict()),
            request.get_data(as_text=True) or '',
            request.headers.get('User-Agent', ''),
        ])

        attack_hints = detect_attack_hints(req_data, request.path, request.method)

        log_entry = {
            'timestamp':    datetime.now(timezone.utc).isoformat(),
            'ip':           ip,
            'method':       request.method,
            'path':         request.full_path if request.query_string else request.path,
            'status':       response.status_code,
            'duration_ms':  duration_ms,
            'user_agent':   request.headers.get('User-Agent', 'unknown'),
            'referer':      request.headers.get('Referer', ''),
            'body':         json.dumps(request.form.to_dict()) if request.method != 'GET' else '',
            'query':        json.dumps(request.args.to_dict()),
            'attack_hints': attack_hints,
        }

        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

        # Coloured terminal output
        color = '\033[91m' if attack_hints else '\033[92m'
        reset = '\033[0m'
        flag  = f' 🚨 {attack_hints}' if attack_hints else ''
        print(f'{color}[{log_entry["timestamp"]}] {ip} {request.method} '
              f'{request.path} → {response.status_code}{flag}{reset}')

        return response

    return app
