# detection-engine/analyzer.py

import json
import os
import re
import time
import hashlib
import requests
from datetime import datetime, timezone
from collections import defaultdict
from dotenv import load_dotenv
from patterns import (
    SIGNATURES, MITRE_MAPPING, OWASP_MAPPING,
    KILL_CHAIN_MAPPING, SEVERITY_MATRIX, SEVERITY_SCORE,
    NEXT_STEP_PREDICTION, DEFENSE_RECOMMENDATIONS
)

load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))

IPINFO_TOKEN = os.getenv('IPINFO_TOKEN', '')

# ─────────────────────────────────────────────────────────────────────────────
# GEO CACHE  — avoid hammering ipinfo.io for same IP
# ─────────────────────────────────────────────────────────────────────────────
_geo_cache: dict = {}

def get_geolocation(ip: str) -> dict:
    """Fetch geolocation from ipinfo.io with in-memory caching."""
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Private / loopback IPs → no lookup needed
    private = re.match(
        r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|localhost)', ip
    )
    if private:
        result = {
            'ip': ip, 'city': 'Local', 'region': 'Local',
            'country': 'Local', 'org': 'Private Network',
            'loc': '0,0', 'lat': 0.0, 'lon': 0.0,
        }
        _geo_cache[ip] = result
        return result

    try:
        url      = f'https://ipinfo.io/{ip}/json'
        headers  = {'Authorization': f'Bearer {IPINFO_TOKEN}'} if IPINFO_TOKEN else {}
        resp     = requests.get(url, headers=headers, timeout=4)
        data     = resp.json()
        lat, lon = (data.get('loc', '0,0').split(',') + ['0', '0'])[:2]
        result   = {
            'ip':      ip,
            'city':    data.get('city',     'Unknown'),
            'region':  data.get('region',   'Unknown'),
            'country': data.get('country',  'Unknown'),
            'org':     data.get('org',      'Unknown'),
            'loc':     data.get('loc',      '0,0'),
            'lat':     float(lat),
            'lon':     float(lon),
        }
    except Exception as e:
        result = {
            'ip': ip, 'city': 'Lookup Failed', 'region': '?',
            'country': '?', 'org': '?', 'loc': '0,0',
            'lat': 0.0, 'lon': 0.0,
        }

    _geo_cache[ip] = result
    return result

# ─────────────────────────────────────────────────────────────────────────────
# BRUTE FORCE TRACKER  — cross-request state
# ─────────────────────────────────────────────────────────────────────────────
_brute_tracker: dict = defaultdict(list)
BRUTE_WINDOW   = 300   # 5 minutes
BRUTE_THRESH   = 5

def check_brute_force(ip: str, path: str, method: str, status: int) -> dict | None:
    """Returns brute force detection dict if threshold exceeded, else None."""
    if method != 'POST' or not re.search(r'login|auth|signin', path, re.I):
        return None

    now = time.time()
    _brute_tracker[ip] = [t for t in _brute_tracker[ip] if now - t < BRUTE_WINDOW]

    if status in (200, 302):
        # Successful login after many fails = confirmed brute force
        if len(_brute_tracker[ip]) >= BRUTE_THRESH:
            return {'confirmed': True, 'attempts': len(_brute_tracker[ip])}
        _brute_tracker[ip] = []
        return None

    _brute_tracker[ip].append(now)
    count = len(_brute_tracker[ip])

    if count >= BRUTE_THRESH:
        return {'confirmed': False, 'attempts': count}
    return None

# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORER
# ─────────────────────────────────────────────────────────────────────────────

def score_attack(attack_type: str, haystack: str) -> float:
    """Returns a 0–100 confidence score based on how many signatures matched."""
    sigs    = SIGNATURES.get(attack_type, [])
    total   = sum(w for _, w in sigs)
    matched = sum(w for pattern, w in sigs if pattern.search(haystack))
    if total == 0:
        return 0.0
    raw = (matched / total) * 100
    # Clamp between 0-100, scale up slightly so even 1 match shows clearly
    return min(100.0, round(raw * 2.5, 1))

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def extract_payload(log_entry: dict) -> str:
    """Pull the most interesting part of the request as the payload."""
    parts = []

    # Query params
    query = log_entry.get('query', '{}')
    try:
        q = json.loads(query)
        if q:
            parts.append('QUERY: ' + ' | '.join(f'{k}={v}' for k, v in q.items()))
    except Exception:
        if query and query != '{}':
            parts.append('QUERY: ' + query)

    # POST body
    body = log_entry.get('body', '')
    if body and body != '{}':
        try:
            b = json.loads(body)
            # Mask passwords in log display
            safe_b = {k: ('***' if 'pass' in k.lower() else v) for k, v in b.items()}
            parts.append('BODY: ' + ' | '.join(f'{k}={v}' for k, v in safe_b.items()))
        except Exception:
            parts.append('BODY: ' + body)

    # URL path (may contain attack)
    path = log_entry.get('path', '')
    if any(c in path for c in ["'", '<', '>', ';', '|', '&', '.']):
        parts.append('PATH: ' + path)

    return ' || '.join(parts) if parts else log_entry.get('path', '')

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

def analyze(log_entry: dict) -> dict:
    """
    Takes a raw log entry dict and returns a fully enriched
    threat intelligence report.
    """

    ip         = log_entry.get('ip', 'unknown')
    method     = log_entry.get('method', 'GET')
    path       = log_entry.get('path', '/')
    status     = log_entry.get('status', 200)
    user_agent = log_entry.get('user_agent', '')
    timestamp  = log_entry.get('timestamp', datetime.now(timezone.utc).isoformat())

    # Build full searchable string from all request data
    haystack = ' '.join([
        path,
        log_entry.get('query',  '{}'),
        log_entry.get('body',   '{}'),
        user_agent,
    ]).lower()

    # ── 1. Detect attacks ─────────────────────────────────────────────────────
    detected_attacks = []

    for attack_type, sigs in SIGNATURES.items():
        if attack_type == 'BRUTE_FORCE':
            continue   # handled separately below
        for pattern, _ in sigs:
            if pattern.search(haystack):
                detected_attacks.append(attack_type)
                break

    # Brute force cross-request check
    brute = check_brute_force(ip, path, method, status)
    if brute:
        detected_attacks.append('BRUTE_FORCE')

    # Use hints from logger as fallback
    hints = log_entry.get('attack_hints', [])
    for h in hints:
        h_clean = h.replace('_ATTEMPT', '')
        if h_clean not in detected_attacks:
            detected_attacks.append(h_clean)

    # ── 2. Determine primary attack & severity ────────────────────────────────
    if not detected_attacks:
        # Normal traffic
        return {
            'id':            _make_id(log_entry),
            'timestamp':     timestamp,
            'ip':            ip,
            'method':        method,
            'path':          path,
            'status':        status,
            'user_agent':    user_agent,
            'is_attack':     False,
            'severity':      'INFO',
            'attacks':       [],
            'payload':       extract_payload(log_entry),
            'geolocation':   get_geolocation(ip),
            'duration_ms':   log_entry.get('duration_ms', 0),
        }

    # Sort detected attacks by severity score (highest first)
    detected_attacks = sorted(
        set(detected_attacks),
        key=lambda a: SEVERITY_SCORE.get(SEVERITY_MATRIX.get(a, 'LOW'), 0),
        reverse=True
    )

    primary    = detected_attacks[0]
    severity   = SEVERITY_MATRIX.get(primary, 'LOW')

    # Upgrade severity if multiple attack types detected
    if len(detected_attacks) > 2 and severity != 'CRITICAL':
        severity = 'CRITICAL'

    # ── 3. Build attack details ───────────────────────────────────────────────
    attack_details = []
    for atk in detected_attacks:
        confidence = score_attack(atk, haystack)
        # Scanner detected via user agent gets lower confidence
        if atk == 'SCANNER' and re.search(
            r'(nikto|sqlmap|nmap|burp|zap)', user_agent, re.I
        ):
            confidence = max(confidence, 75.0)

        attack_details.append({
            'type':       atk,
            'confidence': confidence,
            'severity':   SEVERITY_MATRIX.get(atk, 'LOW'),
            'mitre':      MITRE_MAPPING.get(atk, {}),
            'owasp':      OWASP_MAPPING.get(atk, {}),
            'kill_chain': KILL_CHAIN_MAPPING.get(atk, {}),
            'defense':    DEFENSE_RECOMMENDATIONS.get(atk, 'Review and sanitize all user inputs.'),
        })

    # ── 4. Next step predictions (from primary attack) ────────────────────────
    next_steps = NEXT_STEP_PREDICTION.get(primary, [
        'Continue reconnaissance of the application',
        'Attempt further exploitation of discovered vulnerability',
    ])

    # ── 5. Assemble final report ──────────────────────────────────────────────
    report = {
        'id':            _make_id(log_entry),
        'timestamp':     timestamp,
        'ip':            ip,
        'method':        method,
        'path':          path,
        'status':        status,
        'user_agent':    user_agent,
        'duration_ms':   log_entry.get('duration_ms', 0),
        'is_attack':     True,
        'severity':      severity,
        'primary_attack': primary,
        'attacks':       attack_details,
        'payload':       extract_payload(log_entry),
        'geolocation':   get_geolocation(ip),
        'next_steps':    next_steps,
        'brute_info':    brute,
        'raw_log':       log_entry,
    }

    return report

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _make_id(log_entry: dict) -> str:
    """Generate a stable unique ID for each log entry."""
    key = f"{log_entry.get('timestamp','')}{log_entry.get('ip','')}{log_entry.get('path','')}"
    return hashlib.md5(key.encode()).hexdigest()[:12]

def analyze_log_line(line: str) -> dict | None:
    """Parse a raw log line string and return analysis. Returns None on parse error."""
    line = line.strip()
    if not line:
        return None
    try:
        entry = json.loads(line)
        return analyze(entry)
    except json.JSONDecodeError:
        return None
