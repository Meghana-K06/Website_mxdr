# ip_manager.py  — IP Block List & Feedback Store
import json
import os
from datetime import datetime, timezone

DATA_DIR      = os.path.join(os.path.dirname(__file__), 'data')
BLOCKLIST_FILE = os.path.join(DATA_DIR, 'blocked_ips.json')
FEEDBACK_FILE  = os.path.join(DATA_DIR, 'feedback.json')
AUTO_BLOCK_LOG = os.path.join(DATA_DIR, 'auto_block_log.json')

os.makedirs(DATA_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _load(path: str) -> list | dict:
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def _save(path: str, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

# ─────────────────────────────────────────────────────────────────────────────
# BLOCK LIST MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

def get_blocked_ips() -> list[dict]:
    data = _load(BLOCKLIST_FILE)
    return data if isinstance(data, list) else []

def is_blocked(ip: str) -> bool:
    return any(b['ip'] == ip for b in get_blocked_ips())

def block_ip(ip: str, reason: str, mode: str = 'manual', analyst: str = 'SOC Analyst', severity: str = '') -> dict:
    blocked = get_blocked_ips()
    # Prevent duplicates
    if any(b['ip'] == ip for b in blocked):
        return {'status': 'already_blocked', 'ip': ip}
    entry = {
        'ip':        ip,
        'reason':    reason,
        'mode':      mode,        # 'manual' | 'auto'
        'analyst':   analyst,
        'severity':  severity,
        'blocked_at': _now(),
        'active':    True,
    }
    blocked.append(entry)
    _save(BLOCKLIST_FILE, blocked)
    return {'status': 'blocked', 'ip': ip}

def unblock_ip(ip: str) -> dict:
    blocked = get_blocked_ips()
    updated = [b for b in blocked if b['ip'] != ip]
    _save(BLOCKLIST_FILE, updated)
    return {'status': 'unblocked', 'ip': ip}

# ─────────────────────────────────────────────────────────────────────────────
# AUTO-BLOCK LOGIC  — called by the engine after analysis
# ─────────────────────────────────────────────────────────────────────────────

# Thresholds for automatic block
AUTO_BLOCK_RULES = {
    'CMDI':           {'min_confidence': 60, 'reason': 'Automated block: Command Injection detected'},
    'SQLI':           {'min_confidence': 70, 'reason': 'Automated block: SQL Injection detected'},
    'PATH_TRAVERSAL': {'min_confidence': 70, 'reason': 'Automated block: Path Traversal detected'},
    'XSS':            {'min_confidence': 80, 'reason': 'Automated block: XSS detected'},
    'BRUTE_FORCE':    {'min_confidence': 50, 'reason': 'Automated block: Brute Force detected'},
    'SCANNER':        {'min_confidence': 75, 'reason': 'Automated block: Scanner activity detected'},
}

def maybe_auto_block(event: dict, auto_block_enabled: bool = True) -> dict | None:
    """Evaluate an event and auto-block its IP if rules match. Returns block entry or None."""
    if not auto_block_enabled:
        return None
    if not event.get('is_attack'):
        return None
    if is_blocked(event.get('ip', '')):
        return None

    ip       = event.get('ip', '')
    severity = event.get('severity', 'INFO')

    # Always auto-block CRITICAL severity
    if severity == 'CRITICAL':
        result = block_ip(ip, 'Automated block: CRITICAL severity event', mode='auto', severity=severity)
        _log_auto_block(ip, event, 'CRITICAL severity threshold')
        return result

    for atk in event.get('attacks', []):
        atype = atk.get('type', '')
        conf  = atk.get('confidence', 0)
        rule  = AUTO_BLOCK_RULES.get(atype)
        if rule and conf >= rule['min_confidence']:
            result = block_ip(ip, rule['reason'], mode='auto', severity=severity)
            _log_auto_block(ip, event, f'{atype} confidence {conf}%')
            return result

    return None

def _log_auto_block(ip: str, event: dict, reason: str):
    log = _load(AUTO_BLOCK_LOG)
    if not isinstance(log, list):
        log = []
    log.append({
        'ip':        ip,
        'reason':    reason,
        'event_id':  event.get('id'),
        'severity':  event.get('severity'),
        'timestamp': _now(),
    })
    _save(AUTO_BLOCK_LOG, log[-200:])  # keep last 200

def get_auto_block_log() -> list[dict]:
    data = _load(AUTO_BLOCK_LOG)
    return data if isinstance(data, list) else []

# ─────────────────────────────────────────────────────────────────────────────
# FEEDBACK / ALERT TRIAGE
# ─────────────────────────────────────────────────────────────────────────────

def save_feedback(event_id: str, verdict: str, analyst: str, notes: str, event_snapshot: dict) -> dict:
    """
    verdict: 'true_positive' | 'false_positive'
    """
    feedbacks = get_all_feedback()
    # Update if already exists
    for fb in feedbacks:
        if fb['event_id'] == event_id:
            fb.update({'verdict': verdict, 'analyst': analyst, 'notes': notes, 'updated_at': _now()})
            _save(FEEDBACK_FILE, feedbacks)
            return fb

    entry = {
        'event_id':       event_id,
        'verdict':        verdict,
        'analyst':        analyst,
        'notes':          notes,
        'created_at':     _now(),
        'ip':             event_snapshot.get('ip', ''),
        'attack_type':    event_snapshot.get('primary_attack', ''),
        'severity':       event_snapshot.get('severity', ''),
        'path':           event_snapshot.get('path', ''),
        'event_snapshot': event_snapshot,
    }
    feedbacks.append(entry)
    _save(FEEDBACK_FILE, feedbacks)
    return entry

def get_all_feedback() -> list[dict]:
    data = _load(FEEDBACK_FILE)
    return data if isinstance(data, list) else []

def get_feedback_for_event(event_id: str) -> dict | None:
    for fb in get_all_feedback():
        if fb['event_id'] == event_id:
            return fb
    return None

def get_feedback_stats() -> dict:
    feedbacks = get_all_feedback()
    tp = sum(1 for f in feedbacks if f['verdict'] == 'true_positive')
    fp = sum(1 for f in feedbacks if f['verdict'] == 'false_positive')
    total = len(feedbacks)
    return {
        'total':          total,
        'true_positives': tp,
        'false_positives': fp,
        'tp_rate':        round(tp / total * 100, 1) if total else 0,
        'fp_rate':        round(fp / total * 100, 1) if total else 0,
    }
