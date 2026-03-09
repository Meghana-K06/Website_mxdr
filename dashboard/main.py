# dashboard/main.py

import os
import sys
import json
import asyncio
import time
from datetime import datetime, timezone
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
import uvicorn

# ── Path setup so we can import detection engine ──────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../detection-engine'))
from analyzer    import analyze_log_line
from intelligence import build_intelligence_report

load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(__file__)
LOG_FILE  = os.path.join(BASE_DIR, '../logs/access.log')
TEMPLATES = Jinja2Templates(directory=os.path.join(BASE_DIR, 'templates'))

# ── In-memory state ───────────────────────────────────────────────────────────
# Stores last 500 analyzed events
event_store: list[dict] = []
MAX_EVENTS = 500

# IP visit counter
ip_counter: dict = defaultdict(lambda: {
    'count': 0, 'attacks': 0,
    'last_seen': '', 'severity_max': 'INFO',
    'attack_types': defaultdict(int),
    'geo': {}
})

# Connected WebSocket clients
ws_clients: list[WebSocket] = []

# ─────────────────────────────────────────────────────────────────────────────
# LOG FILE WATCHER
# ─────────────────────────────────────────────────────────────────────────────

async def watch_log_file():
    """
    Tail access.log continuously.
    For each new line: analyze it, update state, broadcast to all WS clients.
    """
    print(f'👁️  Watching log file: {LOG_FILE}')

    # Wait for log file to exist
    while not os.path.exists(LOG_FILE):
        print('⏳ Waiting for log file to appear...')
        await asyncio.sleep(2)

    with open(LOG_FILE, 'r') as f:
        # Seek to end — we only want NEW lines
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.3)
                continue

            result = analyze_log_line(line)
            if not result:
                continue

            # Update in-memory stores
            _update_state(result)

            # Broadcast to all connected dashboard clients
            await _broadcast(result)

async def _broadcast(event: dict):
    """Send event to all connected WebSocket clients."""
    if not ws_clients:
        return

    # Make it JSON-serializable
    payload = json.dumps(event, default=str)
    dead    = []

    for ws in ws_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)

    for ws in dead:
        ws_clients.remove(ws)

def _update_state(result: dict):
    """Update in-memory event store and IP counter."""
    global event_store

    ip  = result.get('ip', 'unknown')
    ts  = result.get('timestamp', '')
    sev = result.get('severity', 'INFO')

    # Event store (newest first, capped at MAX_EVENTS)
    event_store.insert(0, result)
    if len(event_store) > MAX_EVENTS:
        event_store.pop()

    # IP tracking
    ip_counter[ip]['count']    += 1
    ip_counter[ip]['last_seen'] = ts

    if not ip_counter[ip]['geo']:
        ip_counter[ip]['geo'] = result.get('geolocation', {})

    if result.get('is_attack'):
        ip_counter[ip]['attacks'] += 1
        for atk in result.get('attacks', []):
            ip_counter[ip]['attack_types'][atk['type']] += 1

        sev_order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'INFO':0}
        if sev_order.get(sev,0) > sev_order.get(ip_counter[ip]['severity_max'],0):
            ip_counter[ip]['severity_max'] = sev

# ─────────────────────────────────────────────────────────────────────────────
# APP LIFESPAN  — start background watcher when FastAPI starts
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load existing log history into memory on startup
    _load_existing_logs()
    # Start the live tail watcher
    task = asyncio.create_task(watch_log_file())
    yield
    task.cancel()

def _load_existing_logs():
    """Pre-load last 200 log entries so dashboard isn't empty on start."""
    if not os.path.exists(LOG_FILE):
        return
    lines = []
    with open(LOG_FILE, 'r') as f:
        lines = f.readlines()

    # Take last 200 lines
    for line in lines[-200:]:
        result = analyze_log_line(line)
        if result:
            _update_state(result)

    print(f'📂 Pre-loaded {len(event_store)} log entries into memory')

# ─────────────────────────────────────────────────────────────────────────────
# FASTAPI APP
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title='Threat Intelligence Dashboard', lifespan=lifespan)

# Static files
static_dir = os.path.join(BASE_DIR, 'static')
os.makedirs(static_dir, exist_ok=True)
app.mount('/static', StaticFiles(directory=static_dir), name='static')

# ─────────────────────────────────────────────────────────────────────────────
# WEBSOCKET
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket('/ws')
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)
    print(f'🔌 Dashboard client connected. Total: {len(ws_clients)}')
    try:
        while True:
            # Keep connection alive — client can send pings
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_clients.remove(ws)
        print(f'🔌 Dashboard client disconnected. Total: {len(ws_clients)}')

# ─────────────────────────────────────────────────────────────────────────────
# REST API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.get('/api/events')
async def get_events(limit: int = 100, attack_only: bool = False):
    """Return recent events, optionally filtered to attacks only."""
    events = event_store
    if attack_only:
        events = [e for e in events if e.get('is_attack')]
    return {
        'events': events[:limit],
        'total':  len(events),
    }

@app.get('/api/stats')
async def get_stats():
    """Return aggregated stats for charts."""
    report = build_intelligence_report()
    return report

@app.get('/api/ips')
async def get_ips():
    """Return all visitor IPs with stats."""
    result = []
    for ip, stats in ip_counter.items():
        result.append({
            'ip':            ip,
            'total_requests': stats['count'],
            'total_attacks':  stats['attacks'],
            'attack_types':   dict(stats['attack_types']),
            'last_seen':      stats['last_seen'],
            'severity_max':   stats['severity_max'],
            'geo':            stats['geo'],
            'threat_score':   stats['count'] + stats['attacks'] * 5,
        })
    result.sort(key=lambda x: x['threat_score'], reverse=True)
    return {'ips': result, 'total': len(result)}

@app.get('/api/event/{event_id}')
async def get_event_detail(event_id: str):
    """Return full details for a single event by ID."""
    for event in event_store:
        if event.get('id') == event_id:
            return event
    return {'error': 'Event not found'}, 404

@app.get('/api/health')
async def health():
    return {
        'status':         'ok',
        'events_in_memory': len(event_store),
        'connected_clients': len(ws_clients),
        'log_file_exists': os.path.exists(LOG_FILE),
        'timestamp':      datetime.now(timezone.utc).isoformat(),
    }

# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD ROUTE  — serves the main HTML
# ─────────────────────────────────────────────────────────────────────────────

@app.get('/', response_class=HTMLResponse)
async def dashboard(request: Request):
    return TEMPLATES.TemplateResponse('dashboard.html', {'request': request})

# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.getenv('DASHBOARD_PORT', 4000))
    print(f'\n🛡️  Threat Dashboard running → http://localhost:{port}')
    print(f'📡  WebSocket endpoint     → ws://localhost:{port}/ws\n')
    uvicorn.run('main:app', host='0.0.0.0', port=port, reload=False)
