# app.py  — WEB MXDR Streamlit Dashboard
# Preserves all original features + adds Feedback + IP Blocking

import os, sys, json, time
from datetime import datetime, timezone
from collections import defaultdict, Counter
from sample_logs import generate_sample_logs

import streamlit as st
import pandas as pd

# ── path so detection_engine imports work ─────────────────────────────────────
BASE_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(BASE_DIR, 'detection_engine'))

from analyzer    import analyze_log_line
from intelligence import build_intelligence_report
from ip_manager  import (
    block_ip, unblock_ip, get_blocked_ips, is_blocked,
    maybe_auto_block, get_auto_block_log,
    save_feedback, get_all_feedback, get_feedback_for_event, get_feedback_stats,
)

LOG_FILE = '/home/meghana/Desktop/web_MXDR/logs/access.log'

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title='🛡️ WEB MXDR Dashboard',
    page_icon='🛡️',
    layout='wide',
    initial_sidebar_state='expanded',
)

# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM CSS  — preserve dark cyber theme
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base ─────────────────────────────────────────────── */
:root {
  --bg:#080e1a; --surface:#0d1526; --surface2:#111d33; --border:#1e3050;
  --text:#e2e8f0; --muted:#4a6080; --accent:#3b82f6; --accent2:#06b6d4;
  --critical:#ef4444; --high:#f97316; --medium:#eab308;
  --low:#22c55e; --info:#6b7280;
}
html, body, [class*="css"] { background:#080e1a !important; color:#e2e8f0 !important; }
.stApp { background:#080e1a !important; }
section[data-testid="stSidebar"] { background:#0d1526 !important; border-right:1px solid #1e3050; }

/* ── Metric cards ─────────────────────────────────────── */
[data-testid="metric-container"] {
  background:#0d1526 !important; border:1px solid #1e3050 !important;
  border-radius:12px !important; padding:16px !important;
}
[data-testid="stMetricValue"] { font-size:2rem !important; font-weight:800 !important; }

/* ── Tabs ─────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] { background:#0d1526; border-radius:8px; gap:4px; padding:4px; }
.stTabs [data-baseweb="tab"] { color:#4a6080 !important; font-weight:600; border-radius:6px; }
.stTabs [aria-selected="true"] { background:#1e3050 !important; color:#06b6d4 !important; }

/* ── Buttons ──────────────────────────────────────────── */
.stButton>button {
  background:#0d1526; border:1px solid #1e3050; color:#e2e8f0;
  border-radius:8px; font-weight:600; transition:all .15s;
}
.stButton>button:hover { border-color:#3b82f6; color:#3b82f6; background:#111d33; }
.block-btn>button { border-color:#ef4444 !important; color:#ef4444 !important; }
.unblock-btn>button { border-color:#22c55e !important; color:#22c55e !important; }
.tp-btn>button { border-color:#22c55e !important; color:#22c55e !important; }
.fp-btn>button { border-color:#f97316 !important; color:#f97316 !important; }

/* ── Severity badges ──────────────────────────────────── */
.badge { display:inline-block; padding:2px 10px; border-radius:20px;
  font-size:.7rem; font-weight:700; text-transform:uppercase; }
.CRITICAL { background:rgba(239,68,68,.2); color:#ef4444; border:1px solid rgba(239,68,68,.3); }
.HIGH     { background:rgba(249,115,22,.2); color:#f97316; border:1px solid rgba(249,115,22,.3); }
.MEDIUM   { background:rgba(234,179,8,.2);  color:#eab308; border:1px solid rgba(234,179,8,.3); }
.LOW      { background:rgba(34,197,94,.2);  color:#22c55e; border:1px solid rgba(34,197,94,.3); }
.INFO     { background:rgba(107,114,128,.2);color:#6b7280; border:1px solid rgba(107,114,128,.3); }

/* ── Tables ───────────────────────────────────────────── */
.stDataFrame { border:1px solid #1e3050 !important; border-radius:10px !important; }
thead th { background:#0d1526 !important; color:#4a6080 !important; font-size:.72rem !important; text-transform:uppercase; }
tbody tr:hover td { background:#111d33 !important; }

/* ── Cards ────────────────────────────────────────────── */
.mxdr-card {
  background:#0d1526; border:1px solid #1e3050; border-radius:12px;
  padding:16px; margin-bottom:12px;
}
.mxdr-card h4 { color:#06b6d4; font-size:.85rem; margin-bottom:8px; }
.mxdr-card p  { font-size:.78rem; color:#e2e8f0; margin:3px 0; }
.mxdr-card .lbl { color:#4a6080; font-size:.72rem; }
.blocked-tag { background:rgba(239,68,68,.15); color:#ef4444;
  border:1px solid rgba(239,68,68,.3); border-radius:6px;
  padding:2px 8px; font-size:.7rem; font-weight:700; }
.auto-tag { background:rgba(249,115,22,.15); color:#f97316;
  border:1px solid rgba(249,115,22,.3); border-radius:6px;
  padding:2px 8px; font-size:.7rem; }
.manual-tag { background:rgba(59,130,246,.15); color:#3b82f6;
  border:1px solid rgba(59,130,246,.3); border-radius:6px;
  padding:2px 8px; font-size:.7rem; }
.tp-tag { background:rgba(34,197,94,.15); color:#22c55e;
  border:1px solid rgba(34,197,94,.3); border-radius:6px;
  padding:2px 8px; font-size:.7rem; }
.fp-tag { background:rgba(249,115,22,.15); color:#f97316;
  border:1px solid rgba(249,115,22,.3); border-radius:6px;
  padding:2px 8px; font-size:.7rem; }

/* ── selectbox / inputs ───────────────────────────────── */
.stSelectbox>div>div, .stTextInput>div>div>input, .stTextArea>div>div>textarea {
  background:#111d33 !important; border-color:#1e3050 !important; color:#e2e8f0 !important;
}
.stToggle>label { color:#e2e8f0 !important; }

/* ── Headers ──────────────────────────────────────────── */
h1,h2,h3,h4 { color:#e2e8f0 !important; }
.section-title {
  font-size:.75rem; font-weight:700; text-transform:uppercase; letter-spacing:.5px;
  color:#4a6080; margin-bottom:12px; display:flex; align-items:center; gap:6px;
}
.section-title::before { content:''; display:inline-block; width:6px; height:6px; border-radius:50%; background:#3b82f6; }

/* ── Divider ──────────────────────────────────────────── */
hr { border-color:#1e3050 !important; }
.stAlert { background:#111d33 !important; border-color:#1e3050 !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
if 'events'          not in st.session_state: st.session_state.events = []
if 'auto_block_on'   not in st.session_state: st.session_state.auto_block_on = True
if 'analyst_name'    not in st.session_state: st.session_state.analyst_name = 'SOC Analyst'
if 'last_loaded'     not in st.session_state: st.session_state.last_loaded = 0
if 'selected_event'  not in st.session_state: st.session_state.selected_event = None

# ─────────────────────────────────────────────────────────────────────────────
# LOG LOADER
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_events(limit: int = 500) -> list[dict]:
    """Load & analyze log entries. Cached for 30 s."""
    events = []
    if not os.path.exists(LOG_FILE):
        return events
    with open(LOG_FILE, 'r') as f:
        lines = f.readlines()
    for line in lines[-limit:]:
        result = analyze_log_line(line)
        if result:
            events.insert(0, result)
    return events

@st.cache_data(ttl=60)
def load_intel() -> dict:
    return build_intelligence_report()

# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY HELPER
# ─────────────────────────────────────────────────────────────────────────────
SEV_COLOR = {'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e','INFO':'#6b7280'}
SEV_ICON  = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','INFO':'⚪'}

def sev_badge(s: str) -> str:
    return f'<span class="badge {s}">{s}</span>'

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('## 🛡️ WEB MXDR')
    st.markdown('<p style="color:#4a6080;font-size:.78rem;margin-top:-10px;">Managed Extended Detection & Response</p>', unsafe_allow_html=True)
    st.divider()

    st.session_state.analyst_name = st.text_input(
        '👤 Analyst Name',
        value=st.session_state.analyst_name,
        placeholder='Enter your name...',
    )

    st.divider()
    st.markdown('### ⚙️ Settings')
    st.session_state.auto_block_on = st.toggle(
        '🤖 Auto-Block on Detection',
        value=st.session_state.auto_block_on,
        help='Automatically block IPs that trigger high-confidence attack rules.',
    )

    limit = st.slider('Events to load', 100, 1000, 500, 50)

    if st.button('🔄 Refresh Data', use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    st.divider()
    st.markdown('### 🧪 Demo')
    st.caption('No logs yet? Load sample attack scenarios to populate the dashboard.')
    sample_count = st.select_slider(
        'Number of sample logs',
        options=[20, 40, 60, 80, 100, 150, 200],
        value=80,
    )
    if st.button('📂 Load Sample Logs', use_container_width=True, type='primary'):
        with st.spinner('Generating sample attack logs...'):
            n = generate_sample_logs(sample_count)
            st.cache_data.clear()
        st.success(f'✅ Loaded {n} sample log entries!')
        st.rerun()

    if st.button('🗑️ Clear All Logs', use_container_width=True):
        log_path = os.path.join(BASE_DIR, 'logs', 'access.log')
        if os.path.exists(log_path):
            open(log_path, 'w').close()
            st.cache_data.clear()
            st.success('Logs cleared.')
            st.rerun()

    st.divider()
    blocked = get_blocked_ips()
    fb_stats = get_feedback_stats()
    st.metric('🚫 Blocked IPs',   len(blocked))
    st.metric('📋 Total Feedback', fb_stats['total'])
    st.metric('✅ True Positives', f"{fb_stats['tp_rate']}%")
    st.metric('⚠️ False Positives', f"{fb_stats['fp_rate']}%")

# ─────────────────────────────────────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────────────────────────────────────
events = load_events(limit)
intel  = load_intel()

attacks   = [e for e in events if e.get('is_attack')]
blocked_set = {b['ip'] for b in get_blocked_ips()}

# Auto-block new events if enabled
if st.session_state.auto_block_on:
    for ev in attacks[:50]:  # check recent 50
        maybe_auto_block(ev, auto_block_enabled=True)

# ─────────────────────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────────────────────
col_logo, col_status = st.columns([3, 1])
with col_logo:
    st.markdown('# 🛡️ WEB MXDR — Threat Intelligence Dashboard')
with col_status:
    now_str = datetime.now().strftime('%H:%M:%S')
    st.markdown(f"""
    <div style="text-align:right;padding-top:16px;">
      <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;margin-right:6px;"></span>
      <span style="color:#22c55e;font-size:.8rem;font-weight:700;">LIVE</span>
      <span style="color:#4a6080;font-size:.75rem;margin-left:8px;">{now_str}</span>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# ─────────────────────────────────────────────────────────────────────────────
# TOP METRICS ROW
# ─────────────────────────────────────────────────────────────────────────────
m1, m2, m3, m4, m5, m6 = st.columns(6)
sev_counts = intel.get('severity_counts', {})

with m1:
    st.metric('📡 Total Requests', f"{intel.get('total_requests', 0):,}")
with m2:
    st.metric('⚔️ Total Attacks', f"{intel.get('total_attacks', 0):,}")
with m3:
    st.metric('🔴 Critical', sev_counts.get('CRITICAL', 0))
with m4:
    st.metric('🟠 High', sev_counts.get('HIGH', 0))
with m5:
    st.metric('🟡 Medium', sev_counts.get('MEDIUM', 0))
with m6:
    st.metric('🚫 Blocked IPs', len(blocked))

st.divider()

# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────
tab_live, tab_intel, tab_ips, tab_block, tab_feedback = st.tabs([
    '📡 Live Feed',
    '📊 Intelligence',
    '🌐 IP Analysis',
    '🚫 IP Blocking',
    '📋 SOC Feedback',
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — LIVE FEED
# ══════════════════════════════════════════════════════════════════════════════
with tab_live:
    st.markdown('<div class="section-title">Live Log Feed</div>', unsafe_allow_html=True)

    # Filters
    fc1, fc2, fc3 = st.columns([2, 2, 2])
    with fc1:
        sev_filter = st.multiselect('Severity', ['CRITICAL','HIGH','MEDIUM','LOW','INFO'], default=[])
    with fc2:
        atk_filter = st.multiselect('Attack Type', ['SQLI','XSS','CMDI','PATH_TRAVERSAL','BRUTE_FORCE','SCANNER'], default=[])
    with fc3:
        attacks_only = st.toggle('Attacks only', value=False)

    filtered = events
    if attacks_only:
        filtered = [e for e in filtered if e.get('is_attack')]
    if sev_filter:
        filtered = [e for e in filtered if e.get('severity') in sev_filter]
    if atk_filter:
        def has_atk(e):
            return any(a['type'] in atk_filter for a in e.get('attacks', []))
        filtered = [e for e in filtered if has_atk(e)]

    st.caption(f'Showing {len(filtered)} of {len(events)} events')

    # Event list
    for ev in filtered[:200]:
        sev   = ev.get('severity', 'INFO')
        ip    = ev.get('ip', '-')
        ts    = ev.get('timestamp', '')[:19].replace('T', ' ')
        path  = ev.get('path', '-')
        meth  = ev.get('method', '-')
        atks  = ', '.join(a['type'] for a in ev.get('attacks', []))
        eid   = ev.get('id', '')
        fb    = get_feedback_for_event(eid)
        blocked_tag = '<span class="blocked-tag">BLOCKED</span>' if ip in blocked_set else ''
        fb_tag = ''
        if fb:
            if fb['verdict'] == 'true_positive':
                fb_tag = '<span class="tp-tag">✅ TP</span>'
            else:
                fb_tag = '<span class="fp-tag">⚠️ FP</span>'

        left_border = SEV_COLOR.get(sev, '#1e3050')
        row_html = f"""
        <div style="background:#0d1526;border:1px solid #1e3050;border-left:3px solid {left_border};
             border-radius:8px;padding:8px 14px;margin-bottom:4px;display:grid;
             grid-template-columns:140px 120px 60px 1fr 120px 80px;gap:8px;align-items:center;font-size:.78rem;">
          <span style="color:#4a6080;font-family:monospace;font-size:.72rem;">{ts}</span>
          <span style="color:#06b6d4;font-family:monospace;">{ip} {blocked_tag}</span>
          <span style="color:#a78bfa;font-weight:700;">{meth}</span>
          <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{path}</span>
          <span style="color:#f97316;font-size:.7rem;">{atks}</span>
          {sev_badge(sev)} {fb_tag}
        </div>
        """
        st.markdown(row_html, unsafe_allow_html=True)

        # Expand button per event
        with st.expander(f'🔍 Details — {eid}', expanded=False):
            d1, d2 = st.columns(2)
            with d1:
                st.markdown('**Event Info**')
                st.write(f"**IP:** `{ip}`")
                st.write(f"**Method:** `{meth}`")
                st.write(f"**Path:** `{path}`")
                st.write(f"**Status:** `{ev.get('status','')}`")
                st.write(f"**Severity:** {sev_badge(sev)}", unsafe_allow_html=True)
                st.write(f"**Duration:** `{ev.get('duration_ms',0)} ms`")
                geo = ev.get('geolocation', {})
                if geo:
                    st.write(f"**Location:** {geo.get('city','?')}, {geo.get('country','?')}")
                    st.write(f"**Org:** {geo.get('org','?')}")

            with d2:
                st.markdown('**Attack Details**')
                for atk in ev.get('attacks', []):
                    st.markdown(f"""
                    <div class="mxdr-card">
                      <h4>{atk['type']}</h4>
                      <p><span class="lbl">Confidence:</span> {atk.get('confidence',0)}%</p>
                      <p><span class="lbl">MITRE:</span> {atk.get('mitre',{}).get('technique_id','?')} — {atk.get('mitre',{}).get('technique_name','?')}</p>
                      <p><span class="lbl">OWASP:</span> {atk.get('owasp',{}).get('id','?')} {atk.get('owasp',{}).get('name','?')}</p>
                      <p><span class="lbl">Kill Chain:</span> {atk.get('kill_chain',{}).get('phase','?')}</p>
                      <p><span class="lbl">Defense:</span> {atk.get('defense','')}</p>
                    </div>
                    """, unsafe_allow_html=True)

            if ev.get('payload'):
                st.markdown('**Payload**')
                st.code(ev['payload'], language=None)

            if ev.get('next_steps'):
                st.markdown('**Predicted Next Steps**')
                for step in ev['next_steps']:
                    st.markdown(f'→ {step}')

            # ── FEEDBACK WIDGET ───────────────────────────────────────────
            st.divider()
            st.markdown('### 📋 SOC Analyst Feedback')
            existing_fb = get_feedback_for_event(eid)
            if existing_fb:
                v_icon = '✅' if existing_fb['verdict'] == 'true_positive' else '⚠️'
                st.success(f"{v_icon} Already triaged by **{existing_fb['analyst']}** as **{existing_fb['verdict'].replace('_',' ').title()}**")
                if existing_fb.get('notes'):
                    st.info(f"📝 Notes: {existing_fb['notes']}")
                if st.button('✏️ Update Feedback', key=f'update_{eid}'):
                    st.session_state[f'edit_fb_{eid}'] = True

            if not existing_fb or st.session_state.get(f'edit_fb_{eid}'):
                fb1, fb2 = st.columns(2)
                with fb1:
                    st.markdown('<div class="tp-btn">', unsafe_allow_html=True)
                    if st.button('✅ True Positive', key=f'tp_{eid}', use_container_width=True):
                        save_feedback(eid, 'true_positive', st.session_state.analyst_name, '', ev)
                        st.success('Marked as True Positive')
                        st.cache_data.clear()
                        st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)
                with fb2:
                    st.markdown('<div class="fp-btn">', unsafe_allow_html=True)
                    if st.button('⚠️ False Positive', key=f'fp_{eid}', use_container_width=True):
                        save_feedback(eid, 'false_positive', st.session_state.analyst_name, '', ev)
                        st.warning('Marked as False Positive')
                        st.cache_data.clear()
                        st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)

                notes = st.text_area('Notes (optional)', key=f'notes_{eid}', placeholder='Add analyst notes, context, or remediation steps...')
                if notes and st.button('💾 Save with Notes', key=f'save_notes_{eid}'):
                    verdict = existing_fb['verdict'] if existing_fb else 'true_positive'
                    save_feedback(eid, verdict, st.session_state.analyst_name, notes, ev)
                    st.success('Feedback saved with notes')
                    st.cache_data.clear()
                    st.rerun()

            # ── QUICK IP BLOCK ────────────────────────────────────────────
            st.divider()
            if ip in blocked_set:
                st.markdown('<div class="unblock-btn">', unsafe_allow_html=True)
                if st.button(f'🔓 Unblock {ip}', key=f'unbl_{eid}'):
                    unblock_ip(ip)
                    st.success(f'Unblocked {ip}')
                    st.cache_data.clear()
                    st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="block-btn">', unsafe_allow_html=True)
                if ev.get('is_attack') and st.button(f'🚫 Block {ip}', key=f'bl_{eid}'):
                    block_ip(ip, f'Manual block from Live Feed — {atks}', mode='manual',
                             analyst=st.session_state.analyst_name, severity=sev)
                    st.error(f'Blocked {ip}')
                    st.cache_data.clear()
                    st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — INTELLIGENCE (Charts)
# ══════════════════════════════════════════════════════════════════════════════
with tab_intel:
    st.markdown('<div class="section-title">Threat Intelligence Overview</div>', unsafe_allow_html=True)

    ic1, ic2 = st.columns(2)

    # Attack type distribution
    with ic1:
        st.markdown('**Attack Type Distribution**')
        atk_data = intel.get('attack_types', {})
        if atk_data:
            df_atk = pd.DataFrame(list(atk_data.items()), columns=['Attack', 'Count'])
            df_atk = df_atk.sort_values('Count', ascending=False)
            st.bar_chart(df_atk.set_index('Attack'), color='#3b82f6')
        else:
            st.info('No attack data yet.')

    # Severity breakdown
    with ic2:
        st.markdown('**Severity Distribution**')
        sev_data = intel.get('severity_counts', {})
        if sev_data:
            df_sev = pd.DataFrame(list(sev_data.items()), columns=['Severity', 'Count'])
            st.bar_chart(df_sev.set_index('Severity'), color='#ef4444')
        else:
            st.info('No severity data yet.')

    # Timeline
    st.markdown('**Hourly Request Timeline**')
    timeline = intel.get('hourly_timeline', {})
    if timeline:
        df_tl = pd.DataFrame(list(timeline.items()), columns=['Hour', 'Requests'])
        df_tl['Hour'] = pd.to_datetime(df_tl['Hour'])
        df_tl = df_tl.sort_values('Hour')
        st.line_chart(df_tl.set_index('Hour'), color='#06b6d4')
    else:
        st.info('No timeline data yet.')

    # Top endpoints
    st.markdown('**Most Targeted Endpoints**')
    endpoints = intel.get('top_endpoints', {})
    if endpoints:
        df_ep = pd.DataFrame(list(endpoints.items()), columns=['Endpoint', 'Hits'])
        df_ep = df_ep.sort_values('Hits', ascending=False).head(10)
        st.dataframe(df_ep, use_container_width=True, hide_index=True)

    # Recent events table
    st.markdown('**Recent Attack Events**')
    recent = intel.get('recent_events', [])
    if recent:
        rows = []
        for e in recent[:50]:
            rows.append({
                'Time':       e.get('timestamp', '')[:19].replace('T', ' '),
                'IP':         e.get('ip', ''),
                'Method':     e.get('method', ''),
                'Path':       e.get('path', ''),
                'Severity':   e.get('severity', ''),
                'Attack':     e.get('primary_attack', ''),
                'Status':     e.get('status', ''),
            })
        df_r = pd.DataFrame(rows)
        st.dataframe(df_r, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — IP ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
with tab_ips:
    st.markdown('<div class="section-title">IP Threat Analysis</div>', unsafe_allow_html=True)

    top_ips = intel.get('top_ips', [])
    if not top_ips:
        st.info('No IP data yet. Load some logs.')
    else:
        rows = []
        for entry in top_ips[:50]:
            ip = entry['ip']
            rows.append({
                'IP':            ip,
                'Requests':      entry['total_requests'],
                'Attacks':       entry['total_attacks'],
                'Max Severity':  entry['severity_max'],
                'Threat Score':  entry['threat_score'],
                'Attack Types':  ', '.join(entry.get('attack_types', {}).keys()),
                'Last Seen':     entry['last_seen'][:19].replace('T', ' ') if entry.get('last_seen') else '',
                'Blocked':       '🚫 YES' if ip in blocked_set else '',
            })
        df_ips = pd.DataFrame(rows)
        st.dataframe(df_ips, use_container_width=True, hide_index=True)

        # Geo map
        st.markdown('**Geographic Distribution**')
        geo_rows = []
        ip_set_seen = set()
        for ev in events:
            ip = ev.get('ip', '')
            if ip in ip_set_seen:
                continue
            ip_set_seen.add(ip)
            geo = ev.get('geolocation', {})
            lat, lon = geo.get('lat', 0), geo.get('lon', 0)
            if lat and lon and not (lat == 0 and lon == 0):
                geo_rows.append({'lat': lat, 'lon': lon})
        if geo_rows:
            df_geo = pd.DataFrame(geo_rows)
            st.map(df_geo, zoom=1)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — IP BLOCKING
# ══════════════════════════════════════════════════════════════════════════════
with tab_block:
    st.markdown('<div class="section-title">IP Block Management</div>', unsafe_allow_html=True)

    bl1, bl2 = st.columns([1, 1])

    # ── Manual Block ──────────────────────────────────────────────────────────
    with bl1:
        st.markdown('### 🔒 Manual IP Block')
        manual_ip = st.text_input('IP Address to block', placeholder='e.g. 192.168.1.100', key='manual_ip_input')
        manual_reason = st.text_area('Reason', placeholder='Why are you blocking this IP?', key='manual_reason_input', height=80)

        c_block, c_unblock = st.columns(2)
        with c_block:
            st.markdown('<div class="block-btn">', unsafe_allow_html=True)
            if st.button('🚫 Block IP', use_container_width=True, key='do_manual_block'):
                if manual_ip:
                    res = block_ip(manual_ip.strip(), manual_reason or 'Manual block', mode='manual',
                                   analyst=st.session_state.analyst_name)
                    if res['status'] == 'blocked':
                        st.error(f'✅ Blocked `{manual_ip}`')
                    else:
                        st.warning(f'`{manual_ip}` is already blocked.')
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.warning('Enter an IP address first.')
            st.markdown('</div>', unsafe_allow_html=True)
        with c_unblock:
            st.markdown('<div class="unblock-btn">', unsafe_allow_html=True)
            if st.button('🔓 Unblock IP', use_container_width=True, key='do_manual_unblock'):
                if manual_ip:
                    unblock_ip(manual_ip.strip())
                    st.success(f'Unblocked `{manual_ip}`')
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.warning('Enter an IP address first.')
            st.markdown('</div>', unsafe_allow_html=True)

    # ── Auto-Block Status ─────────────────────────────────────────────────────
    with bl2:
        st.markdown('### 🤖 Auto-Block Rules')
        auto_status = '🟢 ENABLED' if st.session_state.auto_block_on else '🔴 DISABLED'
        st.markdown(f'**Status:** {auto_status}')
        st.markdown('Auto-block triggers when:')
        rules_md = """
| Attack Type | Min Confidence |
|---|---|
| CMDI | 60% |
| SQLI | 70% |
| PATH_TRAVERSAL | 70% |
| XSS | 80% |
| BRUTE_FORCE | 50% |
| SCANNER | 75% |
| Any CRITICAL | Immediate |
"""
        st.markdown(rules_md)

    st.divider()

    # ── Active Block List ─────────────────────────────────────────────────────
    st.markdown('### 🚫 Active Block List')
    blocked_list = get_blocked_ips()
    if not blocked_list:
        st.info('No IPs are currently blocked.')
    else:
        for b in blocked_list:
            bc1, bc2, bc3, bc4, bc5 = st.columns([2, 3, 2, 2, 1])
            mode_tag = f'<span class="auto-tag">🤖 AUTO</span>' if b['mode'] == 'auto' else f'<span class="manual-tag">👤 MANUAL</span>'
            with bc1:
                st.markdown(f'`{b["ip"]}`')
            with bc2:
                st.caption(b.get('reason', ''))
            with bc3:
                st.markdown(f'{mode_tag} {sev_badge(b.get("severity","INFO"))}', unsafe_allow_html=True)
            with bc4:
                st.caption(b.get('blocked_at', '')[:19].replace('T', ' '))
            with bc5:
                if st.button('🔓', key=f'unbl_list_{b["ip"]}', help=f'Unblock {b["ip"]}'):
                    unblock_ip(b['ip'])
                    st.cache_data.clear()
                    st.rerun()
            st.divider()

    # ── Auto-Block Log ────────────────────────────────────────────────────────
    st.markdown('### 📜 Auto-Block Log')
    abl = get_auto_block_log()
    if not abl:
        st.info('No auto-block events yet.')
    else:
        df_abl = pd.DataFrame(abl[:50])
        st.dataframe(df_abl[['timestamp','ip','reason','severity']].rename(
            columns={'timestamp':'Time','ip':'IP','reason':'Reason','severity':'Severity'}
        ), use_container_width=True, hide_index=True)

    # ── Quick block from high-threat IPs ─────────────────────────────────────
    st.markdown('### ⚡ Quick Block — Top Threats')
    threat_ips = [ip for ip in intel.get('top_ips', [])[:10] if ip['ip'] not in blocked_set and ip['total_attacks'] > 0]
    if not threat_ips:
        st.caption('All top threat IPs are already blocked or no threats found.')
    for tip in threat_ips:
        qc1, qc2, qc3, qc4 = st.columns([2, 1, 2, 1])
        with qc1:
            st.markdown(f'`{tip["ip"]}`')
        with qc2:
            st.markdown(sev_badge(tip['severity_max']), unsafe_allow_html=True)
        with qc3:
            st.caption(f"Attacks: {tip['total_attacks']}  |  Score: {tip['threat_score']}")
        with qc4:
            st.markdown('<div class="block-btn">', unsafe_allow_html=True)
            if st.button('🚫 Block', key=f'qbl_{tip["ip"]}', use_container_width=True):
                block_ip(tip['ip'], f'Quick block — threat score {tip["threat_score"]}',
                         mode='manual', analyst=st.session_state.analyst_name,
                         severity=tip['severity_max'])
                st.cache_data.clear()
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — SOC FEEDBACK
# ══════════════════════════════════════════════════════════════════════════════
with tab_feedback:
    st.markdown('<div class="section-title">SOC Analyst Feedback & Alert Triage</div>', unsafe_allow_html=True)

    # Stats row
    fb_stats = get_feedback_stats()
    fs1, fs2, fs3, fs4 = st.columns(4)
    with fs1: st.metric('Total Triaged', fb_stats['total'])
    with fs2: st.metric('True Positives', fb_stats['true_positives'])
    with fs3: st.metric('False Positives', fb_stats['false_positives'])
    with fs4: st.metric('TP Rate', f"{fb_stats['tp_rate']}%")

    st.divider()

    # Feedback filter
    verdict_filter = st.selectbox('Filter by verdict', ['All', 'True Positive', 'False Positive'])

    all_fb = get_all_feedback()
    if verdict_filter == 'True Positive':
        all_fb = [f for f in all_fb if f['verdict'] == 'true_positive']
    elif verdict_filter == 'False Positive':
        all_fb = [f for f in all_fb if f['verdict'] == 'false_positive']

    all_fb_sorted = sorted(all_fb, key=lambda x: x.get('created_at', ''), reverse=True)

    if not all_fb_sorted:
        st.info('No feedback submitted yet. Review alerts in the Live Feed tab and mark them as True/False Positive.')
    else:
        for fb in all_fb_sorted:
            v = fb['verdict']
            v_color = '#22c55e' if v == 'true_positive' else '#f97316'
            v_label = '✅ True Positive' if v == 'true_positive' else '⚠️ False Positive'
            ev_snap = fb.get('event_snapshot', {})

            st.markdown(f"""
            <div class="mxdr-card" style="border-left:3px solid {v_color};">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <span style="color:{v_color};font-weight:700;">{v_label}</span>
                <span style="color:#4a6080;font-size:.72rem;">{fb.get('created_at','')[:19].replace('T',' ')}</span>
              </div>
              <p><span class="lbl">Analyst:</span> <strong>{fb.get('analyst','?')}</strong></p>
              <p><span class="lbl">Event ID:</span> <code>{fb.get('event_id','?')}</code></p>
              <p><span class="lbl">IP:</span> <code>{fb.get('ip','?')}</code></p>
              <p><span class="lbl">Attack Type:</span> {fb.get('attack_type','?')}</p>
              <p><span class="lbl">Severity:</span> {sev_badge(fb.get('severity','INFO'))}</p>
              <p><span class="lbl">Path:</span> <code>{fb.get('path','?')}</code></p>
              {'<p><span class="lbl">Notes:</span> ' + fb.get('notes','') + '</p>' if fb.get('notes') else ''}
            </div>
            """, unsafe_allow_html=True)

            # Allow adding feedback+block from feedback tab
            fb_col1, fb_col2, fb_col3 = st.columns(3)
            with fb_col1:
                if st.button('🔄 Flip Verdict', key=f'flip_{fb["event_id"]}'):
                    new_v = 'false_positive' if v == 'true_positive' else 'true_positive'
                    save_feedback(fb['event_id'], new_v, st.session_state.analyst_name, fb.get('notes',''), ev_snap)
                    st.cache_data.clear()
                    st.rerun()
            with fb_col2:
                tip_ip = fb.get('ip', '')
                if tip_ip and tip_ip not in blocked_set:
                    st.markdown('<div class="block-btn">', unsafe_allow_html=True)
                    if st.button(f'🚫 Block {tip_ip}', key=f'fb_block_{fb["event_id"]}'):
                        block_ip(tip_ip, f'Blocked from feedback — {v}', mode='manual',
                                 analyst=st.session_state.analyst_name, severity=fb.get('severity',''))
                        st.cache_data.clear()
                        st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)
                elif tip_ip in blocked_set:
                    st.markdown('<div class="unblock-btn">', unsafe_allow_html=True)
                    if st.button(f'🔓 Unblock {tip_ip}', key=f'fb_unbl_{fb["event_id"]}'):
                        unblock_ip(tip_ip)
                        st.cache_data.clear()
                        st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)
            with fb_col3:
                new_note = st.text_input('Add note', key=f'fb_note_{fb["event_id"]}', placeholder='Additional note...')
                if new_note and st.button('💾 Save', key=f'fb_save_note_{fb["event_id"]}'):
                    save_feedback(fb['event_id'], v, st.session_state.analyst_name, new_note, ev_snap)
                    st.cache_data.clear()
                    st.rerun()

    # Export feedback as CSV
    st.divider()
    if all_fb:
        export_rows = []
        for fb in all_fb:
            export_rows.append({
                'event_id':    fb.get('event_id',''),
                'verdict':     fb.get('verdict',''),
                'analyst':     fb.get('analyst',''),
                'ip':          fb.get('ip',''),
                'attack_type': fb.get('attack_type',''),
                'severity':    fb.get('severity',''),
                'path':        fb.get('path',''),
                'notes':       fb.get('notes',''),
                'created_at':  fb.get('created_at',''),
            })
        df_export = pd.DataFrame(export_rows)
        csv = df_export.to_csv(index=False)
        st.download_button(
            '⬇️ Export Feedback CSV',
            data=csv,
            file_name=f'mxdr_feedback_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            mime='text/csv',
        )

# ─────────────────────────────────────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────────────────────────────────────
st.divider()
st.markdown("""
<div style="text-align:center;color:#1e3050;font-size:.72rem;padding:8px;">
  WEB MXDR — SISA Internship 2026 · BMSIT&M · Built with Flask detection engine + Streamlit
</div>
""", unsafe_allow_html=True)
