# 🛡️ WEB MXDR — Streamlit Dashboard

**Web Managed Extended Detection & Response**
SISA Internship 2026 · BMSIT&M

---

## Features

- **Live Log Feed** — Real-time analysis of web access logs with Isolation Forest anomaly detection
- **Threat Intelligence** — Attack type distribution, severity charts, hourly timeline, top endpoints
- **IP Analysis** — Geolocation enrichment, threat scoring, geographic map
- **IP Blocking** — Manual block/unblock + Automatic blocking on high-confidence detections
- **SOC Feedback** — True Positive / False Positive triage per alert, analyst notes, CSV export
- **MITRE ATT&CK / OWASP / Cyber Kill Chain** — Full framework enrichment per attack

---

## How to Run on Ubuntu

### Step 1 — Install Python & pip (if not installed)
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y
```

### Step 2 — Create & activate a virtual environment
```bash
cd mxdr_streamlit
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — (Optional) Add ipinfo.io token for geolocation
Edit the `.env` file:
```bash
nano .env
# Add your token: IPINFO_TOKEN=your_token_here
```
Get a free token at https://ipinfo.io/signup

### Step 5 — Run the dashboard
```bash
streamlit run app.py
```

Open your browser at: **http://localhost:8501**

---

## Folder Structure

```
mxdr_streamlit/
├── app.py                    ← Main Streamlit app
├── ip_manager.py             ← IP blocking + SOC feedback engine
├── requirements.txt
├── .env                      ← IPINFO_TOKEN (optional)
├── .streamlit/
│   └── config.toml           ← Dark theme config
├── detection_engine/
│   ├── analyzer.py           ← Log analysis + attack detection
│   ├── intelligence.py       ← Aggregate stats builder
│   └── patterns.py           ← Attack signatures + MITRE/OWASP/Kill Chain mappings
├── logs/
│   └── access.log            ← Web access logs (JSON format)
└── data/                     ← Auto-created: stores block list, feedback, auto-block log
    ├── blocked_ips.json
    ├── feedback.json
    └── auto_block_log.json
```

---

## Log Format

The `logs/access.log` file should contain one JSON object per line:
```json
{"timestamp":"2024-01-01T12:00:00Z","ip":"1.2.3.4","method":"GET","path":"/login","status":200,"user_agent":"Mozilla/5.0","query":"{}","body":"{}"}
```

To generate test logs, run your Flask target-site and point traffic at it.

---

## IP Blocking Modes

| Mode | How |
|---|---|
| **Manual** | Click "Block IP" in Live Feed, IP Blocking tab, or SOC Feedback tab |
| **Auto** | Triggered automatically when attack confidence exceeds threshold |

Auto-block thresholds:
- CMDI ≥ 60% confidence → instant block
- SQLI ≥ 70%
- PATH_TRAVERSAL ≥ 70%
- XSS ≥ 80%
- BRUTE_FORCE ≥ 50%
- SCANNER ≥ 75%
- ANY event with CRITICAL severity → instant block

Toggle auto-blocking in the sidebar.

---

## SOC Feedback Workflow

1. Open **Live Feed** tab → click any event to expand
2. Review MITRE ATT&CK mapping, payload, kill chain phase
3. Click **✅ True Positive** or **⚠️ False Positive**
4. Optionally add analyst notes
5. All feedback is stored in `data/feedback.json`
6. View all triaged alerts and export CSV in the **SOC Feedback** tab
