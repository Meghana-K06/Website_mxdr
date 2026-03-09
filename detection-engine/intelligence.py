# detection-engine/intelligence.py

import os
import json
from collections import defaultdict, Counter
from datetime import datetime, timezone
from analyzer import analyze_log_line

LOG_FILE = os.path.join(os.path.dirname(__file__), '../logs/access.log')

# ─────────────────────────────────────────────────────────────────────────────
# AGGREGATE STATS  — built from scanning full log file
# ─────────────────────────────────────────────────────────────────────────────

def build_intelligence_report() -> dict:
    """
    Scan the entire access.log and build a full intelligence picture:
    - Top attacking IPs
    - Attack type distribution
    - Hourly timeline
    - Severity breakdown
    - Most targeted endpoints
    """
    if not os.path.exists(LOG_FILE):
        return _empty_report()

    ip_stats:       dict = defaultdict(lambda: {
        'count': 0, 'attacks': 0, 'attack_types': Counter(),
        'last_seen': '', 'severity_max': 'INFO'
    })
    attack_counter: Counter = Counter()
    severity_counter: Counter = Counter()
    hourly_timeline: Counter = Counter()
    endpoint_counter: Counter = Counter()
    total_requests  = 0
    total_attacks   = 0
    recent_events   = []

    with open(LOG_FILE, 'r') as f:
        for line in f:
            result = analyze_log_line(line)
            if not result:
                continue

            total_requests += 1
            ip = result['ip']
            ts = result['timestamp']

            ip_stats[ip]['count']    += 1
            ip_stats[ip]['last_seen'] = ts
            endpoint_counter[result['path']] += 1

            # Hourly bucket
            try:
                hour = datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:00')
                hourly_timeline[hour] += 1
            except Exception:
                pass

            if result['is_attack']:
                total_attacks += 1
                sev = result['severity']
                ip_stats[ip]['attacks'] += 1

                for atk in result['attacks']:
                    attack_counter[atk['type']] += 1
                    ip_stats[ip]['attack_types'][atk['type']] += 1

                severity_counter[sev] += 1

                # Track highest severity per IP
                sev_order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'INFO':0}
                if sev_order.get(sev,0) > sev_order.get(ip_stats[ip]['severity_max'],0):
                    ip_stats[ip]['severity_max'] = sev

                recent_events.append(result)

    # Sort recent events newest first, keep top 100
    recent_events.sort(key=lambda e: e['timestamp'], reverse=True)
    recent_events = recent_events[:100]

    # Build top IPs list
    top_ips = sorted(
        [
            {
                'ip':           ip,
                'total_requests': stats['count'],
                'total_attacks':  stats['attacks'],
                'attack_types':   dict(stats['attack_types']),
                'last_seen':      stats['last_seen'],
                'severity_max':   stats['severity_max'],
                'threat_score':   _threat_score(stats),
            }
            for ip, stats in ip_stats.items()
        ],
        key=lambda x: x['threat_score'],
        reverse=True
    )

    return {
        'generated_at':    datetime.now(timezone.utc).isoformat(),
        'total_requests':  total_requests,
        'total_attacks':   total_attacks,
        'attack_rate':     round((total_attacks / total_requests * 100), 1) if total_requests else 0,
        'attack_types':    dict(attack_counter),
        'severity_counts': dict(severity_counter),
        'hourly_timeline': dict(sorted(hourly_timeline.items())),
        'top_endpoints':   dict(endpoint_counter.most_common(10)),
        'top_ips':         top_ips[:20],
        'recent_events':   recent_events,
    }

def _threat_score(stats: dict) -> int:
    """Simple threat score: weight attacks more than visits."""
    return stats['count'] + (stats['attacks'] * 5)

def _empty_report() -> dict:
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_requests': 0, 'total_attacks': 0, 'attack_rate': 0,
        'attack_types': {}, 'severity_counts': {},
        'hourly_timeline': {}, 'top_endpoints': {},
        'top_ips': [], 'recent_events': [],
    }
