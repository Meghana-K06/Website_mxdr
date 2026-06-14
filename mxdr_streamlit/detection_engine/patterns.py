# detection-engine/patterns.py
import re

# ─────────────────────────────────────────────────────────────────────────────
# ATTACK SIGNATURES
# Each entry: (compiled_regex, weight)
# Higher weight = stronger indicator of that attack type
# ─────────────────────────────────────────────────────────────────────────────

SIGNATURES = {

    'SQLI': [
        (re.compile(r"'(\s*)(or|and)(\s+)\d+\s*=\s*\d+", re.I),          10),
        (re.compile(r"union(\s+)select", re.I),                            10),
        (re.compile(r"drop(\s+)table", re.I),                              10),
        (re.compile(r"insert(\s+)into", re.I),                              8),
        (re.compile(r"select(.+)from", re.I),                               8),
        (re.compile(r"sleep\s*\(\s*\d+\s*\)", re.I),                       9),
        (re.compile(r"benchmark\s*\(", re.I),                               9),
        (re.compile(r"information_schema", re.I),                           9),
        (re.compile(r"xp_cmdshell", re.I),                                  9),
        (re.compile(r"'(\s*)(--|\#)", re.I),                                7),
        (re.compile(r";\s*(drop|insert|update|delete|select)", re.I),       8),
        (re.compile(r"\bor\b\s+['\d].*=.*['\d]", re.I),                    7),
        (re.compile(r"waitfor\s+delay", re.I),                              9),
        (re.compile(r"(load_file|outfile|dumpfile)", re.I),                 8),
        (re.compile(r"char\s*\(\s*\d+", re.I),                             6),
    ],

    'XSS': [
        (re.compile(r"<script[\s>]", re.I),                                10),
        (re.compile(r"</script>", re.I),                                   10),
        (re.compile(r"javascript\s*:", re.I),                               9),
        (re.compile(r"on(error|load|click|mouseover|focus)\s*=", re.I),     9),
        (re.compile(r"alert\s*\(", re.I),                                   8),
        (re.compile(r"document\.(cookie|write|location)", re.I),            9),
        (re.compile(r"<iframe[\s>]", re.I),                                 9),
        (re.compile(r"<img[^>]+onerror", re.I),                             9),
        (re.compile(r"eval\s*\(", re.I),                                    8),
        (re.compile(r"<svg[\s>].*on\w+\s*=", re.I),                        9),
        (re.compile(r"(prompt|confirm)\s*\(", re.I),                        7),
        (re.compile(r"String\.fromCharCode\s*\(", re.I),                    8),
        (re.compile(r"expression\s*\(", re.I),                              7),
        (re.compile(r"vbscript\s*:", re.I),                                 9),
    ],

    'PATH_TRAVERSAL': [
        (re.compile(r"\.\./"),                                             10),
        (re.compile(r"\.\.\\"),                                            10),
        (re.compile(r"%2e%2e[%2f%5c]", re.I),                             10),
        (re.compile(r"%252e%252e", re.I),                                  10),
        (re.compile(r"/etc/passwd"),                                       10),
        (re.compile(r"/etc/shadow"),                                       10),
        (re.compile(r"/etc/hosts"),                                         8),
        (re.compile(r"/proc/self", re.I),                                   9),
        (re.compile(r"windows[/\\]system32", re.I),                        10),
        (re.compile(r"boot\.ini", re.I),                                    9),
        (re.compile(r"\.\.%2f", re.I),                                      9),
        (re.compile(r"\.\.%5c", re.I),                                      9),
    ],

    'CMDI': [
        (re.compile(r";\s*(id|whoami|ls|pwd|cat|echo|wget|curl)\b", re.I), 10),
        (re.compile(r"\|\s*(id|whoami|ls|cat|bash|sh)\b", re.I),          10),
        (re.compile(r"&&\s*(id|whoami|ls|cat)\b", re.I),                  10),
        (re.compile(r"\$\([^)]+\)"),                                        9),
        (re.compile(r"`[^`]+`"),                                            9),
        (re.compile(r"/bin/(bash|sh|zsh|dash)", re.I),                     9),
        (re.compile(r"(nc|netcat)\s+-[lnvue]", re.I),                     10),
        (re.compile(r"wget\s+http", re.I),                                  9),
        (re.compile(r"curl\s+http", re.I),                                  8),
        (re.compile(r"chmod\s+[0-7]{3,4}", re.I),                          8),
        (re.compile(r"python[23]?\s+-c", re.I),                             9),
        (re.compile(r"base64\s+--decode", re.I),                            8),
        (re.compile(r"cmd\.exe\s*/c", re.I),                               10),
        (re.compile(r"powershell\s+-", re.I),                              10),
    ],

    'BRUTE_FORCE': [
        (re.compile(r"(login|signin|auth|session)", re.I),                  5),
    ],

    'SCANNER': [
        (re.compile(r"(nikto|sqlmap|nmap|masscan|gobuster|dirb|dirbuster)", re.I), 10),
        (re.compile(r"(burpsuite|burp suite|owasp zap|w3af|acunetix)", re.I),      10),
        (re.compile(r"python-requests/", re.I),                             6),
        (re.compile(r"go-http-client", re.I),                               6),
        (re.compile(r"(hydra|medusa|patator)", re.I),                      10),
        (re.compile(r"zgrab|masscan|shodan", re.I),                        10),
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# THREAT INTELLIGENCE MAPPINGS
# ─────────────────────────────────────────────────────────────────────────────

MITRE_MAPPING = {
    'SQLI': {
        'technique_id':   'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'tactic':         'Initial Access',
        'tactic_id':      'TA0001',
        'description':    'Adversary exploits weakness in SQL query construction to manipulate database.',
        'url':            'https://attack.mitre.org/techniques/T1190/',
    },
    'XSS': {
        'technique_id':   'T1059.007',
        'technique_name': 'JavaScript Execution via XSS',
        'tactic':         'Execution',
        'tactic_id':      'TA0002',
        'description':    'Malicious scripts injected into web pages executed in victim browsers.',
        'url':            'https://attack.mitre.org/techniques/T1059/007/',
    },
    'PATH_TRAVERSAL': {
        'technique_id':   'T1083',
        'technique_name': 'File and Directory Discovery',
        'tactic':         'Discovery',
        'tactic_id':      'TA0007',
        'description':    'Attacker reads arbitrary files outside the web root via path manipulation.',
        'url':            'https://attack.mitre.org/techniques/T1083/',
    },
    'CMDI': {
        'technique_id':   'T1059',
        'technique_name': 'Command and Scripting Interpreter',
        'tactic':         'Execution',
        'tactic_id':      'TA0002',
        'description':    'Attacker injects OS commands through unsanitized application input.',
        'url':            'https://attack.mitre.org/techniques/T1059/',
    },
    'BRUTE_FORCE': {
        'technique_id':   'T1110',
        'technique_name': 'Brute Force',
        'tactic':         'Credential Access',
        'tactic_id':      'TA0006',
        'description':    'Attacker submits many passwords to gain unauthorized access.',
        'url':            'https://attack.mitre.org/techniques/T1110/',
    },
    'SCANNER': {
        'technique_id':   'T1595',
        'technique_name': 'Active Scanning',
        'tactic':         'Reconnaissance',
        'tactic_id':      'TA0043',
        'description':    'Automated tool scanning for vulnerabilities and exposed endpoints.',
        'url':            'https://attack.mitre.org/techniques/T1595/',
    },
}

OWASP_MAPPING = {
    'SQLI':           {'id': 'A03:2021', 'name': 'Injection',
                       'description': 'Untrusted data sent to interpreter as part of a command or query.'},
    'XSS':            {'id': 'A03:2021', 'name': 'Injection (XSS)',
                       'description': 'Malicious scripts injected into content delivered to users.'},
    'PATH_TRAVERSAL': {'id': 'A01:2021', 'name': 'Broken Access Control',
                       'description': 'Restrictions on authenticated users not properly enforced.'},
    'CMDI':           {'id': 'A03:2021', 'name': 'Injection',
                       'description': 'OS commands injected through unsanitized user input.'},
    'BRUTE_FORCE':    {'id': 'A07:2021', 'name': 'Identification and Authentication Failures',
                       'description': 'Authentication mechanisms can be bypassed or overwhelmed.'},
    'SCANNER':        {'id': 'A05:2021', 'name': 'Security Misconfiguration',
                       'description': 'Exposed endpoints and information disclosure to scanning tools.'},
}

KILL_CHAIN_MAPPING = {
    'SCANNER':        {'phase': 'Reconnaissance',    'order': 1,
                       'description': 'Attacker is actively probing and mapping the target surface.'},
    'BRUTE_FORCE':    {'phase': 'Weaponization / Delivery', 'order': 2,
                       'description': 'Attacker attempting to gain valid credentials for access.'},
    'SQLI':           {'phase': 'Exploitation',      'order': 3,
                       'description': 'Attacker exploiting SQL injection to extract or manipulate data.'},
    'XSS':            {'phase': 'Exploitation',      'order': 3,
                       'description': 'Attacker injecting scripts for session hijacking or defacement.'},
    'PATH_TRAVERSAL': {'phase': 'Exploitation',      'order': 3,
                       'description': 'Attacker traversing filesystem to access sensitive files.'},
    'CMDI':           {'phase': 'Installation / C2', 'order': 5,
                       'description': 'Attacker executing OS commands — likely establishing persistence.'},
}

SEVERITY_MATRIX = {
    'SQLI':           'HIGH',
    'XSS':            'MEDIUM',
    'PATH_TRAVERSAL': 'HIGH',
    'CMDI':           'CRITICAL',
    'BRUTE_FORCE':    'MEDIUM',
    'SCANNER':        'LOW',
}

SEVERITY_SCORE = {
    'CRITICAL': 4,
    'HIGH':     3,
    'MEDIUM':   2,
    'LOW':      1,
    'INFO':     0,
}

NEXT_STEP_PREDICTION = {
    'SQLI': [
        'Attempt UNION-based data extraction from users/credentials table',
        'Try time-based blind SQLi to enumerate database schema',
        'Attempt to read system files using LOAD_FILE()',
        'Escalate to OS command execution via xp_cmdshell (MSSQL)',
        'Dump entire database and exfiltrate credentials',
    ],
    'XSS': [
        'Inject persistent XSS payload to steal session cookies from other users',
        'Redirect victims to phishing page via document.location',
        'Capture keystrokes via JavaScript event listeners',
        'Attempt to escalate to CSRF attack using injected form',
        'Use BeEF framework to hook browsers for further exploitation',
    ],
    'PATH_TRAVERSAL': [
        'Attempt to read /etc/passwd to enumerate system users',
        'Try to access /etc/shadow for password hashes',
        'Read application config files (.env, config.py, settings.py)',
        'Access SSH private keys (~/.ssh/id_rsa)',
        'Read web server config to find other hosted apps',
    ],
    'CMDI': [
        'Establish reverse shell for persistent remote access',
        'Download and execute malware via wget/curl',
        'Add SSH key to authorized_keys for backdoor access',
        'Enumerate internal network (ifconfig, netstat, arp)',
        'Attempt privilege escalation via SUID binaries or sudo',
    ],
    'BRUTE_FORCE': [
        'Switch to credential stuffing using known leaked passwords',
        'Try common username/password combos (admin/admin, root/root)',
        'After login — pivot to privilege escalation inside app',
        'Use valid credentials to access other services (SSH, FTP)',
        'Attempt password spray across all enumerated usernames',
    ],
    'SCANNER': [
        'Move from passive recon to active exploitation of found endpoints',
        'Run targeted SQLmap/XSSer on discovered input fields',
        'Enumerate hidden directories via discovered path patterns',
        'Fingerprint tech stack to find known CVEs',
        'Map all user-controllable inputs for injection testing',
    ],
}

DEFENSE_RECOMMENDATIONS = {
    'SQLI':           'Use parameterized queries / prepared statements. Never interpolate user input into SQL.',
    'XSS':            'Sanitize all output with context-aware encoding. Implement Content Security Policy (CSP).',
    'PATH_TRAVERSAL': 'Validate and sanitize file paths. Use os.path.realpath() and whitelist allowed directories.',
    'CMDI':           'Never pass user input to shell commands. Use subprocess with argument lists, not shell=True.',
    'BRUTE_FORCE':    'Implement rate limiting, account lockout, CAPTCHA, and multi-factor authentication.',
    'SCANNER':        'Deploy a WAF, hide server headers, and block known scanner User-Agent strings.',
}
