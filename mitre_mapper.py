# ─────────────────────────────────────────
# SentinelIQ — MITRE ATT&CK Mapping Engine
# Day 4: dictionary-based mapping (no ChromaDB yet)
# ─────────────────────────────────────────

# Full MITRE ATT&CK technique knowledge base.
# Each entry holds the details a SOC analyst needs to
# triage and explain an alert.
MITRE_TECHNIQUES = {
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain "
            "access to accounts when passwords are unknown or "
            "when password hashes are obtained."
        ),
        "threat_actors": ["APT28", "APT39", "FIN5", "Lazarus Group"],
        "mitigations": [
            "Enforce account lockout policies",
            "Require multi-factor authentication (MFA)",
            "Enforce strong password policies",
            "Monitor for repeated authentication failures",
        ],
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries guess passwords using a list of common "
            "passwords against many accounts to gain valid "
            "credentials."
        ),
        "threat_actors": ["APT28", "Turla"],
        "mitigations": [
            "Enforce account lockout policies",
            "Require multi-factor authentication (MFA)",
            "Ban commonly used weak passwords",
        ],
    },
    "T1110.003": {
        "technique_id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": (
            "Adversaries use a single or small list of commonly "
            "used passwords against many different accounts to "
            "avoid account lockouts."
        ),
        "threat_actors": ["APT28", "APT33", "Lazarus Group"],
        "mitigations": [
            "Require multi-factor authentication (MFA)",
            "Monitor for many failed logins across many accounts",
            "Enforce strong, unique password policies",
        ],
    },
    "T1110.004": {
        "technique_id": "T1110.004",
        "name": "Credential Stuffing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries use credentials obtained from breach "
            "dumps to attempt logins across other services, "
            "exploiting password reuse."
        ),
        "threat_actors": ["APT39", "FIN6"],
        "mitigations": [
            "Require multi-factor authentication (MFA)",
            "Detect logins from breached credential lists",
            "Rate-limit and monitor authentication attempts",
        ],
    },
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of "
            "existing accounts to gain initial access, persist, "
            "escalate privileges, or evade defenses."
        ),
        "threat_actors": ["APT28", "APT29", "FIN4", "Lazarus Group"],
        "mitigations": [
            "Require multi-factor authentication (MFA)",
            "Apply least-privilege access controls",
            "Monitor for impossible-travel and anomalous logins",
            "Disable or remove unused accounts",
        ],
    },
    "T1078.001": {
        "technique_id": "T1078.001",
        "name": "Default Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": (
            "Adversaries may abuse default accounts (such as "
            "built-in administrator or guest accounts) that ship "
            "with operating systems or applications."
        ),
        "threat_actors": ["Magic Hound"],
        "mitigations": [
            "Change or disable all default account credentials",
            "Apply least-privilege access controls",
            "Audit default accounts on all systems",
        ],
    },
    "T1566": {
        "technique_id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may send phishing messages with "
            "malicious links or attachments to gain access to "
            "victim systems."
        ),
        "threat_actors": ["APT28", "APT29", "FIN7", "Lazarus Group"],
        "mitigations": [
            "Deploy email and link filtering",
            "Conduct user security awareness training",
            "Restrict execution of attachments",
            "Use network intrusion prevention",
        ],
    },
    "T1090": {
        "technique_id": "T1090",
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may use a connection proxy (such as Tor "
            "or anonymizing services) to direct network traffic "
            "and hide the true source of activity."
        ),
        "threat_actors": ["APT28", "APT41", "Lazarus Group"],
        "mitigations": [
            "Filter and monitor known anonymizer/Tor exit nodes",
            "Use network intrusion detection/prevention",
            "Block traffic to/from unauthorized proxies",
        ],
    },
    "T1059": {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script "
            "interpreters (such as PowerShell, Bash, or Python) "
            "to execute commands, scripts, or binaries."
        ),
        "threat_actors": ["APT3", "APT32", "FIN7", "Lazarus Group"],
        "mitigations": [
            "Disable or restrict unused interpreters",
            "Enable script-block and command-line logging",
            "Apply application control / allow-listing",
        ],
    },
}


# Keyword aliases → technique ID.
# This drives fuzzy matching so that variations like
# "brute force", "bruteforce", and "brute-force" all map
# to the same technique.
KEYWORD_MAP = {
    "brute force": "T1110",
    "bruteforce": "T1110",
    "brute-force": "T1110",
    "brute": "T1110",
    "password guessing": "T1110.001",
    "guessing": "T1110.001",
    "password spraying": "T1110.003",
    "spraying": "T1110.003",
    "spray": "T1110.003",
    "credential stuffing": "T1110.004",
    "credentialstuffing": "T1110.004",
    "stuffing": "T1110.004",
    "valid accounts": "T1078",
    "valid account": "T1078",
    "impossible travel": "T1078",
    "account compromise": "T1078",
    "default accounts": "T1078.001",
    "default account": "T1078.001",
    "phishing": "T1566",
    "phish": "T1566",
    "spear phishing": "T1566",
    "proxy": "T1090",
    "tor": "T1090",
    "anonymizer": "T1090",
    "command and scripting interpreter": "T1059",
    "command and scripting": "T1059",
    "scripting": "T1059",
    "powershell": "T1059",
}


def _normalize(text: str) -> str:
    """Lowercase and collapse separators so that
    'Brute-Force' and 'brute force' compare equal."""
    cleaned = text.strip().lower()
    for ch in ["-", "_", "/"]:
        cleaned = cleaned.replace(ch, " ")
    # Collapse multiple spaces into one
    cleaned = " ".join(cleaned.split())
    return cleaned


def get_mitre_technique(attack_type: str):
    """
    Fuzzy keyword match an attack type to a MITRE technique.

    Returns the full technique dictionary, or None if no
    technique matches the input.

    Examples:
        "brute force"  -> T1110
        "bruteforce"   -> T1110
        "brute-force"  -> T1110
        "phishing"     -> T1566
    """
    if not attack_type or attack_type.strip() == "":
        return None

    normalized = _normalize(attack_type)

    # 1) Direct technique-ID match (e.g. "T1110")
    upper = attack_type.strip().upper()
    if upper in MITRE_TECHNIQUES:
        return MITRE_TECHNIQUES[upper]

    # 2) Exact keyword alias match
    if normalized in KEYWORD_MAP:
        return MITRE_TECHNIQUES[KEYWORD_MAP[normalized]]

    # 3) Substring / partial match against known keywords
    for keyword, technique_id in KEYWORD_MAP.items():
        if keyword in normalized or normalized in keyword:
            return MITRE_TECHNIQUES[technique_id]

    # No match found
    return None


def get_mitre_for_ip(abuse_score: int, isp: str):
    """
    Map an IP-reputation result to a MITRE technique.

    - If the ISP looks like a Tor/anonymizer/proxy provider,
      map to T1090 (Proxy).
    - If the abuse score is high, map to T1110 (Brute Force),
      since abusive IPs are most often brute-force sources.
    - Otherwise return None (nothing notable to map).
    """
    isp_text = (isp or "").lower()

    if any(word in isp_text for word in ["tor", "proxy", "anonymizer", "vpn"]):
        return MITRE_TECHNIQUES["T1090"]

    if abuse_score >= 50:
        return MITRE_TECHNIQUES["T1110"]

    return None


def get_mitre_for_url(malicious_count: int):
    """
    Map a URL-analysis result to a MITRE technique.

    A URL flagged by one or more engines is most commonly a
    phishing or malicious-delivery URL, so map to T1566
    (Phishing). Returns None when nothing was flagged.
    """
    if malicious_count and malicious_count >= 1:
        return MITRE_TECHNIQUES["T1566"]

    return None


# ─────────────────────────────────────────
# Day 13: MITRE mitigation suggestions
# Maps a technique ID to recommended mitigations (M-codes).
# ─────────────────────────────────────────
MITRE_MITIGATIONS = {
    "T1566": [
        {"id": "M1031", "name": "Network Intrusion Prevention",
         "description": "Use intrusion detection signatures to block phishing traffic"},
        {"id": "M1021", "name": "Restrict Web-Based Content",
         "description": "Block access to known malicious domains and URLs"}
    ],
    "T1110": [
        {"id": "M1036", "name": "Account Use Policies",
         "description": "Set account lockout after failed login attempts"},
        {"id": "M1032", "name": "Multi-factor Authentication",
         "description": "Use MFA to mitigate credential compromise"}
    ],
    "T1078": [
        {"id": "M1032", "name": "Multi-factor Authentication",
         "description": "Require MFA especially for remote access"},
        {"id": "M1026", "name": "Privileged Account Management",
         "description": "Audit privileged accounts for suspicious activity"}
    ],
    "T1110.004": [
        {"id": "M1036", "name": "Account Use Policies",
         "description": "Implement rate limiting and account lockout policies"},
        {"id": "M1032", "name": "Multi-factor Authentication",
         "description": "MFA prevents credential stuffing even if passwords are compromised"}
    ],
    "T1090": [
        {"id": "M1037", "name": "Filter Network Traffic",
         "description": "Block known Tor exit nodes and anonymous proxy IPs"},
        {"id": "M1031", "name": "Network Intrusion Prevention",
         "description": "Use IDS/IPS to detect and block proxy-based traffic"}
    ],
    "T1071": [
        {"id": "M1031", "name": "Network Intrusion Prevention",
         "description": "Monitor and filter command and control traffic patterns"},
        {"id": "M1037", "name": "Filter Network Traffic",
         "description": "Block suspicious outbound connections to unknown IPs"}
    ]
}


def get_mitigations(technique_id: str) -> list:
    base_id = technique_id.split(".")[0] if "." in technique_id else technique_id
    return MITRE_MITIGATIONS.get(technique_id,
           MITRE_MITIGATIONS.get(base_id, []))
