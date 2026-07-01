# ─────────────────────────────────────────
# SentinelIQ — Tunable Detection Configuration
#
# Central home for every threshold, magic number, and tunable
# constant used by the detection / scoring logic. A SOC team can
# adjust these values to fit their environment WITHOUT editing any
# business-logic code.
#
# Nothing in this file imports project modules, so it is safe to
# import from anywhere (no circular-import risk).
# ─────────────────────────────────────────


# ── Risk Scoring — IP verdict classification ──────────────────
# AbuseIPDB abuse-confidence thresholds (0-100).
ABUSE_SCORE_MALICIOUS = 80              # abuse score >= this → MALICIOUS
ABUSE_SCORE_SUSPICIOUS = 30             # abuse score >= this → SUSPICIOUS
ABUSE_SCORE_PREVIOUSLY_MALICIOUS = 10  # abuse score < this (with prior reports) → PREVIOUSLY_MALICIOUS


# ── SANS ISC — third threat-intel source ──────────────────────
SANS_REPORTS_MALICIOUS = 50000   # SANS attack reports > this → MALICIOUS
SANS_REPORTS_SUSPICIOUS = 5000   # SANS attack reports > this → SUSPICIOUS
SANS_BONUS_DIVISOR = 5000        # reports // this = extra risk points
SANS_BONUS_MAX = 40              # cap the SANS risk contribution here
SANS_CACHE_TTL_SECONDS = 600     # refresh the SANS top-100 feed every 10 min


# ── Previously-malicious floor ────────────────────────────────
PREVIOUSLY_MALICIOUS_RISK_FLOOR = 20  # minimum risk for a PREVIOUSLY_MALICIOUS verdict


# ── URL verdict classification (VirusTotal engines) ───────────
URL_MALICIOUS_ENGINE_COUNT = 3   # malicious engines > this → MALICIOUS
URL_SUSPICIOUS_ENGINE_COUNT = 1  # malicious engines >= this → SUSPICIOUS


# ── Severity bands (mapped from the 0-100 risk score) ─────────
SEVERITY_CRITICAL_MIN = 75  # risk >= this → CRITICAL
SEVERITY_HIGH_MIN = 50      # risk >= this → HIGH
SEVERITY_MEDIUM_MIN = 25    # risk >= this → MEDIUM (else LOW)


# ── SOAR — auto-playbook trigger ──────────────────────────────
SOAR_TRIGGER_RISK = 75    # risk score >= this triggers a SOAR alert
SOAR_CRITICAL_RISK = 90   # risk score >= this → CRITICAL severity (else HIGH)


# ── Bulk investigation — CSV triage buckets ───────────────────
BULK_FLAGGED_RISK = 70   # bulk row risk >= this → counted as high-risk/flagged
BULK_CLEAN_RISK = 30     # bulk row risk < this → counted as clean


# ── Rate Limiting (slowapi format: "<count>/<period>") ────────
RATE_LIMIT_INVESTIGATE = "10/minute"
RATE_LIMIT_BULK = "3/minute"
RATE_LIMIT_HUNT = "20/minute"


# ── Login Detection — REFERENCE ONLY ──────────────────────────
# NOTE: login_detector.py is a LOCKED module and is NOT wired to
# read from this config. These values mirror the constants/inline
# numbers currently hardcoded in login_detector.py and are listed
# here for documentation. Changing them here has NO effect until
# login_detector.py is unlocked and refactored to import them.
BRUTE_FORCE_WINDOW_MINUTES = 10    # time window for brute-force detection
BRUTE_FORCE_FAILURE_THRESHOLD = 5  # failures within the window → brute force
CREDENTIAL_STUFFING_THRESHOLD = 3  # unique usernames from one IP → cred stuffing
TRAVEL_SPEED_KMH = 900             # max realistic travel speed (km/h) — already a named constant in login_detector.py
