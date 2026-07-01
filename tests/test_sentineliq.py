# ─────────────────────────────────────────
# SentinelIQ — focused pytest suite
#
# Covers the most bug-prone logic: the investigate_ip verdict
# chain, the risk_breakdown numerical guarantee, the three login
# detection rules, and the MITRE semantic search.
#
# All external API calls (_call_abuseipdb, check_sans_isc) and the
# Groq AI call (explain_ip_alert) are mocked — no real HTTP happens.
# Business logic is NEVER modified to make a test pass; only the
# mocks/assertions are shaped to match reality.
# ─────────────────────────────────────────

import re
from unittest.mock import patch

import pytest

# Import the REAL tunable thresholds so tests never hardcode them.
from config import (
    ABUSE_SCORE_MALICIOUS,
    ABUSE_SCORE_SUSPICIOUS,
    ABUSE_SCORE_PREVIOUSLY_MALICIOUS,
    PREVIOUSLY_MALICIOUS_RISK_FLOOR,
    SANS_BONUS_DIVISOR,
    SANS_BONUS_MAX,
)

import investigator
from investigator import investigate_ip
from login_detector import analyze_login_events
from vector_store import search_mitre


# ─────────────────────────────────────────
# Test fixtures / helpers
# ─────────────────────────────────────────

def make_abuse_data(**overrides):
    """
    Build a dict with the EXACT shape _call_abuseipdb returns
    (AbuseIPDB's response.json()["data"] object). investigate_ip
    reads: abuseConfidenceScore, countryCode, totalReports, domain,
    usageType, isp, isPublic, isWhitelisted.
    """
    data = {
        "ipAddress": "1.2.3.4",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example ISP",
        "domain": "example.com",
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
    }
    data.update(overrides)
    return data


# check_sans_isc's real return shapes.
NO_SANS = {"found": False, "reports": 0, "targets": 0}


def sans_found(reports):
    """Mirror check_sans_isc's 'found' return shape (includes rank)."""
    return {"found": True, "reports": reports, "targets": 12, "rank": 5}


# Stand-ins so investigate_ip never touches ChromaDB or Groq.
FAKE_MITRE = [
    {"technique_id": "T1090", "name": "Proxy", "tactic": "Command and Control",
     "score": 0.51, "search_method": "test"}
]
FAKE_AI = {
    "explanation": "test", "primary_mitre": "T1090",
    "recommended_action": "x", "ai_model": "test", "grounded": True,
}


def run_ip(abuse_data, sans_result=NO_SANS):
    """
    Run investigate_ip with all externalities mocked:
      - _call_abuseipdb  → the given AbuseIPDB data dict
      - check_sans_isc   → the given SANS result
      - search_mitre     → a fixed technique list (no ChromaDB)
      - explain_ip_alert → a fixed dict (no Groq HTTP call)
    Patches target the investigator module globals so the calls made
    inside its ThreadPoolExecutor pick up the mocks too.
    """
    with patch.object(investigator, "_call_abuseipdb", return_value=abuse_data), \
         patch.object(investigator, "check_sans_isc", return_value=sans_result), \
         patch.object(investigator, "search_mitre", return_value=list(FAKE_MITRE)), \
         patch.object(investigator, "explain_ip_alert", return_value=dict(FAKE_AI)):
        return investigate_ip(abuse_data["ipAddress"])


# ─────────────────────────────────────────
# SECTION 1 — Verdict chain
# ─────────────────────────────────────────

def test_ip_malicious_high_abuse_score():
    """A very high AbuseIPDB score (>= ABUSE_SCORE_MALICIOUS) must
    yield a MALICIOUS verdict."""
    result = run_ip(make_abuse_data(abuseConfidenceScore=95, totalReports=50))
    assert result["verdict"] == "MALICIOUS"
    assert result["risk_score"] >= ABUSE_SCORE_MALICIOUS


def test_ip_suspicious_medium_abuse_score():
    """A mid-range score (>= ABUSE_SCORE_SUSPICIOUS but below
    MALICIOUS) must yield SUSPICIOUS."""
    result = run_ip(make_abuse_data(abuseConfidenceScore=45, totalReports=10))
    assert result["verdict"] == "SUSPICIOUS"
    assert ABUSE_SCORE_SUSPICIOUS <= result["risk_score"] < ABUSE_SCORE_MALICIOUS


def test_ip_previously_malicious():
    """An IP with prior reports but a now-low score (< PREV_MAL
    threshold) is PREVIOUSLY_MALICIOUS, and its risk is floored at
    PREVIOUSLY_MALICIOUS_RISK_FLOOR so it is never shown as risk-free."""
    result = run_ip(make_abuse_data(abuseConfidenceScore=5, totalReports=8))
    assert result["verdict"] == "PREVIOUSLY_MALICIOUS"
    assert result["risk_score"] >= PREVIOUSLY_MALICIOUS_RISK_FLOOR


def test_ip_clean_zero_reports_with_real_record():
    """A public IP with a real AbuseIPDB record (country/isp/domain
    present) but zero reports and zero abuse is genuinely CLEAN —
    not UNRATED."""
    result = run_ip(make_abuse_data(
        abuseConfidenceScore=0, totalReports=0,
        countryCode="US", isp="Cloudflare", domain="cloudflare.com",
    ))
    assert result["verdict"] == "CLEAN"


def test_ip_unrated_no_record():
    """An IP AbuseIPDB has NO usable record for (no country, isp, or
    domain) is UNRATED with risk_score 0 — 'no data', not 'clean'."""
    result = run_ip(make_abuse_data(
        abuseConfidenceScore=0, totalReports=0,
        countryCode=None, isp=None, domain=None,
    ))
    assert result["verdict"] == "UNRATED"
    assert result["risk_score"] == 0


def test_ip_private_is_unrated():
    """A private/reserved (non-routable) IP overrides all other
    signal → UNRATED, risk 0."""
    result = run_ip(make_abuse_data(
        isPublic=False, usageType="Reserved",
        abuseConfidenceScore=0, totalReports=0,
    ))
    assert result["verdict"] == "UNRATED"
    assert result["risk_score"] == 0


def test_ip_whitelisted_public_is_clean():
    """A whitelisted public IP (recognized known-good service) is
    CLEAN with risk 0, even if stray reports exist."""
    result = run_ip(make_abuse_data(
        isPublic=True, isWhitelisted=True,
        abuseConfidenceScore=0, totalReports=5,
    ))
    assert result["verdict"] == "CLEAN"
    assert result["risk_score"] == 0


def test_ip_sans_upgrades_clean_to_suspicious():
    """SANS ISC is an independent source: an IP AbuseIPDB knows
    nothing about, but that SANS reports heavily (> SUSPICIOUS
    report threshold), must be lifted to at least SUSPICIOUS."""
    result = run_ip(
        make_abuse_data(abuseConfidenceScore=0, totalReports=0),
        sans_result=sans_found(30000),
    )
    assert result["verdict"] == "SUSPICIOUS"


# ─────────────────────────────────────────
# SECTION 2 — Risk breakdown numerical guarantee
# ─────────────────────────────────────────

def test_risk_breakdown_sums_to_risk_score():
    """Every 'contribution' in risk_breakdown must sum EXACTLY to
    risk_score — the numerical-correctness guarantee shown to
    analysts (weights must never leak or double-count risk)."""
    result = run_ip(make_abuse_data(
        abuseConfidenceScore=90, totalReports=100, isp="Cloudflare",
    ))
    assert result["verdict"] == "MALICIOUS"
    total = sum(item["contribution"] for item in result["risk_breakdown"])
    assert total == pytest.approx(result["risk_score"], abs=0.01)


# ─────────────────────────────────────────
# SECTION 3 — Login detector
# The real output field on each threat dict is "type".
# ─────────────────────────────────────────

def _threat_types(result):
    return [t.get("type", "").lower() for t in result.get("threats", [])]


def test_brute_force_detected():
    """6 failed logins from one IP/user inside 10 minutes must raise
    a brute-force threat."""
    events = [
        {"ip": "10.0.0.1", "username": "alice", "success": "false",
         "country": "US", "timestamp": f"2026-07-01T10:0{i}:00"}
        for i in range(6)
    ]
    result = analyze_login_events(events)
    assert any("brute" in t for t in _threat_types(result))


def test_brute_force_not_triggered_below_threshold():
    """Only 4 failed logins (below the 5-failure threshold) must NOT
    raise a brute-force threat."""
    events = [
        {"ip": "10.0.0.2", "username": "bob", "success": "false",
         "country": "US", "timestamp": f"2026-07-01T10:0{i}:00"}
        for i in range(4)
    ]
    result = analyze_login_events(events)
    assert not any("brute" in t for t in _threat_types(result))


def test_impossible_travel_detected():
    """Two successful logins by the same user from India then the UK
    only 30 minutes apart is physically impossible → travel threat."""
    events = [
        {"ip": "10.0.0.3", "username": "carol", "success": "true",
         "country": "IN", "timestamp": "2026-07-01T10:00:00"},
        {"ip": "20.0.0.4", "username": "carol", "success": "true",
         "country": "GB", "timestamp": "2026-07-01T10:30:00"},
    ]
    result = analyze_login_events(events)
    assert any("travel" in t for t in _threat_types(result))


def test_credential_stuffing_detected():
    """4 distinct usernames from a single IP is credential stuffing."""
    events = [
        {"ip": "10.0.0.5", "username": u, "success": "false",
         "country": "US", "timestamp": f"2026-07-01T10:0{i}:00"}
        for i, u in enumerate(["u1", "u2", "u3", "u4"])
    ]
    result = analyze_login_events(events)
    assert any(("stuffing" in t or "credential" in t) for t in _threat_types(result))


# ─────────────────────────────────────────
# SECTION 4 — MITRE semantic search
# ─────────────────────────────────────────

def test_mitre_search_returns_results():
    """search_mitre must return a non-empty list, each result
    carrying a 'technique_id' field."""
    results = search_mitre("brute force login attack credential")
    assert isinstance(results, list)
    assert len(results) >= 1
    assert "technique_id" in results[0]


def test_mitre_search_technique_id_format():
    """Every returned technique_id must be a valid MITRE ID
    (T followed by 4 digits, optionally a sub-technique suffix)."""
    results = search_mitre("phishing email")
    assert len(results) >= 1
    for item in results:
        assert re.match(r"T\d{4}", item["technique_id"])
