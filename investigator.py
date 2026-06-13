# ─────────────────────────────────────────
# SentinelIQ — Unified Investigator (Day 7)
# Orchestrates threat intel + MITRE + AI RAG into a
# single end-to-end investigation report.
#
# This module REUSES existing engines (read-only imports)
# and replicates the VirusTotal / AbuseIPDB call logic so
# that main.py and the locked modules stay untouched.
# ─────────────────────────────────────────

import os
import time
import datetime

import requests
from dotenv import load_dotenv

# Read-only reuse of existing engines
from login_detector import analyze_login_events
from mitre_mapper import get_mitre_for_url, get_mitre_for_ip
from vector_store import search_mitre
from ai_explainer import (
    explain_url_alert,
    explain_ip_alert,
    explain_login_alert,
)

load_dotenv()

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")


# ─────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────
def _new_investigation_id():
    """Return (investigation_id, iso_timestamp)."""
    now = datetime.datetime.now()
    inv_id = f"INV-{now.strftime('%Y%m%d%H%M%S')}"
    return inv_id, now.isoformat()


def _severity_from_risk(risk_score: int) -> str:
    """Map a 0-100 risk score to a severity band."""
    if risk_score >= 75:
        return "CRITICAL"
    elif risk_score >= 50:
        return "HIGH"
    elif risk_score >= 25:
        return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────
# URL INVESTIGATION
# ─────────────────────────────────────────
def investigate_url(url: str) -> dict:
    """Full investigation for a URL (VirusTotal + MITRE + AI)."""
    inv_id, timestamp = _new_investigation_id()
    headers = {"x-apikey": VT_KEY.strip()}

    # Step 1: Submit URL for analysis
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=10
    )
    if response.status_code != 200:
        raise RuntimeError(f"VirusTotal error: {response.status_code}")

    analysis_id = response.json()["data"]["id"]

    # Step 2: Wait for engines to complete
    time.sleep(15)

    # Step 3: Fetch results
    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=10
    )
    if result.status_code != 200:
        raise RuntimeError(f"VirusTotal error: {result.status_code}")

    data = result.json()

    # Step 4: Extract stats (same fields/logic as /analyze-url)
    stats = data["data"]["attributes"]["stats"]
    malicious = stats["malicious"]
    harmless = stats["harmless"]
    suspicious = stats["suspicious"]
    undetected = stats["undetected"]

    total_engines = malicious + harmless + suspicious + undetected
    risk_score = (
        round((malicious / total_engines) * 100)
        if total_engines > 0 else 0
    )

    explainability = {
        "virustotal": {
            "contribution": round(
                (malicious / total_engines) * 40
            ) if total_engines > 0 else 0,
            "reason": f"{malicious} of {total_engines} engines flagged"
        }
    }

    # Same 3-tier verdict thresholds as /analyze-url
    if malicious > 3:
        verdict = "MALICIOUS"
    elif malicious >= 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    threat_intel = {
        "type": "url_analysis",
        "url": url,
        "malicious_engines": malicious,
        "harmless_engines": harmless,
        "suspicious_engines": suspicious,
        "total_engines": total_engines,
        "primary_mitre": get_mitre_for_url(malicious),
    }

    # MITRE retrieval (semantic) + AI explanation (RAG)
    mitre_mapping = search_mitre(f"malicious url phishing {verdict}")
    ai_explanation = explain_url_alert(threat_intel)

    # Confidence score
    confidence = min(
        100,
        (
            (malicious / total_engines * 100)
            if total_engines > 0 else 0
        ) + (risk_score * 0.5)
    )
    confidence = round(confidence)

    # Recommended action
    if verdict == "MALICIOUS":
        recommended_action = "Block URL immediately and notify users"
    elif verdict == "SUSPICIOUS":
        recommended_action = "Investigate further — do not click"
    else:
        recommended_action = "No action required"

    return {
        "investigation_id": inv_id,
        "timestamp": timestamp,
        "input_type": "url",
        "input_value": url,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "severity": _severity_from_risk(risk_score),
        "recommended_action": recommended_action,
        "threat_intel": threat_intel,
        "mitre_mapping": mitre_mapping,
        "explainability": explainability,
        "ai_explanation": ai_explanation,
        "investigation_complete": True
    }


# ─────────────────────────────────────────
# IP INVESTIGATION
# ─────────────────────────────────────────
def investigate_ip(ip: str) -> dict:
    """Full investigation for an IP (AbuseIPDB + MITRE + AI)."""
    inv_id, timestamp = _new_investigation_id()
    headers = {
        "Key": ABUSE_KEY.strip(),
        "Accept": "application/json"
    }

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params={
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        },
        timeout=10
    )
    if response.status_code != 200:
        raise RuntimeError(f"AbuseIPDB error: {response.status_code}")

    data = response.json()["data"]

    abuse_score = data["abuseConfidenceScore"]
    country = data["countryCode"]
    total_reports = data["totalReports"]
    domain = data.get("domain", "unknown")
    usage_type = data.get("usageType", "unknown")
    isp = data.get("isp", "unknown")

    # Same logic as /analyze-ip
    risk_score = abuse_score

    explainability = {
        "abuseipdb": {
            "contribution": round(abuse_score * 0.4),
            "reason": f"Abuse confidence {abuse_score}%, "
                      f"reported {total_reports} times"
        }
    }

    if abuse_score >= 80:
        verdict = "MALICIOUS"
    elif abuse_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    threat_intel = {
        "type": "ip_analysis",
        "ip": ip,
        "abuse_score": abuse_score,
        "country": country,
        "isp": isp,
        "domain": domain,
        "usage_type": usage_type,
        "total_reports": total_reports,
        "verdict": verdict,
        "primary_mitre": get_mitre_for_ip(abuse_score, isp),
    }

    # MITRE retrieval (semantic) + AI explanation (RAG)
    mitre_mapping = search_mitre(
        f"malicious ip {isp} {verdict} brute force proxy"
    )
    ai_explanation = explain_ip_alert(threat_intel)

    # Confidence score
    confidence = abuse_score

    # Recommended action
    if verdict == "MALICIOUS":
        recommended_action = "Block IP at firewall immediately"
    elif verdict == "SUSPICIOUS":
        recommended_action = "Monitor traffic from this IP"
    else:
        recommended_action = "No action required"

    return {
        "investigation_id": inv_id,
        "timestamp": timestamp,
        "input_type": "ip",
        "input_value": ip,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "severity": _severity_from_risk(risk_score),
        "recommended_action": recommended_action,
        "threat_intel": threat_intel,
        "mitre_mapping": mitre_mapping,
        "explainability": explainability,
        "ai_explanation": ai_explanation,
        "investigation_complete": True
    }


# ─────────────────────────────────────────
# LOGIN INVESTIGATION
# ─────────────────────────────────────────
def investigate_login(events: list) -> dict:
    """Full investigation for login events (detection + MITRE + AI)."""
    inv_id, timestamp = _new_investigation_id()

    # Existing detection engine (unchanged)
    detection = analyze_login_events(events)
    overall_verdict = detection.get("overall_verdict", "CLEAN")

    # Confidence score per blueprint
    if overall_verdict == "CRITICAL":
        confidence = 95
    elif overall_verdict == "SUSPICIOUS":
        confidence = 70
    else:
        confidence = 10

    # Risk score derived from confidence so severity is meaningful
    risk_score = confidence

    # Recommended action
    if overall_verdict == "CRITICAL":
        recommended_action = "Lock affected accounts immediately"
    elif overall_verdict == "SUSPICIOUS":
        recommended_action = "Force password reset + enable MFA"
    else:
        recommended_action = "No action required"

    # MITRE techniques already live in the detection threats;
    # enrich via semantic search for the unified report.
    threats = detection.get("threats", [])
    if threats:
        query_parts = []
        for threat in threats:
            query_parts.append(threat.get("mitre_name", ""))
            query_parts.append(threat.get("type", ""))
        query = " ".join(p for p in query_parts if p)
    else:
        query = "suspicious login authentication anomaly"

    mitre_mapping = search_mitre(query)
    ai_explanation = explain_login_alert(detection)

    explainability = {
        "login_detection": {
            "brute_force_detected":
                detection.get("summary", {}).get("brute_force_detected", 0),
            "impossible_travel_detected":
                detection.get("summary", {}).get(
                    "impossible_travel_detected", 0
                ),
            "credential_stuffing_detected":
                detection.get("summary", {}).get(
                    "credential_stuffing_detected", 0
                ),
            "reason": (
                f"{detection.get('total_threats_detected', 0)} threat(s) "
                f"detected across "
                f"{detection.get('total_events_analyzed', 0)} events"
            )
        }
    }

    return {
        "investigation_id": inv_id,
        "timestamp": timestamp,
        "input_type": "login",
        "input_value": "login_events",
        "verdict": overall_verdict,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "severity": _severity_from_risk(risk_score),
        "recommended_action": recommended_action,
        "threat_intel": detection,
        "mitre_mapping": mitre_mapping,
        "explainability": explainability,
        "ai_explanation": ai_explanation,
        "investigation_complete": True
    }
