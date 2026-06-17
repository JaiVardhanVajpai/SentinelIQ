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
from mitre_mapper import get_mitre_for_url, get_mitre_for_ip, get_mitigations
from vector_store import search_mitre
from ai_explainer import (
    explain_url_alert,
    explain_ip_alert,
    explain_login_alert,
)

# Day 8: MongoDB persistence
from database import get_db

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

    # Day 13: attach recommended mitigations to each technique
    mitre_with_mitigations = []
    for technique in (mitre_mapping or []):
        technique_copy = dict(technique)
        technique_copy["mitigations"] = get_mitigations(
            technique.get("technique_id", "")
        )
        mitre_with_mitigations.append(technique_copy)
    mitre_mapping = mitre_with_mitigations

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

    # Day 12: Explainability — risk score breakdown (sums to risk_score)
    risk_breakdown = []
    total_risk = float(risk_score) if risk_score else 0

    malicious_val = 0
    total_val = 1
    try:
        malicious_val = int(
            threat_intel.get("malicious_engines", 0)
        )
        total_val = int(
            threat_intel.get("total_engines", 1)
        ) or 1
    except:
        pass

    has_mitre = (
        mitre_mapping and
        isinstance(mitre_mapping, list) and
        len(mitre_mapping) > 0
    )

    if total_risk > 0:
        if has_mitre:
            vt_contrib = round(total_risk * 0.80)
            mitre_contrib = total_risk - vt_contrib
            risk_breakdown = [
                {
                    "source": "VirusTotal",
                    "contribution": vt_contrib,
                    "reason": f"{malicious_val} of {total_val} engines flagged",
                    "weight": "80%"
                },
                {
                    "source": "MITRE ATT&CK",
                    "contribution": mitre_contrib,
                    "reason": f"Top: {mitre_mapping[0].get('technique_id','')} ({round(mitre_mapping[0].get('score',0),2)})",
                    "weight": "20%"
                }
            ]
        else:
            risk_breakdown = [
                {
                    "source": "VirusTotal",
                    "contribution": int(total_risk),
                    "reason": f"{malicious_val} of {total_val} engines flagged",
                    "weight": "100%"
                }
            ]
    elif total_risk == 0 and has_mitre:
        risk_breakdown = [
            {
                "source": "VirusTotal",
                "contribution": 0,
                "reason": f"0 of {total_val} engines flagged — URL appears clean",
                "weight": "100%"
            }
        ]

    # Day 14: investigation timeline (incremental 1s steps)
    _t0 = datetime.datetime.utcnow()
    _sec = lambda n: (_t0 + datetime.timedelta(seconds=n)).isoformat()
    timeline = [
        {
            "time": _sec(0),
            "step": "Investigation Started",
            "detail": f"URL submitted for analysis",
            "status": "complete"
        },
        {
            "time": _sec(1),
            "step": "VirusTotal Scan",
            "detail": f"Scanned by {threat_intel.get('total_engines', 'N/A')} engines — {threat_intel.get('malicious_engines', 0)} flagged malicious",
            "status": "complete"
        },
        {
            "time": _sec(2),
            "step": "MITRE ATT&CK Mapping",
            "detail": f"Top technique: {mitre_mapping[0].get('technique_id', 'N/A') if mitre_mapping else 'None found'}",
            "status": "complete"
        },
        {
            "time": _sec(3),
            "step": "AI Explanation Generated",
            "detail": "RAG-grounded explanation via Groq LLaMA 3.1",
            "status": "complete"
        },
        {
            "time": _sec(4),
            "step": "Awaiting Analyst Decision",
            "detail": "Investigation complete — analyst review required",
            "status": "pending"
        }
    ]

    return {
        "investigation_id": inv_id,
        "timestamp": timestamp,
        "input_type": "url",
        "input_value": url,
        "timeline": timeline,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "severity": _severity_from_risk(risk_score),
        "recommended_action": recommended_action,
        "threat_intel": threat_intel,
        "mitre_mapping": mitre_mapping,
        "explainability": explainability,
        "ai_explanation": ai_explanation,
        "risk_breakdown": risk_breakdown,
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

    # Day 13: attach recommended mitigations to each technique
    mitre_with_mitigations = []
    for technique in (mitre_mapping or []):
        technique_copy = dict(technique)
        technique_copy["mitigations"] = get_mitigations(
            technique.get("technique_id", "")
        )
        mitre_with_mitigations.append(technique_copy)
    mitre_mapping = mitre_with_mitigations

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

    # Day 12: Explainability — risk score breakdown (sums to risk_score)
    risk_breakdown = []
    total_risk = float(risk_score) if risk_score else 0

    abuse_score_val = 0
    try:
        abuse_score_val = float(
            threat_intel.get("abuse_score", 0)
        )
    except:
        abuse_score_val = 0

    isp_val = str(
        threat_intel.get("isp", "")
    ).lower()
    tor_keywords = ["tor", "exit", "relay", "anonymous"]
    is_tor = any(kw in isp_val for kw in tor_keywords)

    has_mitre = (
        mitre_mapping and
        isinstance(mitre_mapping, list) and
        len(mitre_mapping) > 0
    )

    if total_risk > 0:
        if is_tor and has_mitre:
            abuse_contrib = round(total_risk * 0.60)
            tor_contrib = round(total_risk * 0.25)
            mitre_contrib = total_risk - abuse_contrib - tor_contrib
            risk_breakdown = [
                {
                    "source": "AbuseIPDB",
                    "contribution": abuse_contrib,
                    "reason": f"Abuse confidence: {abuse_score_val}/100",
                    "weight": "60%"
                },
                {
                    "source": "Tor Detection",
                    "contribution": tor_contrib,
                    "reason": f"ISP: {threat_intel.get('isp','')}",
                    "weight": "25%"
                },
                {
                    "source": "MITRE ATT&CK",
                    "contribution": mitre_contrib,
                    "reason": f"Top: {mitre_mapping[0].get('technique_id','')} ({round(mitre_mapping[0].get('score',0),2)})",
                    "weight": "15%"
                }
            ]
        elif has_mitre:
            abuse_contrib = round(total_risk * 0.80)
            mitre_contrib = total_risk - abuse_contrib
            risk_breakdown = [
                {
                    "source": "AbuseIPDB",
                    "contribution": abuse_contrib,
                    "reason": f"Abuse confidence: {abuse_score_val}/100",
                    "weight": "80%"
                },
                {
                    "source": "MITRE ATT&CK",
                    "contribution": mitre_contrib,
                    "reason": f"Top: {mitre_mapping[0].get('technique_id','')} ({round(mitre_mapping[0].get('score',0),2)})",
                    "weight": "20%"
                }
            ]
        else:
            risk_breakdown = [
                {
                    "source": "AbuseIPDB",
                    "contribution": int(total_risk),
                    "reason": f"Abuse confidence: {abuse_score_val}/100",
                    "weight": "100%"
                }
            ]

    # Day 14: investigation timeline (incremental 1s steps)
    _t0 = datetime.datetime.utcnow()
    _sec = lambda n: (_t0 + datetime.timedelta(seconds=n)).isoformat()
    timeline = [
        {
            "time": _sec(0),
            "step": "Investigation Started",
            "detail": f"IP address {ip} submitted for analysis",
            "status": "complete"
        },
        {
            "time": _sec(1),
            "step": "Threat Intelligence",
            "detail": f"AbuseIPDB returned abuse score: {threat_intel.get('abuse_score', 'N/A')}",
            "status": "complete"
        },
        {
            "time": _sec(2),
            "step": "MITRE ATT&CK Mapping",
            "detail": f"Top technique: {mitre_mapping[0].get('technique_id', 'N/A') if mitre_mapping else 'None found'}",
            "status": "complete"
        },
        {
            "time": _sec(3),
            "step": "AI Explanation Generated",
            "detail": "RAG-grounded explanation via Groq LLaMA 3.1",
            "status": "complete"
        },
        {
            "time": _sec(4),
            "step": "Awaiting Analyst Decision",
            "detail": "Investigation complete — analyst review required",
            "status": "pending"
        }
    ]

    return {
        "investigation_id": inv_id,
        "timestamp": timestamp,
        "input_type": "ip",
        "input_value": ip,
        "timeline": timeline,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "severity": _severity_from_risk(risk_score),
        "recommended_action": recommended_action,
        "threat_intel": threat_intel,
        "mitre_mapping": mitre_mapping,
        "explainability": explainability,
        "ai_explanation": ai_explanation,
        "risk_breakdown": risk_breakdown,
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

    # Day 13: attach recommended mitigations to each technique
    mitre_with_mitigations = []
    for technique in (mitre_mapping or []):
        technique_copy = dict(technique)
        technique_copy["mitigations"] = get_mitigations(
            technique.get("technique_id", "")
        )
        mitre_with_mitigations.append(technique_copy)
    mitre_mapping = mitre_with_mitigations

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

    # Day 12: Explainability — risk score breakdown (sums to risk_score)
    # NOTE: threat flags live under detection["summary"] (real output shape).
    risk_breakdown = []
    total_risk = float(risk_score) if risk_score else 0

    summary = {}
    if isinstance(detection, dict):
        summary = detection.get("summary", {})

    brute_force = summary.get("brute_force_detected", 0)
    impossible_travel = summary.get("impossible_travel_detected", 0)
    credential_stuffing = summary.get("credential_stuffing_detected", 0)

    detected_count = sum([
        1 if brute_force else 0,
        1 if impossible_travel else 0,
        1 if credential_stuffing else 0
    ])

    # Split the total risk equally across every detected threat type
    if total_risk > 0 and detected_count > 0:
        per_detection = total_risk / detected_count
        if brute_force:
            risk_breakdown.append({
                "source": "Brute Force",
                "contribution": round(per_detection),
                "reason": "Multiple failed logins from same IP",
                "weight": f"{round(100/detected_count)}%"
            })
        if impossible_travel:
            risk_breakdown.append({
                "source": "Impossible Travel",
                "contribution": round(per_detection),
                "reason": "Geographically impossible login sequence",
                "weight": f"{round(100/detected_count)}%"
            })
        if credential_stuffing:
            risk_breakdown.append({
                "source": "Credential Stuffing",
                "contribution": round(per_detection),
                "reason": "Many usernames from single IP",
                "weight": f"{round(100/detected_count)}%"
            })

    # Day 14: investigation timeline (incremental 1s steps)
    _t0 = datetime.datetime.utcnow()
    _sec = lambda n: (_t0 + datetime.timedelta(seconds=n)).isoformat()
    timeline = [
        {
            "time": _sec(0),
            "step": "Investigation Started",
            "detail": f"Login events submitted for analysis",
            "status": "complete"
        },
        {
            "time": _sec(1),
            "step": "Anomaly Detection",
            "detail": f"Analyzed {len(events) if events else 0} login events for suspicious patterns",
            "status": "complete"
        },
        {
            "time": _sec(2),
            "step": "MITRE ATT&CK Mapping",
            "detail": f"Top technique: {mitre_mapping[0].get('technique_id', 'N/A') if mitre_mapping else 'None found'}",
            "status": "complete"
        },
        {
            "time": _sec(3),
            "step": "AI Explanation Generated",
            "detail": "RAG-grounded explanation via Groq LLaMA 3.1",
            "status": "complete"
        },
        {
            "time": _sec(4),
            "step": "Awaiting Analyst Decision",
            "detail": "Investigation complete — analyst review required",
            "status": "pending"
        }
    ]

    return {
        "investigation_id": inv_id,
        "timestamp": timestamp,
        "input_type": "login",
        "input_value": "login_events",
        "timeline": timeline,
        "verdict": overall_verdict,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "severity": _severity_from_risk(risk_score),
        "recommended_action": recommended_action,
        "threat_intel": detection,
        "mitre_mapping": mitre_mapping,
        "explainability": explainability,
        "ai_explanation": ai_explanation,
        "risk_breakdown": risk_breakdown,
        "investigation_complete": True
    }


# ─────────────────────────────────────────
# Day 8: Persist an investigation to MongoDB
# ─────────────────────────────────────────
async def save_investigation(result: dict):
    try:
        db = get_db()
        record = {
            "investigation_id": result.get("investigation_id"),
            "timestamp": result.get("timestamp"),
            "input_type": result.get("input_type"),
            "input_value": result.get("input_value"),
            "verdict": result.get("verdict"),
            "risk_score": result.get("risk_score"),
            "severity": result.get("severity"),
            "recommended_action": result.get("recommended_action"),
            "full_report": result
        }
        await db.insert_one(record)
        print(f"[SAVED] MongoDB: {result.get('investigation_id')}")
    except Exception as e:
        print(f"[ERROR] MongoDB save failed: {e}")


# ─────────────────────────────────────────
# Day 11: Human-in-the-loop analyst decision
# ─────────────────────────────────────────
async def save_analyst_decision(
    investigation_id: str,
    decision: str,
    analyst_note: str = ""
):
    try:
        db = get_db()
        decision_record = {
            "decision": decision,
            "analyst_note": analyst_note,
            "decided_at": datetime.datetime.utcnow().isoformat(),
            "decided_by": "analyst"
        }
        result = await db.update_one(
            {"investigation_id": investigation_id},
            {"$set": {"analyst_decision": decision_record}}
        )
        if result.modified_count == 1:
            print(f"[DECISION] {investigation_id}: {decision}")
            return True
        else:
            print(f"[ERROR] Investigation not found: {investigation_id}")
            return False
    except Exception as e:
        print(f"[ERROR] Decision save failed: {e}")
        return False
