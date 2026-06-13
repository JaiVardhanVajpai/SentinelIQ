from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from login_detector import analyze_login_events
from mitre_mapper import (
    get_mitre_technique,
    get_mitre_for_ip,
    get_mitre_for_url,
)
import requests
import os
from dotenv import load_dotenv
import time

load_dotenv()

app = FastAPI()

# Check at startup that API keys exist
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not VT_KEY or VT_KEY.strip() == "":
    raise RuntimeError("VIRUSTOTAL_API_KEY is missing from .env")

if not ABUSE_KEY or ABUSE_KEY.strip() == "":
    raise RuntimeError("ABUSEIPDB_API_KEY is missing from .env")


# ─────────────────────────────────────────
# REQUEST MODEL — Login Analysis
# ─────────────────────────────────────────
class LoginRequest(BaseModel):
    events: List[dict]


# ─────────────────────────────────────────
# HOME
# ─────────────────────────────────────────
@app.get("/")
def home():
    return {
        "message": "SentinelIQ is running!",
        "version": "3.0",
        "endpoints": [
            "/analyze-url",
            "/analyze-ip",
            "/analyze-login",
            "/analyze-mitre"
        ]
    }


# ─────────────────────────────────────────
# URL ANALYSIS — VirusTotal
# ─────────────────────────────────────────
@app.get("/analyze-url")
def analyze_url(url: str):

    if not url or url.strip() == "":
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty"
        )
    if not url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    headers = {"x-apikey": VT_KEY.strip()}

    try:
        # Step 1: Submit URL for analysis
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"VirusTotal error: {response.status_code}"
            )

        analysis_id = response.json()["data"]["id"]

        # Step 2: Wait for engines to complete
        time.sleep(15)

        # Step 3: Fetch results
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )

        # Check fetch response status
        if result.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"VirusTotal error: {result.status_code}"
            )

        data = result.json()

        # Step 4: Extract stats
        stats = data["data"]["attributes"]["stats"]
        malicious = stats["malicious"]
        harmless = stats["harmless"]
        suspicious = stats["suspicious"]
        undetected = stats["undetected"]

        # Step 5: Calculate risk score
        total_engines = (
            malicious + harmless + suspicious + undetected
        )
        risk_score = (
            round((malicious / total_engines) * 100)
            if total_engines > 0 else 0
        )

        # Step 6: Explainability breakdown
        explainability = {
            "virustotal": {
                "contribution": round(
                    (malicious / total_engines) * 40
                ) if total_engines > 0 else 0,
                "reason": f"{malicious} of {total_engines} engines flagged"
            }
        }

        # Step 7: 3-tier verdict
        if malicious > 3:
            verdict = "MALICIOUS"
        elif malicious >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        # Step 8: MITRE ATT&CK mapping (flagged URLs map to Phishing)
        mitre_mapping = get_mitre_for_url(malicious)

        return {
            "type": "url_analysis",
            "url": url,
            "malicious_engines": malicious,
            "harmless_engines": harmless,
            "suspicious_engines": suspicious,
            "total_engines": total_engines,
            "risk_score": risk_score,
            "verdict": verdict,
            "explainability": explainability,
            "mitre_mapping": mitre_mapping
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


# ─────────────────────────────────────────
# IP ANALYSIS — AbuseIPDB
# ─────────────────────────────────────────
@app.get("/analyze-ip")
def analyze_ip(ip: str):

    if not ip or ip.strip() == "":
        raise HTTPException(
            status_code=400,
            detail="IP address cannot be empty"
        )

    headers = {
        "Key": ABUSE_KEY.strip(),
        "Accept": "application/json"
    }

    try:
        # Query AbuseIPDB
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
            raise HTTPException(
                status_code=502,
                detail=f"AbuseIPDB error: {response.status_code}"
            )

        data = response.json()["data"]

        abuse_score = data["abuseConfidenceScore"]
        country = data["countryCode"]
        total_reports = data["totalReports"]
        domain = data.get("domain", "unknown")
        usage_type = data.get("usageType", "unknown")
        isp = data.get("isp", "unknown")

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

        # MITRE ATT&CK mapping (Tor/proxy ISP -> T1090, high abuse -> T1110)
        mitre_mapping = get_mitre_for_ip(abuse_score, isp)

        return {
            "type": "ip_analysis",
            "ip": ip,
            "abuse_score": abuse_score,
            "country": country,
            "isp": isp,
            "domain": domain,
            "usage_type": usage_type,
            "total_reports": total_reports,
            "risk_score": risk_score,
            "verdict": verdict,
            "explainability": explainability,
            "mitre_mapping": mitre_mapping
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"IP analysis failed: {str(e)}"
        )


# ─────────────────────────────────────────
# LOGIN ANALYSIS — Anomaly Detection
# ─────────────────────────────────────────
@app.post("/analyze-login")
def analyze_login(request: LoginRequest):

    if not request.events:
        raise HTTPException(
            status_code=400,
            detail="No login events provided"
        )

    try:
        return analyze_login_events(request.events)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Login analysis failed: {str(e)}"
        )


# ─────────────────────────────────────────
# MITRE ATT&CK LOOKUP
# ─────────────────────────────────────────
@app.get("/analyze-mitre")
def analyze_mitre(attack_type: str):

    # Input validation
    if not attack_type or attack_type.strip() == "":
        raise HTTPException(
            status_code=400,
            detail="attack_type cannot be empty"
        )

    try:
        technique = get_mitre_technique(attack_type)

        if technique is None:
            raise HTTPException(
                status_code=404,
                detail=f"MITRE technique not found for '{attack_type}'"
            )

        return {
            "type": "mitre_lookup",
            "query": attack_type,
            "mitre_mapping": technique
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"MITRE lookup failed: {str(e)}"
        )