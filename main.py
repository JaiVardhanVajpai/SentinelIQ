from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from login_detector import analyze_login_events
from mitre_mapper import (
    get_mitre_technique,
    get_mitre_for_ip,
    get_mitre_for_url,
)
from vector_store import search_mitre
from ai_explainer import (
    explain_url_alert,
    explain_ip_alert,
    explain_login_alert,
)
from investigator import (
    investigate_url,
    investigate_ip,
    investigate_login,
    save_investigation,
)
from database import get_db
import requests
import os
from dotenv import load_dotenv
import time
from fastapi.responses import FileResponse
from pdf_generator import generate_pdf

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Check at startup that API keys exist
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not VT_KEY or VT_KEY.strip() == "":
    raise RuntimeError("VIRUSTOTAL_API_KEY is missing from .env")

if not ABUSE_KEY or ABUSE_KEY.strip() == "":
    raise RuntimeError("ABUSEIPDB_API_KEY is missing from .env")

GROQ_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_KEY or GROQ_KEY.strip() == "":
    raise RuntimeError("GROQ_API_KEY is missing from .env")


# ─────────────────────────────────────────
# REQUEST MODEL — Login Analysis
# ─────────────────────────────────────────
class LoginRequest(BaseModel):
    events: List[dict]


# ─────────────────────────────────────────
# REQUEST MODEL — Explain Alert (RAG)
# ─────────────────────────────────────────
class ExplainRequest(BaseModel):
    alert_type: str
    alert_data: dict


# ─────────────────────────────────────────
# REQUEST MODEL — Unified Investigation
# ─────────────────────────────────────────
class InvestigateRequest(BaseModel):
    input_type: str
    input_value: Optional[str] = None
    events: Optional[List[dict]] = None


# ─────────────────────────────────────────
# HOME
# ─────────────────────────────────────────
@app.get("/")
def home():
    return {
        "message": "SentinelIQ is running!",
        "version": "4.0",
        "endpoints": [
            "/analyze-url",
            "/analyze-ip",
            "/analyze-login",
            "/analyze-mitre",
            "/search-mitre",
            "/explain-alert",
            "/investigate"
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


# ─────────────────────────────────────────
# MITRE SEMANTIC SEARCH (ChromaDB / TF-IDF)
# ─────────────────────────────────────────
@app.get("/search-mitre")
def search_mitre_endpoint(query: str):

    # Input validation
    if not query or query.strip() == "":
        raise HTTPException(
            status_code=400,
            detail="query cannot be empty"
        )

    try:
        results = search_mitre(query)

        return {
            "type": "mitre_search",
            "query": query,
            "results_count": len(results),
            "search_method": (
                results[0]["search_method"] if results else "none"
            ),
            "results": results
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"MITRE search failed: {str(e)}"
        )


# ─────────────────────────────────────────
# EXPLAIN ALERT — RAG (Retrieve + Gemini)
# ─────────────────────────────────────────
@app.post("/explain-alert")
def explain_alert(request: ExplainRequest):

    valid_types = ["url", "ip", "login"]

    # Input validation
    if request.alert_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid alert type. Must be 'url', 'ip', or 'login'"
        )

    if not request.alert_data:
        raise HTTPException(
            status_code=400,
            detail="alert_data cannot be empty"
        )

    try:
        # Route to the correct RAG explainer
        if request.alert_type == "url":
            explanation = explain_url_alert(request.alert_data)
        elif request.alert_type == "ip":
            explanation = explain_ip_alert(request.alert_data)
        else:  # login
            explanation = explain_login_alert(request.alert_data)

        return {
            "type": "alert_explanation",
            "alert_type": request.alert_type,
            "explanation": explanation
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Explanation failed: {str(e)}"
        )


# ─────────────────────────────────────────
# UNIFIED INVESTIGATION — end-to-end report
# ─────────────────────────────────────────
@app.post("/investigate")
async def investigate(request: InvestigateRequest):

    valid_types = ["url", "ip", "login"]

    # Input validation
    if request.input_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid input_type. Must be 'url', 'ip', or 'login'"
        )

    if request.input_type in ["url", "ip"]:
        if not request.input_value or request.input_value.strip() == "":
            raise HTTPException(
                status_code=400,
                detail="input_value is required for url/ip investigations"
            )
    else:  # login
        if not request.events:
            raise HTTPException(
                status_code=400,
                detail="events are required for login investigations"
            )

    try:
        if request.input_type == "url":
            result = investigate_url(request.input_value)
        elif request.input_type == "ip":
            result = investigate_ip(request.input_value)
        else:  # login
            result = investigate_login(request.events)

        await save_investigation(result)
        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {str(e)}"
        )


# ─────────────────────────────────────────
# Day 8: Investigation history (MongoDB)
# ─────────────────────────────────────────
@app.get("/investigations")
async def get_all_investigations():
    try:
        db = get_db()
        cursor = db.find({}, {"_id": 0}).sort("timestamp", -1).limit(20)
        investigations = await cursor.to_list(length=20)
        return {
            "total": len(investigations),
            "investigations": investigations
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/investigations/{investigation_id}")
async def get_one_investigation(investigation_id: str):
    try:
        db = get_db()
        result = await db.find_one(
            {"investigation_id": investigation_id},
            {"_id": 0}
        )
        if result:
            return result
        return {"error": "Investigation not found"}
    except Exception as e:
        return {"error": str(e)}


@app.delete("/investigations/{investigation_id}")
async def delete_investigation(investigation_id: str):
    try:
        db = get_db()
        result = await db.delete_one(
            {"investigation_id": investigation_id}
        )
        if result.deleted_count == 1:
            return {"message": f"Deleted {investigation_id}"}
        return {"error": "Investigation not found"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────
# Day 9: Download investigation report as PDF
# ─────────────────────────────────────────
@app.get("/investigations/{investigation_id}/report")
async def download_report(investigation_id: str):
    try:
        db = get_db()
        investigation = await db.find_one(
            {"investigation_id": investigation_id},
            {"_id": 0}
        )
        if not investigation:
            return {"error": "Investigation not found"}

        full_report = investigation.get("full_report", investigation)
        filepath = generate_pdf(full_report)

        return FileResponse(
            path=filepath,
            media_type="application/pdf",
            filename=f"{investigation_id}.pdf"
        )
    except Exception as e:
        return {"error": f"PDF generation failed: {str(e)}"}