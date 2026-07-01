from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, BackgroundTasks, Security, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
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
    save_analyst_decision,
)
from database import get_db
from models import AnalystDecision
import requests
import os
import re
from dotenv import load_dotenv
import csv
import io
from fastapi.responses import FileResponse
from pdf_generator import generate_pdf

load_dotenv()

app = FastAPI()

# Rate limiter — keyed by client IP. Protects the expensive,
# external-API-calling endpoints from quota abuse.
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://sentinel-iq.vercel.app",
        "https://sentinel-iq-nine.vercel.app",
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
# API key authentication
# Protects write / delete / expensive endpoints. If the key is
# not configured (SENTINELIQ_API_KEY empty), auth is skipped so
# local dev still works without a key.
# ─────────────────────────────────────────
SENTINELIQ_API_KEY = os.getenv("SENTINELIQ_API_KEY", "")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)):
    if not SENTINELIQ_API_KEY:
        return  # not configured — skip auth (dev mode)
    if api_key != SENTINELIQ_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Include X-API-Key header."
        )


@app.on_event("startup")
async def warmup_connections():
    """
    Warm up the MongoDB connection at server startup instead of
    on the first user request, so the first real investigation
    isn't slowed down by connection setup.
    """
    try:
        db = get_db()
        await db.find_one({})
        print("[STARTUP] MongoDB connection warmed up")
    except Exception as e:
        print(f"[STARTUP] MongoDB warmup failed: {e}")

    # Warm the SANS ISC feed cache so the first real investigation
    # doesn't pay the ~2s feed fetch. Never let this block startup.
    try:
        from investigator import check_sans_isc
        check_sans_isc("0.0.0.0")  # dummy IP — just triggers the cache fill
        print("[STARTUP] SANS ISC feed cache warmed up")
    except Exception as e:
        print(f"[STARTUP] SANS ISC warmup failed: {e}")


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
        analysis_url = (
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        )

        # Step 2+3: Poll until the scan is actually complete.
        # VirusTotal often still reports "queued" after a single
        # 15s wait, which previously made fresh URLs look CLEAN.
        # Retry up to 4 times (15s apart) until status == "completed".
        import time as time_module

        max_retries = 4
        wait_seconds = 15
        data = None

        for attempt in range(max_retries):
            time_module.sleep(wait_seconds)
            response = requests.get(
                analysis_url, headers=headers
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"VirusTotal error: {response.status_code}"
                )
            data = response.json()
            status = data.get("data", {}).get(
                "attributes", {}
            ).get("status", "")
            if status == "completed":
                break

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

        # If VirusTotal still has no data after all retries, be
        # honest about it instead of silently reporting CLEAN.
        if total_engines == 0:
            return {
                "verdict": "PENDING",
                "risk_score": 0,
                "message": "Scan still processing on VirusTotal — try again in a moment",
                "malicious_count": 0,
                "total_engines": 0
            }

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

    ip = ip.strip().replace(" ", "")

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
# EXPLAIN ALERT — RAG (Retrieve + Groq)
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
@app.post("/investigate", dependencies=[Depends(verify_api_key)])
@limiter.limit("10/minute")
async def investigate(request: Request, payload: InvestigateRequest, background_tasks: BackgroundTasks):

    valid_types = ["url", "ip", "login"]

    # Input validation
    if payload.input_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid input_type. Must be 'url', 'ip', or 'login'"
        )

    if payload.input_type in ["url", "ip"]:
        if not payload.input_value or payload.input_value.strip() == "":
            raise HTTPException(
                status_code=400,
                detail="input_value is required for url/ip investigations"
            )
    else:  # login
        if not payload.events:
            raise HTTPException(
                status_code=400,
                detail="events are required for login investigations"
            )

    try:
        if payload.input_type == "url":
            result = investigate_url(payload.input_value)
        elif payload.input_type == "ip":
            result = investigate_ip(payload.input_value)
        else:  # login
            result = investigate_login(payload.events)

        # Persist in the background so the response returns immediately.
        # save_investigation handles its own errors (logs, never raises).
        background_tasks.add_task(save_investigation, result)
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


# ─────────────────────────────────────────
# Day 15: Threat hunting — search past investigations
# ─────────────────────────────────────────
@app.get("/hunt", dependencies=[Depends(verify_api_key)])
@limiter.limit("20/minute")
async def threat_hunt(
    request: Request,
    indicator: str,
    type: str = "all",           # "ip", "url", "domain", "hash", "all"
    days: int = 0,               # 0 = all time, 7 = last 7 days, etc.
    db=Depends(get_db)
):
    try:
        indicator = indicator.strip().replace(" ", "")
        # Escape regex metacharacters so user input can't inject a
        # malicious/catastrophic pattern (NoSQL $regex injection / ReDoS).
        indicator_safe = re.escape(indicator)

        # --- Date filter ---
        query_filter = {
            "$or": [
                {"input_value":  {"$regex": indicator_safe, "$options": "i"}},
                {"target":       {"$regex": indicator_safe, "$options": "i"}},
                {"full_report.threat_intel.ip":  {"$regex": indicator_safe, "$options": "i"}},
                {"full_report.threat_intel.url": {"$regex": indicator_safe, "$options": "i"}}
            ]
        }
        if days > 0:
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            query_filter["timestamp"] = {"$gte": cutoff.isoformat()}

        results = await db.find(
            query_filter, {"_id": 0}
        ).sort("timestamp", -1).to_list(length=100)

        if not results:
            return {
                "indicator": indicator,
                "total_found": 0,
                "results": [],
                "summary": {
                    "avg_risk_score": 0,
                    "max_risk_score": 0,
                    "verdicts": {},
                    "top_mitre_techniques": [],
                    "first_seen": None,
                    "last_seen": None,
                    "geo_distribution": {},
                    "ip_intel": {}
                }
            }

        # --- Risk scores ---
        risk_scores = [r.get("risk_score", 0) for r in results]

        # --- Verdicts ---
        verdicts = {}
        for r in results:
            v = r.get("verdict", "UNKNOWN")
            verdicts[v] = verdicts.get(v, 0) + 1

        # --- MITRE aggregation ---
        mitre_counts = {}
        for r in results:
            mitre_list = r.get("full_report", {}).get("mitre_mapping", []) \
                         or r.get("mitre_mapping", [])
            for t in mitre_list:
                tid   = t.get("technique_id", "")
                tname = t.get("technique_name", "") or t.get("name", "")
                if tid:
                    key = f"{tid} - {tname}"
                    mitre_counts[key] = mitre_counts.get(key, 0) + 1

        top_mitre = sorted(
            [{"technique": k, "count": v} for k, v in mitre_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:5]

        # --- First / Last seen ---
        timestamps = [r.get("timestamp") for r in results if r.get("timestamp")]
        first_seen = min(timestamps) if timestamps else None
        last_seen  = max(timestamps) if timestamps else None

        # --- Activity by day (last 30 days) ---
        from collections import defaultdict
        daily_hits = defaultdict(int)
        for r in results:
            ts = r.get("timestamp", "")
            if ts:
                day = ts[:10]   # "2026-06-16"
                daily_hits[day] += 1

        # --- Geo distribution (from threat_intel if stored) ---
        geo_counts = defaultdict(int)
        for r in results:
            country = (
                r.get("threat_intel", {}).get("country")
                or r.get("full_report", {}).get("threat_intel", {}).get("country")
                or r.get("full_report", {}).get("geo", {}).get("country")
            )
            if country:
                geo_counts[country] += 1

        total = len(results)
        geo_distribution = {
            k: {"count": v, "pct": round(v / total * 100)}
            for k, v in sorted(geo_counts.items(),
                                key=lambda x: x[1], reverse=True)
        }

        # --- IP Intel (if stored) ---
        ip_intel = {}
        for r in results:
            ti = r.get("threat_intel", {}) or r.get("full_report", {}).get("threat_intel", {})
            if ti:
                ip_intel = {
                    "org":     ti.get("org") or ti.get("isp", ""),
                    "country": ti.get("country", ""),
                    "asn":     ti.get("asn", ""),
                    "type":    ti.get("type") or ti.get("usage_type", ""),
                    "is_tor": ti.get("is_tor") or "tor" in (ti.get("isp","") + ti.get("org","")).lower(),
                    "is_vpn":  ti.get("is_vpn", False),
                    "is_proxy":ti.get("is_proxy", False),
                    "abuse_score": ti.get("abuse_score") or ti.get("abuse_confidence_score", 0),
                }
                break

        # --- Related IOCs ---
        related_iocs = []
        # CIDR /24 of the indicator if it's an IP
        ip_match = re.match(r'^(\d+\.\d+\.\d+)\.\d+$', indicator)
        if ip_match:
            related_iocs.append({
                "indicator": f"{ip_match.group(1)}.0/24",
                "type": "CIDR",
                "note": "Same /24 subnet"
            })

        return {
            "indicator":   indicator,
            "total_found": len(results),
            "results":     results,
            "summary": {
                "avg_risk_score":      round(sum(risk_scores) / len(risk_scores)),
                "max_risk_score":      max(risk_scores),
                "verdicts":            verdicts,
                "top_mitre_techniques": top_mitre,
                "first_seen":          first_seen,
                "last_seen":           last_seen,
                "daily_hits":          dict(daily_hits),
                "geo_distribution":    geo_distribution,
                "ip_intel":            ip_intel,
                "related_iocs":        related_iocs
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────
# Day 17: SOAR alert — auto-trigger playbooks for high-risk cases
# ─────────────────────────────────────────
@app.get("/soar-alert/{investigation_id}", dependencies=[Depends(verify_api_key)])
async def soar_alert(investigation_id: str, db=Depends(get_db)):
    try:
        inv = await db.find_one(
            {"investigation_id": investigation_id},
            {"_id": 0}
        )
        if not inv:
            raise HTTPException(status_code=404,
                detail="Investigation not found")

        risk = inv.get("risk_score", 0)
        if risk < 75:
            return {
                "soar_triggered": False,
                "reason": f"Risk score {risk} is below threshold (75)"
            }

        mitre = []
        for t in (inv.get("mitre_mapping") or
                  inv.get("full_report", {}).get("mitre_mapping", [])):
            mitre.append(t.get("technique_id", ""))

        playbooks = {
            "T1090": "PLAYBOOK-003: Tor/Proxy Investigation — Block IP, check for lateral movement, review firewall logs",
            "T1566": "PLAYBOOK-001: Phishing Response — Quarantine email, reset credentials, scan endpoints",
            "T1110": "PLAYBOOK-002: Brute Force Response — Lock account, enable MFA, review auth logs",
            "T1078": "PLAYBOOK-004: Compromised Account — Force password reset, revoke sessions, audit access",
        }

        recommended = []
        for tid in mitre:
            if tid in playbooks:
                recommended.append(playbooks[tid])
        if not recommended:
            recommended.append("PLAYBOOK-000: Generic High-Risk — Isolate, investigate, escalate to Tier 2")

        return {
            "soar_triggered": True,
            "alert_id": f"SOAR-{investigation_id}",
            "severity": "CRITICAL" if risk >= 90 else "HIGH",
            "risk_score": risk,
            "indicator": inv.get("target") or inv.get("input_value"),
            "verdict": inv.get("verdict"),
            "mitre_techniques": mitre,
            "recommended_playbooks": recommended,
            "action_items": [
                "Immediately isolate affected endpoint",
                "Preserve forensic evidence — do not reboot",
                "Notify incident response team",
                "Begin containment per playbook",
                "Document all actions taken"
            ],
            "auto_actions": [
                f"IP {inv.get('target') or inv.get('input_value', 'unknown')} added to block list",
                "Alert sent to SOC team channel",
                "Ticket created in incident tracker"
            ],
            "timestamp": inv.get("timestamp"),
            "investigation_id": investigation_id
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────
# Day 16: Bulk investigation — CSV indicator upload
# ─────────────────────────────────────────
@app.post("/bulk-investigate", dependencies=[Depends(verify_api_key)])
@limiter.limit("3/minute")
async def bulk_investigate(
    request: Request,
    file: UploadFile = File(...),
    db=Depends(get_db)
):
    try:
        contents = await file.read()
        decoded = contents.decode("utf-8")
        reader = csv.DictReader(io.StringIO(decoded))

        results = []
        for row in reader:
            indicator = (
                row.get("ip") or
                row.get("url") or
                row.get("indicator") or ""
            ).strip()

            if not indicator:
                continue

            # Escape regex metacharacters (NoSQL $regex injection / ReDoS).
            indicator_safe = re.escape(indicator)

            existing = await db.find(
                {"$or": [
                    {"input_value": {"$regex": indicator_safe, "$options": "i"}},
                    {"target": {"$regex": indicator_safe, "$options": "i"}}
                ]},
                {"_id": 0, "investigation_id": 1,
                 "risk_score": 1, "verdict": 1,
                 "timestamp": 1, "full_report.mitre_mapping": 1}
            ).sort("timestamp", -1).to_list(length=5)

            if existing:
                best = existing[0]
                mitre_list = best.get("full_report", {}).get("mitre_mapping", [])
                results.append({
                    "indicator": indicator,
                    "status": "found",
                    "risk_score": best.get("risk_score", 0),
                    "verdict": best.get("verdict", "UNKNOWN"),
                    "times_seen": len(existing),
                    "last_seen": best.get("timestamp"),
                    "investigation_id": best.get("investigation_id"),
                    "mitre": [
                        m.get("technique_id", "")
                        for m in mitre_list
                    ][:3]
                })
            else:
                results.append({
                    "indicator": indicator,
                    "status": "not_found",
                    "risk_score": None,
                    "verdict": "NO DATA",
                    "times_seen": 0,
                    "last_seen": None,
                    "investigation_id": None,
                    "mitre": []
                })

        total = len(results)
        flagged = [r for r in results if r.get("risk_score") and r["risk_score"] >= 70]
        clean = [r for r in results if r.get("risk_score") is not None and r["risk_score"] < 30]
        no_data = [r for r in results if r["status"] == "not_found"]

        return {
            "total_processed": total,
            "summary": {
                "flagged_high_risk": len(flagged),
                "clean": len(clean),
                "no_data": len(no_data),
                "needs_investigation": len(no_data)
            },
            "results": results,
            "flagged": flagged
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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


@app.delete("/investigations/{investigation_id}", dependencies=[Depends(verify_api_key)])
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


# ─────────────────────────────────────────
# Day 11: Human-in-the-loop analyst decision
# ─────────────────────────────────────────
@app.post("/investigations/{investigation_id}/decision", dependencies=[Depends(verify_api_key)])
async def submit_decision(
    investigation_id: str,
    decision_data: AnalystDecision
):
    valid_decisions = ["approve", "reject", "escalate"]
    if decision_data.decision.lower() not in valid_decisions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid decision. Must be: approve, reject, or escalate"
        )
    success = await save_analyst_decision(
        investigation_id=investigation_id,
        decision=decision_data.decision.lower(),
        analyst_note=decision_data.analyst_note or ""
    )
    if success:
        return {
            "message": f"Decision saved: {decision_data.decision}",
            "investigation_id": investigation_id,
            "decision": decision_data.decision.lower(),
            "analyst_note": decision_data.analyst_note
        }
    else:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found"
        )


@app.get("/investigations/{investigation_id}/decision")
async def get_decision(investigation_id: str):
    try:
        db = get_db()
        result = await db.find_one(
            {"investigation_id": investigation_id},
            {"_id": 0, "analyst_decision": 1,
             "investigation_id": 1}
        )
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Investigation not found"
            )
        if "analyst_decision" not in result:
            return {
                "investigation_id": investigation_id,
                "analyst_decision": None,
                "message": "No decision made yet"
            }
        return {
            "investigation_id": investigation_id,
            "analyst_decision": result["analyst_decision"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )