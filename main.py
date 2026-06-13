from fastapi import FastAPI, HTTPException
import requests
import os
from dotenv import load_dotenv
import time

load_dotenv()

app = FastAPI()

# Check at startup that API key exists
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not API_KEY or API_KEY.strip() == "":
    raise RuntimeError(
        "VIRUSTOTAL_API_KEY is missing from .env file"
    )

@app.get("/")
def home():
    return {"message": "SentinelIQ is running!"}

@app.get("/analyze-url")
def analyze_url(url: str):

    # Input validation
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

    headers = {"x-apikey": API_KEY.strip()}

    try:
        # Step 1: Submit URL to VirusTotal for analysis
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

        # Step 2: Wait for VirusTotal engines to complete analysis
        time.sleep(15)

        # Step 3: Fetch analysis results using the ID
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )

        if result.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail="Failed to fetch analysis results"
            )

        data = result.json()

        # Step 4: Extract engine statistics
        stats = data["data"]["attributes"]["stats"]
        malicious = stats["malicious"]
        harmless = stats["harmless"]
        suspicious = stats["suspicious"]
        undetected = stats["undetected"]

        # Step 5: Calculate risk score (0-100)
        total_engines = (
            malicious + harmless + suspicious + undetected
        )
        risk_score = (
            round((malicious / total_engines) * 100)
            if total_engines > 0 else 0
        )

        # Step 6: Determine verdict with 3 tiers
        if malicious > 3:
            verdict = "MALICIOUS"
        elif malicious >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "url": url,
            "malicious_engines": malicious,
            "harmless_engines": harmless,
            "suspicious_engines": suspicious,
            "total_engines": total_engines,
            "risk_score": risk_score,
            "verdict": verdict
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )