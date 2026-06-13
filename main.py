from fastapi import FastAPI
import requests
import os
from dotenv import load_dotenv
import time

load_dotenv()

app = FastAPI()

@app.get("/")
def home():
    return {"message": "SentinelIQ is running!"}

@app.get("/analyze-url")
def analyze_url(url: str):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    headers = {"x-apikey": api_key}

    # Step 1: URL bhejo analysis ke liye
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    analysis_id = response.json()["data"]["id"]

    # Step 2: 3 second wait karo — VirusTotal analyze kare
    time.sleep(15)

    # Step 3: Result fetch karo
    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )
    data = result.json()

    # Step 4: Important numbers nikalo
    stats = data["data"]["attributes"]["stats"]
    malicious = stats["malicious"]
    harmless = stats["harmless"]
    suspicious = stats["suspicious"]

    # Step 5: Risk score calculate karo
    total_engines = malicious + harmless + suspicious + stats["undetected"]
    risk_score = round((malicious / total_engines) * 100) if total_engines > 0 else 0

    return {
        "url": url,
        "malicious_engines": malicious,
        "harmless_engines": harmless,
        "suspicious_engines": suspicious,
        "total_engines": total_engines,
        "risk_score": risk_score,
        "verdict": "MALICIOUS" if malicious > 3 else "CLEAN"
    }