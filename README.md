# SentinelIQ — AI-Assisted SOC Triage Engine

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![ChromaDB](https://img.shields.io/badge/ChromaDB-1.5.9-7B2FBE?style=for-the-badge)
![Groq](https://img.shields.io/badge/Groq-LLaMA_3.1-F55036?style=for-the-badge)
![Deployed](https://img.shields.io/badge/Deployed-Live-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

<br/>

> **SOCs receive 2,992 alerts per day. 63% go uninvestigated. 46% are false positives. I built something about that.**

SentinelIQ is a production-deployed, full-stack AI-assisted triage engine. Feed it a suspicious IP, URL, or login event — it queries real threat intelligence APIs, maps findings to MITRE ATT&CK via semantic vector search, generates a grounded AI explanation using RAG, and delivers a structured verdict for the analyst to approve, reject, or escalate.

**No black-box scores. No hallucinated threat names. Every output is explainable, traceable, and audit-logged.**

---

## Live Demo

> Open the app. Type `185.220.101.45`. Hit Investigate. See a full threat investigation in under 3 minutes.

| | URL |
|---|---|
| **Frontend** | https://sentinel-iq-nine.vercel.app |
| **Backend API** | https://sentineliq-d0ot.onrender.com |
| **Interactive API Docs** | https://sentineliq-d0ot.onrender.com/docs |

---

## The Problem SentinelIQ Solves

Security Operations Centers don't fail at detection — they fail at triage. The tools exist. The data exists. The bottleneck is the 30–70 minutes an analyst spends manually investigating each alert, one at a time.

| Metric | Industry Reality |
|--------|-----------------|
| Average alerts per SOC per day | 2,992 |
| Alerts that go uninvestigated | 63% |
| Alerts that are false positives | 46% |
| Manual investigation time | 30–70 minutes per alert |
| Average cost of a data breach | $4.44M — IBM Security 2025 |
| SOC analysts reporting burnout | 85% |

SentinelIQ compresses that 30–70 minutes to under 3 by automating the first-pass investigation — enrichment, detection, AI reasoning, and a structured brief — while keeping the analyst in control of every final decision.

---

## System Architecture

SentinelIQ is a five-layer pipeline. Each layer has one job.

```
┌────────────────────────────────────────────────────────┐
│                     SENTINELIQ v4.0                      │
│               AI-Assisted SOC Triage Engine             │
└────────────────────────────────────────────────────────┘

   ANALYST
      │   URL / IP / Login Events
      ▼
┌────────────────────────────────────────────────────────┐
│  LAYER 1 — INPUT                                        │
│  React.js frontend · URL, IP, Login Event forms        │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  LAYER 2 — THREAT INTELLIGENCE ENRICHMENT              │
│  VirusTotal → 92 antivirus engines · risk 0-100        │
│  AbuseIPDB  → abuse score · Tor node detection         │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  LAYER 3 — DETECTION ENGINE                            │
│  Brute Force Detection  → MITRE T1110                  │
│  Impossible Travel      → MITRE T1078                  │
│  Credential Stuffing    → MITRE T1110.004             │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  LAYER 4 — AI INVESTIGATION (RAG PIPELINE)            │
│  ChromaDB           → MITRE ATT&CK vector embeddings   │
│  Groq LLaMA 3.1 8B  → grounded explanation            │
│  Explainability Panel → signal contribution scores     │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  LAYER 5 — HUMAN DECISION LAYER                        │
│  Approve / Reject / Escalate                           │
│  Analyst notes · PDF report · MongoDB audit trail      │
│  SOC Dashboard → TP/FP metrics · risk trends           │
└────────────────────────────────────────────────────────┘
```

---

## What Makes SentinelIQ Different

Most cybersecurity student projects detect or scan a single signal source and return a binary result.
SentinelIQ runs a multi-source investigation, explains every decision, and supports a complete analyst workflow — from input to documented outcome.

| Dimension | Typical Student Project | SentinelIQ |
|-----------|------------------------|------------|
| Output | Malicious / Benign | Risk score + MITRE mapping + RAG explanation + analyst decision |
| AI usage | None, or a direct GPT call | RAG pipeline grounded in real MITRE ATT&CK data |
| Data source | Static dataset (KDD99, etc.) | Live threat intel APIs used by real SOC teams |
| Analyst workflow | Not modelled | Full approve / reject / escalate loop with audit trail |
| Industry framework | None | MITRE ATT&CK aligned throughout |
| Risk score | Black box | Explainability panel — each signal's contribution shown |
| Deployment | Runs on my machine | Live on Render + Vercel with CI/CD |

---

## Why RAG Instead of Direct LLM Prompting

Direct LLM prompting hallucinates. Ask a model to explain a threat and it generates confident, well-formatted MITRE technique names that may have nothing to do with the actual alert. In security, a confidently wrong answer is more dangerous than no answer.

SentinelIQ uses **Retrieval-Augmented Generation**:

```
   Alert data
      │
      ▼
   ChromaDB semantic search
      │   retrieves top-3 matching MITRE ATT&CK entries
      ▼
   Groq LLaMA 3.1 8B
      │   generates explanation grounded in retrieved context
      ▼
   Output
      │   every technique ID traceable to a real MITRE entry
      ▼
   Analyst
```

Every technique ID in the output is retrieved from a verified knowledge base — not hallucinated from model memory. The explanation cites the actual MITRE technique, its tactic, and associated threat actors.

---

## Why Human-in-the-Loop

Gartner's 2026 threat report identifies autonomous AI security decisions as an emerging liability. Explainability and human oversight are becoming regulatory requirements — not optional features.

SentinelIQ is designed around this from the ground up:

- The system never takes autonomous action
- Every investigation produces a recommendation — the analyst decides
- Every decision is logged with timestamp, analyst note, and outcome
- The audit trail is queryable — an analyst can retrieve the full decision history for any indicator

This is the same architecture used by enterprise SOC tools like Dropzone AI and Radiant Security.

---

## Key Features

### Investigation Engine
- **URL Analysis** — VirusTotal aggregates 92 antivirus engines; risk score formula: `(malicious / total) * 100`
- **IP Reputation** — AbuseIPDB confidence score, Tor exit node detection, country + ISP enrichment
- **Login Anomaly Detection** — three independent detection rules:
  - Brute force: 5+ failures from same IP in 10 minutes → T1110
  - Impossible travel: Haversine formula detects geographically impossible login sequences → T1078
  - Credential stuffing: 3+ unique usernames from one IP → T1110.004

### AI Layer (RAG-Powered)
- ChromaDB vector store — MITRE ATT&CK technique descriptions embedded as dense vectors
- Semantic search — natural language input mapped to MITRE technique space
- Groq LLaMA 3.1 8B Instant — fast, reliable, structured explanation output
- **Explainability Panel** — risk score decomposed into per-signal contributions that sum to the final score

### Human-in-the-Loop Workflow
- Three-state analyst decision: **Approve** (true positive confirmed) / **Reject** (false positive) / **Escalate** (Tier 2)
- Analyst notes logged against each decision
- True Positive / False Positive counts tracked live on SOC dashboard
- Full audit trail stored in MongoDB Atlas

### SOC Operations
- Real-time dashboard — TP/FP ratio, verdict distribution, risk score trends
- PDF incident report generation — professional format, one click
- Investigation history — full persistence, queryable by ID or indicator
- CI/CD — every GitHub push auto-deploys to Render (backend) and Vercel (frontend)

---

## Tech Stack

| Layer | Technology | Why This Choice |
|-------|-----------|----------------|
| Backend | FastAPI (Python) | Async support; auto-generates OpenAPI docs at `/docs` |
| Frontend | React.js + Tailwind CSS | Component-based; real-time state management |
| Vector DB | ChromaDB 1.5.9 | Local, open-source; semantic similarity search |
| AI Model | Groq LLaMA 3.1 8B Instant | Free tier; fast inference; structured output |
| Database | MongoDB Atlas | Flexible schema — URL and login investigations have different fields |
| Threat Intel | VirusTotal + AbuseIPDB | Same APIs referenced in real enterprise SOC playbooks |
| PDF | fpdf2 | Lightweight; no external service dependency |
| Deploy | Render + Vercel | Free tier; CI/CD on every GitHub push |

---

## API Reference

Full interactive documentation: **https://sentineliq-d0ot.onrender.com/docs**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check + endpoint list |
| `GET` | `/analyze-url?url=` | VirusTotal URL scan — 92 engines |
| `GET` | `/analyze-ip?ip=` | AbuseIPDB IP reputation |
| `POST` | `/analyze-login` | Brute force + impossible travel + credential stuffing |
| `GET` | `/analyze-mitre?attack_type=` | MITRE ATT&CK dictionary lookup |
| `GET` | `/search-mitre?query=` | Semantic vector search → MITRE technique |
| `POST` | `/explain-alert` | RAG-grounded AI explanation via Groq |
| `POST` | `/investigate` | Full unified investigation pipeline |
| `GET` | `/investigations` | List all saved investigations (newest first) |
| `GET` | `/investigations/{id}` | Retrieve single investigation by ID |
| `POST` | `/investigations/{id}/decision` | Submit analyst decision |
| `GET` | `/investigations/{id}/report` | Download PDF incident report |

---

## Running Locally

**Requirements:** Python 3.11+ · Node.js 20+ · MongoDB Atlas free tier

### Backend

```bash
# Clone the repository
git clone https://github.com/JaiVardhanVajpai/SentinelIQ.git
cd SentinelIQ

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Start the backend
python -m uvicorn main:app --reload
# Runs on http://localhost:8000
# API docs at http://localhost:8000/docs
```

### Frontend

```bash
# In a second terminal
cd frontend
npm install
npm start
# Runs on http://localhost:3000
```

### Environment Variables

```bash
VIRUSTOTAL_API_KEY=your_key    # Free at virustotal.com
ABUSEIPDB_API_KEY=your_key     # Free at abuseipdb.com
GROQ_API_KEY=your_key          # Free at console.groq.com
MONGO_URI=mongodb+srv://...    # Free tier at mongodb.com/atlas
```

---

## Author

**Jai Vardhan Vajpai**
Final Year B.Tech — Computer Science Engineering
BML Munjal University, Gurugram · Batch of 2027

---

*Final Year B.Tech Project · BML Munjal University · 2026*
