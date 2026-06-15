# SentinelIQ — AI-Assisted SOC Triage Engine

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?style=flat&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)
![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=flat&logo=mongodb&logoColor=white)
![ChromaDB](https://img.shields.io/badge/ChromaDB-1.5.9-7B2FBE?style=flat)
![Groq](https://img.shields.io/badge/Groq-LLaMA_3.1-F55036?style=flat)
![Status](https://img.shields.io/badge/Status-Live-brightgreen?style=flat)

> **A Security Operations Center receives ~2,992 alerts a day. 63% are never investigated. SentinelIQ is my attempt to fix the part that actually breaks — not detection, but triage.**

SentinelIQ is a full-stack, AI-assisted triage engine. Hand it a suspicious **URL, IP address, or login event**, and it does what a junior analyst would do in their first 30 minutes — only in seconds:

1. Runs it through **real threat-intelligence APIs** (the same ones SOCs use).
2. Maps the behaviour to the **MITRE ATT&CK** framework using semantic vector search.
3. Generates a **grounded AI explanation** with RAG — no invented threat names.
4. Hands the analyst a clean, structured brief they can **approve, reject, or escalate**.

In plain terms: it reads the noise, does the boring first-pass investigation, and gives a human a decision-ready summary — **with its reasoning shown, every time.**

No black-box verdicts. No hallucinated technique names. Every output is **explainable, traceable, and documented.**

---

## Live Demo

| | URL |
|---|---|
| **Frontend** | https://sentinel-iq-nine.vercel.app |
| **Backend API** | https://sentineliq-d0ot.onrender.com |
| **API Docs** | https://sentineliq-d0ot.onrender.com/docs |

> Open the frontend. Type `185.220.101.45`. Hit **Investigate**. Watch the whole pipeline run.

---

## The Problem

Every major cybersecurity report from 2024–2026 points to the same failure point. It isn't that threats go undetected — the tools and the data exist. It's that the **investigation layer** collapses under volume. Analysts simply can't keep up.

| Metric | Reality |
|--------|---------|
| Alerts per day (avg SOC) | 2,992 |
| Alerts left uninvestigated | 63% |
| False-positive rate | 46% |
| Manual investigation time | 30–70 min per alert |
| Average breach cost | $4.44M — IBM, 2025 |
| Analyst burnout | 85% report alert fatigue |

SentinelIQ automates the **first pass** — not to replace the analyst, but to turn a 30-minute manual investigation into a few-second, explainable brief. The human still makes the call; they just stop drowning before they get to it.

---

## How It Works

A request flows top to bottom through five layers — each one adding context, not just a score:

```
┌─ Layer 1 — INPUT ────────────────────────────────────────────┐
│  React frontend accepts a URL, IP, or login-event batch       │
└───────────────────────────────────────────────────────────────┘
                            ↓
┌─ Layer 2 — THREAT INTELLIGENCE ──────────────────────────────┐
│  VirusTotal  → 92 antivirus engines                           │
│  AbuseIPDB   → IP reputation & abuse history                  │
└───────────────────────────────────────────────────────────────┘
                            ↓
┌─ Layer 3 — DETECTION ENGINE ─────────────────────────────────┐
│  Brute Force         → MITRE T1110                            │
│  Impossible Travel   → MITRE T1078                            │
│  Credential Stuffing → MITRE T1110.004                       │
└───────────────────────────────────────────────────────────────┘
                            ↓
┌─ Layer 4 — AI INVESTIGATION (RAG) ───────────────────────────┐
│  ChromaDB        → MITRE ATT&CK vector embeddings            │
│  Groq LLaMA 3.1  → grounded, retrieval-backed explanation    │
│  Explainability  → per-signal risk contribution breakdown    │
└───────────────────────────────────────────────────────────────┘
                            ↓
┌─ Layer 5 — ANALYST DECISION ─────────────────────────────────┐
│  Approve / Reject / Escalate                                 │
│  PDF report → MongoDB → SOC dashboard                        │
└───────────────────────────────────────────────────────────────┘
```

---

## What Makes This Different

Most student cybersecurity projects **detect** or **scan**. SentinelIQ **investigates, explains, and runs a complete decision workflow** — which is the part real SOCs actually struggle with.

| Dimension | Typical Project | SentinelIQ |
|-----------|----------------|------------|
| Output | Binary verdict | Score + MITRE mapping + AI explanation + analyst decision |
| AI | None, or a thin GPT wrapper | RAG grounded in real MITRE ATT&CK data |
| Data source | Static datasets | Live threat-intelligence APIs |
| Analyst workflow | Not modelled | Full approve / reject / escalate loop |
| Framework | None | MITRE ATT&CK-aligned end to end |

### Why RAG instead of prompting an LLM directly?

Ask a language model to name the MITRE technique for an alert and it will confidently invent one that *sounds* right. That's a hallucination — and in security, a confidently wrong answer is more dangerous than no answer.

RAG (Retrieval-Augmented Generation) flips the order: it first **retrieves verified MITRE ATT&CK entries from ChromaDB**, then asks the model to explain *using only that material*. Every technique ID in the output traces back to a real record. The AI explains; it doesn't guess.

### Why a human stays in the loop

Gartner's 2026 guidance warns that fully autonomous AI security decisions are heading toward real legal liability — explainability and human oversight are becoming compliance requirements, not nice-to-haves.

So SentinelIQ **never acts on its own.** It builds the brief; the analyst decides. Every decision is logged with a timestamp, a note, and the outcome — an audit trail you can hand to a compliance officer.

---

## Features

**Investigation Engine**
- URL analysis via VirusTotal — 92 antivirus engines, 0–100 risk score
- IP reputation via AbuseIPDB — confidence score + Tor exit-node detection
- Login anomaly detection — brute force, impossible travel, credential stuffing

**AI Layer**
- ChromaDB vector store of MITRE ATT&CK technique embeddings
- Semantic search — plain-language behaviour → MITRE technique
- Groq LLaMA 3.1 8B — grounded, RAG-powered explanations
- Explainability panel — the risk score broken down by what each signal contributed

**Human-in-the-Loop**
- Approve / Reject / Escalate on every investigation
- Analyst notes logged against each decision
- True-Positive / False-Positive tracking surfaced on the dashboard

**SOC Operations**
- Real-time dashboard — TP/FP counts, verdict distribution, risk trends
- One-click PDF incident report in a professional format
- Full investigation history persisted in MongoDB Atlas

---

## Tech Stack

| Layer | Technology | Why this choice |
|-------|-----------|-----------------|
| Backend | FastAPI (Python) | Async by default, auto-generates OpenAPI docs |
| Frontend | React.js + Tailwind CSS | Component-based, real-time UI updates |
| Vector DB | ChromaDB 1.5.9 | Local, open-source, semantic search |
| AI Model | Groq LLaMA 3.1 8B | Fast, RAG-grounded, structured output |
| Database | MongoDB Atlas | Flexible schema for varied alert types |
| Threat Intel | VirusTotal + AbuseIPDB | The same APIs used in real SOC playbooks |
| PDF | fpdf2 | Lightweight, no external dependencies |
| Deploy | Render + Vercel | CI/CD on every GitHub push |

---

## API Reference

| Method | Endpoint | What it does |
|--------|----------|--------------|
| GET | `/` | Health check |
| GET | `/analyze-url` | VirusTotal URL scan |
| GET | `/analyze-ip` | AbuseIPDB IP reputation |
| POST | `/analyze-login` | Login anomaly detection |
| GET | `/analyze-mitre` | MITRE technique lookup |
| GET | `/search-mitre` | Semantic MITRE search |
| POST | `/explain-alert` | RAG-grounded AI explanation |
| POST | `/investigate` | Full investigation pipeline |
| GET | `/investigations` | List saved investigations |
| GET | `/investigations/{id}` | Get a single investigation |
| POST | `/investigations/{id}/decision` | Submit analyst decision |
| GET | `/investigations/{id}/report` | Download PDF report |

Full interactive docs: https://sentineliq-d0ot.onrender.com/docs

---

## Running Locally

**Requirements:** Python 3.11+, Node.js 20+, a free MongoDB Atlas tier.

```bash
# 1. Clone and set up the backend
git clone https://github.com/JaiVardhanVajpai/SentinelIQ.git
cd SentinelIQ
pip install -r requirements.txt
cp .env.example .env        # then fill in your API keys
python -m uvicorn main:app --reload

# 2. In a second terminal, start the frontend
cd frontend
npm install
npm start
```

- Backend → http://localhost:8000
- Frontend → http://localhost:3000

---

## Questions I Expect in an Interview

**Why RAG instead of a direct LLM call?**
RAG prevents hallucination. Every MITRE technique in the output is retrieved from a verified knowledge base, not generated from the model's memory.

**Why MongoDB instead of SQL?**
Alert data is schema-variable — a URL analysis carries completely different fields than a login-anomaly analysis. MongoDB stores both without migration scripts.

**Why keep a human in the loop?**
Gartner warns that autonomous AI security decisions face legal liability by 2026. In SentinelIQ, the final call always stays with the analyst, and it's fully logged.

**How is this different from just using VirusTotal?**
VirusTotal returns a verdict. SentinelIQ returns an *investigation* — MITRE mapping, an AI explanation, a recommended action, and a documented decision chain.

---

## Author

**Jai Vardhan Vajpai**
Final-Year B.Tech, Computer Science & Engineering
BML Munjal University, Gurugram

GitHub: https://github.com/JaiVardhanVajpai

---

*Final-Year B.Tech Project · BML Munjal University · 2026*
