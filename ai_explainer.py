# ─────────────────────────────────────────
# SentinelIQ — AI Explainer (Day 6)
# RAG pipeline: Retrieve (ChromaDB) -> Augment
# (build prompt) -> Generate (Groq API).
#
# Turns a raw alert result into a grounded,
# analyst-friendly investigation summary.
# ─────────────────────────────────────────

import os
from dotenv import load_dotenv

from groq import Groq

from vector_store import search_mitre

load_dotenv()

# Groq model name. Groq's free tier serves Llama models with no
# quota issues, which is why we use it instead of Gemini.
# NOTE: the older "llama3-8b-8192" has been decommissioned by
# Groq; "llama-3.1-8b-instant" is its current replacement
# (confirmed available via the Groq models API).
GROQ_MODEL = "llama-3.1-8b-instant"

# Create the Groq client once at import time. The client holds
# the API key.
GROQ_KEY = os.getenv("GROQ_API_KEY")
_client = None
if GROQ_KEY and GROQ_KEY.strip() != "":
    _client = Groq(api_key=GROQ_KEY.strip())


def get_ai_explanation(
    alert_type: str,
    alert_data: dict,
    mitre_techniques: list
) -> dict:
    """
    Send the alert + retrieved MITRE context to Groq and
    return a structured, grounded explanation.

    Returns a dict with: explanation, primary_mitre,
    recommended_action, ai_model, grounded.
    """

    # Pick the primary MITRE technique (top retrieval result)
    primary_mitre = "N/A"
    if mitre_techniques:
        primary_mitre = mitre_techniques[0].get("technique_id", "N/A")

    # Render the MITRE context as readable text for the prompt
    mitre_text_lines = []
    for tech in mitre_techniques:
        mitre_text_lines.append(
            f"- {tech.get('technique_id', '?')} "
            f"({tech.get('name', '?')}): "
            f"{tech.get('description', '')}"
        )
    mitre_text = "\n".join(mitre_text_lines) if mitre_text_lines else "None"

    # Build the grounded prompt
    prompt = (
        "You are a SOC analyst assistant.\n"
        "Analyze this security alert and provide a brief "
        "investigation summary.\n\n"
        f"Alert Type: {alert_type}\n"
        f"Alert Data: {alert_data}\n\n"
        "Relevant MITRE ATT&CK Techniques:\n"
        f"{mitre_text}\n\n"
        "Provide:\n"
        "1. What this attack is (1 sentence)\n"
        "2. Why it is suspicious (1-2 sentences)\n"
        "3. Primary MITRE technique (ID + name)\n"
        "4. Recommended analyst action (1 sentence)\n\n"
        "Be concise and factual. Base your response only on "
        "the provided data and MITRE context."
    )

    try:
        response = _client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=500,
            timeout=20
        )
        explanation_text = (
            response.choices[0].message.content or ""
        ).strip()

        return {
            "explanation": explanation_text,
            "primary_mitre": primary_mitre,
            "recommended_action": _extract_recommended_action(
                explanation_text
            ),
            "ai_model": GROQ_MODEL,
            "grounded": True
        }

    except Exception as e:
        # Never crash the API on an AI failure — return a clear,
        # non-grounded fallback so the analyst still gets context.
        return {
            "explanation": (
                f"AI explanation unavailable: {str(e)}. "
                f"Retrieved MITRE context: {mitre_text}"
            ),
            "primary_mitre": primary_mitre,
            "recommended_action": (
                "Review the alert manually using the MITRE "
                "context above."
            ),
            "ai_model": GROQ_MODEL,
            "grounded": False
        }


def _extract_recommended_action(text: str) -> str:
    """
    Best-effort pull of the 'recommended action' line out of
    the Groq response. Falls back to a generic message if it
    cannot be located.
    """
    if not text:
        return "Review the alert and apply MITRE-recommended mitigations."

    for line in text.splitlines():
        low = line.lower()
        if "recommend" in low or "action" in low:
            return line.strip()

    return "Review the alert and apply MITRE-recommended mitigations."


def explain_url_alert(url_result: dict) -> dict:
    """Explain a /analyze-url result via the RAG pipeline."""
    # Retrieve relevant MITRE techniques semantically
    verdict = url_result.get("verdict", "")
    query = f"malicious url phishing {verdict}"
    mitre = search_mitre(query)

    return get_ai_explanation("url", url_result, mitre)


def explain_ip_alert(ip_result: dict) -> dict:
    """Explain a /analyze-ip result via the RAG pipeline."""
    isp = ip_result.get("isp", "")
    verdict = ip_result.get("verdict", "")
    query = f"malicious ip {isp} {verdict} brute force proxy"
    mitre = search_mitre(query)

    return get_ai_explanation("ip", ip_result, mitre)


def explain_login_alert(login_result: dict) -> dict:
    """
    Explain a /analyze-login result. Login analysis already
    carries MITRE technique IDs in its threat data, so we
    enrich those via semantic search to build the context.
    """
    # Build a query from the detected threat types/techniques
    threats = login_result.get("threats", [])
    if threats:
        parts = []
        for threat in threats:
            parts.append(threat.get("mitre_name", ""))
            parts.append(threat.get("type", ""))
        query = " ".join(p for p in parts if p)
    else:
        query = "suspicious login authentication anomaly"

    mitre = search_mitre(query)

    return get_ai_explanation("login", login_result, mitre)
