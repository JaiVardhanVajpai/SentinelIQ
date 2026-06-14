from pydantic import BaseModel
from typing import Optional

class InvestigationRecord(BaseModel):
    investigation_id: str
    timestamp: str
    input_type: str
    input_value: str
    verdict: str
    risk_score: float
    severity: str
    recommended_action: str
    full_report: dict

class AnalystDecision(BaseModel):
    decision: str
    analyst_note: Optional[str] = ""
