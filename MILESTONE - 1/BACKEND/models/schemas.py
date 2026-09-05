from pydantic import BaseModel
from typing import Optional


class MitreInfo(BaseModel):
    id: str
    technique: str
    tactic: str


class Event(BaseModel):
    id: str
    timestamp: str
    time: str
    eventType: str
    severity: str
    sourceIP: str
    destIP: str
    department: str
    status: str
    mitre: MitreInfo
    riskScore: int


class Stats(BaseModel):
    total_events: int
    critical_events: int
    high_events: int
    vulnerabilities: int
    active_incidents: int
    avg_risk_score: int


class ThreatCount(BaseModel):
    event_type: str
    count: int


class ThreatIntelItem(BaseModel):
    indicator_id: str
    indicator_type: str
    indicator_value: str
    threat_name: str
    threat_actor: str
    confidence: str
    severity: str


class VulnerabilityItem(BaseModel):
    vulnerability_id: str
    cve_id: str
    vulnerability_name: str
    severity: str
    cvss_score: float
    affected_asset: str
    status: str
    patch_available: Optional[str] = None
