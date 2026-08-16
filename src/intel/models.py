from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatIndicatorCreate(BaseModel):
    indicator_type: str = Field(..., description="IP, DOMAIN, URL, or HASH")
    indicator_value: str = Field(..., description="Indicator value e.g. 10.20.30.40 or malicious-domain.com")
    threat_name: str = Field("Unknown Threat", description="Name of associated threat / actor")
    confidence: float = Field(0.9, ge=0.0, le=1.0, description="Intelligence confidence (0.0 to 1.0)")
    severity: str = Field("HIGH", description="CRITICAL, HIGH, MEDIUM, LOW")
    source: str = Field("LOCAL_SOC", description="Source of intelligence e.g. LOCAL_SOC, STIX_FEED")
    tags: List[str] = Field(default_factory=list, description="Tags associated with indicator")
    expires_at: Optional[str] = None
    description: Optional[str] = None


class ThreatIndicator(ThreatIndicatorCreate):
    indicator_id: str
    first_seen: str
    last_seen: str
    created_at: str


class RuleMatch(BaseModel):
    rule_id: str
    rule_name: str
    matched: bool
    severity: str
    reason: str
    evidence: Dict[str, Any]
    timestamp: str


class MitreMapping(BaseModel):
    attack_type: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    mapping_status: str = "MAPPED"  # MAPPED or UNMAPPED
    confidence: float = 0.85
    rationale: str
    source: str = "MITRE ATT&CK Enterprise v19.0"
