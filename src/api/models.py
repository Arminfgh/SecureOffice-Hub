"""
Pydantic Models for API Requests and Responses
"""

from pydantic import BaseModel, Field, HttpUrl, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatLevel(str, Enum):
    """Threat severity levels"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """Types of threats"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"
    MALWARE = "malware"


class ThreatBase(BaseModel):
    """Base threat model"""
    threat_type: str
    value: str
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    metadata: Optional[Dict[str, Any]] = None


class ThreatCreate(ThreatBase):
    """Model for creating a threat"""
    pass


class ThreatResponse(ThreatBase):
    """Model for threat response"""
    threat_id: str
    first_seen: datetime
    last_seen: datetime
    
    class Config:
        from_attributes = True


class AnalysisRequest(BaseModel):
    """Base analysis request"""
    context: Optional[Dict[str, Any]] = None


class URLAnalysisRequest(AnalysisRequest):
    """URL analysis request"""
    url: str
    
    @validator('url')
    def validate_url(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('URL cannot be empty')
        return v.strip()


class IPAnalysisRequest(AnalysisRequest):
    """IP analysis request"""
    ip_address: str
    
    @validator('ip_address')
    def validate_ip(cls, v):
        import re
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid IP address format')
        return v


class HashAnalysisRequest(AnalysisRequest):
    """File hash analysis request"""
    file_hash: str
    hash_type: str = "sha256"
    
    @validator('hash_type')
    def validate_hash_type(cls, v):
        if v.lower() not in ['md5', 'sha1', 'sha256']:
            raise ValueError('Hash type must be md5, sha1, or sha256')
        return v.lower()


class AnalysisResponse(BaseModel):
    """Analysis response"""
    threat_level: ThreatLevel
    confidence: float
    indicators: List[str]
    explanation: str
    recommendations: List[str]
    analyzed_at: datetime
    from_cache: bool = False


class SearchRequest(BaseModel):
    """Search request"""
    query: str
    filters: Optional[Dict[str, Any]] = None
    limit: int = Field(50, ge=1, le=500)


class SearchResponse(BaseModel):
    """Search response"""
    query: str
    total_results: int
    results: List[Dict[str, Any]]
    filters_applied: Optional[Dict[str, Any]] = None


class RelationCreate(BaseModel):
    """Create relationship between threats"""
    source_id: str
    target_id: str
    relation_type: str
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    metadata: Optional[Dict[str, Any]] = None


class CampaignResponse(BaseModel):
    """Campaign response"""
    campaign_id: str
    name: str
    description: Optional[str]
    threat_actor: Optional[str]
    attack_pattern: Optional[str]
    first_seen: datetime
    last_seen: datetime
    total_iocs: int
    is_active: bool
    affected_sectors: List[str] = []


class AlertCreate(BaseModel):
    """Create alert"""
    threat_id: str
    severity: ThreatLevel
    title: str
    description: str
    metadata: Optional[Dict[str, Any]] = None


class AlertResponse(BaseModel):
    """Alert response"""
    alert_id: str
    threat_id: str
    severity: ThreatLevel
    title: str
    description: str
    created_at: datetime
    is_acknowledged: bool
    is_resolved: bool
    assigned_to: Optional[str]
    
    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    """Statistics response"""
    total_threats: int
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    active_campaigns: int
    last_updated: datetime


class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str
    components: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.now)


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None
    status_code: int