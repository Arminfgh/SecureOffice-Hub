"""
Threats API Routes
Endpoints for managing threat indicators
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime
from src.core.threat_graph import ThreatGraph
from src.core.bloom_filter import MalwareHashFilter


router = APIRouter()


class ThreatCreate(BaseModel):
    threat_type: str = Field(..., description="Type of threat (ip, domain, url, hash)")
    value: str = Field(..., description="Threat value")
    threat_level: str = Field("MEDIUM", description="Severity level")
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    metadata: Optional[Dict] = None


class ThreatRelationCreate(BaseModel):
    source_id: str = Field(..., description="Source threat ID")
    target_id: str = Field(..., description="Target threat ID")
    relation_type: str = Field(..., description="Type of relationship")
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    metadata: Optional[Dict] = None


@router.post("/")
async def create_threat(threat: ThreatCreate):
    """
    Create a new threat indicator
    
    - **threat_type**: Type of threat (ip_address, domain, url, file_hash, etc.)
    - **value**: The threat value
    - **threat_level**: Severity (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
    - **confidence**: Confidence score (0.0 to 1.0)
    - **metadata**: Additional threat information
    
    Returns the created threat with ID
    """
    try:
        # This would normally save to database
        # For now, just return the created threat
        threat_id = f"{threat.threat_type}_{threat.value}"
        
        return {
            "threat_id": threat_id,
            "threat_type": threat.threat_type,
            "value": threat.value,
            "threat_level": threat.threat_level,
            "confidence": threat.confidence,
            "metadata": threat.metadata,
            "created_at": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{threat_id}")
async def get_threat(threat_id: str):
    """
    Get a specific threat by ID
    
    - **threat_id**: Unique threat identifier
    
    Returns threat details
    """
    # This would normally query the database
    # For demo, return mock data
    return {
        "threat_id": threat_id,
        "threat_type": "url",
        "value": "example.com",
        "threat_level": "HIGH",
        "confidence": 0.85,
        "first_seen": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat()
    }


@router.get("/")
async def list_threats(
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    threat_level: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Offset for pagination")
):
    """
    List threat indicators with optional filters
    
    - **threat_type**: Filter by type (ip_address, domain, url, etc.)
    - **threat_level**: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
    - **limit**: Maximum number of results
    - **offset**: Pagination offset
    
    Returns paginated list of threats
    """
    # Mock data for demo
    threats = [
        {
            "threat_id": "url_paypa1-secure.tk",
            "threat_type": "url",
            "value": "paypa1-secure.tk/login",
            "threat_level": "CRITICAL",
            "confidence": 0.94,
            "first_seen": "2024-01-15T10:30:00"
        },
        {
            "threat_id": "ip_45.76.123.45",
            "threat_type": "ip_address",
            "value": "45.76.123.45",
            "threat_level": "HIGH",
            "confidence": 0.88,
            "first_seen": "2024-01-15T09:15:00"
        },
        {
            "threat_id": "hash_a3f5b8c9d2e1f4a7",
            "threat_type": "file_hash",
            "value": "a3f5b8c9d2e1f4a7b6c5d8e9f1a2b3c4",
            "threat_level": "CRITICAL",
            "confidence": 0.92,
            "first_seen": "2024-01-14T16:45:00"
        }
    ]
    
    # Apply filters
    if threat_type:
        threats = [t for t in threats if t['threat_type'] == threat_type]
    
    if threat_level:
        threats = [t for t in threats if t['threat_level'] == threat_level]
    
    # Apply pagination
    paginated = threats[offset:offset + limit]
    
    return {
        "total": len(threats),
        "limit": limit,
        "offset": offset,
        "threats": paginated
    }


@router.post("/relations")
async def create_relation(relation: ThreatRelationCreate):
    """
    Create a relationship between two threats
    
    - **source_id**: Source threat ID
    - **target_id**: Target threat ID
    - **relation_type**: Type of relationship (hosts, communicates_with, etc.)
    - **confidence**: Confidence score
    - **metadata**: Additional relationship data
    
    Returns the created relationship
    """
    return {
        "relation_id": f"{relation.source_id}_{relation.target_id}",
        "source_id": relation.source_id,
        "target_id": relation.target_id,
        "relation_type": relation.relation_type,
        "confidence": relation.confidence,
        "metadata": relation.metadata,
        "created_at": datetime.now().isoformat()
    }


@router.get("/{threat_id}/related")
async def get_related_threats(
    threat_id: str,
    depth: int = Query(1, ge=1, le=5, description="Relationship depth"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence")
):
    """
    Get threats related to a specific threat
    
    - **threat_id**: Threat to find relations for
    - **depth**: How many relationship hops to traverse
    - **min_confidence**: Minimum confidence threshold
    
    Returns list of related threats with relationship info
    """
    # Mock related threats
    related = [
        {
            "threat_id": "ip_192.0.2.15",
            "threat_type": "ip_address",
            "value": "192.0.2.15",
            "relation": "hosts",
            "confidence": 0.95,
            "distance": 1
        },
        {
            "threat_id": "domain_evil.com",
            "threat_type": "domain",
            "value": "evil.com",
            "relation": "redirects_to",
            "confidence": 0.88,
            "distance": 1
        }
    ]
    
    return {
        "threat_id": threat_id,
        "depth": depth,
        "total_related": len(related),
        "related_threats": related
    }


@router.delete("/{threat_id}")
async def delete_threat(threat_id: str):
    """
    Delete a threat indicator
    
    - **threat_id**: Threat to delete
    
    Returns success confirmation
    """
    return {
        "success": True,
        "threat_id": threat_id,
        "deleted_at": datetime.now().isoformat()
    }


@router.get("/stats/summary")
async def get_threat_stats():
    """
    Get threat statistics summary
    
    Returns overall statistics about threats
    """
    return {
        "total_threats": 15247,
        "by_severity": {
            "CRITICAL": 23,
            "HIGH": 156,
            "MEDIUM": 892,
            "LOW": 3421,
            "SAFE": 10755
        },
        "by_type": {
            "ip_address": 5234,
            "domain": 4123,
            "url": 3456,
            "file_hash": 2134,
            "email": 300
        },
        "active_campaigns": 7,
        "last_updated": datetime.now().isoformat()
    }