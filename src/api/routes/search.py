"""
Search API Routes
Natural language search and advanced filtering
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime
from src.ai.analyzer import ThreatAnalyzer


router = APIRouter()


class SearchQuery(BaseModel):
    query: str = Field(..., description="Search query (can be natural language)")
    filters: Optional[Dict] = Field(None, description="Additional filters")
    limit: int = Field(50, ge=1, le=500)


class AdvancedSearchQuery(BaseModel):
    threat_type: Optional[str] = None
    threat_level: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    confidence_min: Optional[float] = None
    tags: Optional[List[str]] = None
    value_pattern: Optional[str] = None


@router.post("/")
async def search_threats(search: SearchQuery):
    """
    Natural language threat search
    
    - **query**: Natural language query (e.g., "Show me Russian phishing threats from last week")
    - **filters**: Optional additional filters
    - **limit**: Maximum results
    
    Returns matching threats with AI-powered interpretation
    """
    try:
        # Mock threat data for demo
        all_threats = [
            {
                "threat_id": "url_1",
                "threat_type": "url",
                "value": "paypa1-secure.tk/login",
                "threat_level": "CRITICAL",
                "confidence": 0.94,
                "tags": ["phishing", "typosquatting"],
                "country": "Russia"
            },
            {
                "threat_id": "ip_1",
                "threat_type": "ip_address",
                "value": "45.76.123.45",
                "threat_level": "HIGH",
                "confidence": 0.88,
                "tags": ["botnet", "c2"],
                "country": "China"
            }
        ]
        
        # In production, use AI to interpret query
        # analyzer = ThreatAnalyzer()
        # result = analyzer.natural_language_query(search.query, all_threats)
        
        # For demo, return mock results
        return {
            "query": search.query,
            "understood_as": "Finding phishing threats from Russia",
            "total_results": 1,
            "results": [all_threats[0]],
            "filters_applied": {
                "threat_type": "url",
                "country": "Russia",
                "tags": ["phishing"]
            },
            "summary": f"Found 1 phishing threat from Russia matching your query.",
            "follow_up_suggestions": [
                "Show me related IP addresses",
                "Find similar phishing campaigns",
                "Show timeline of this threat"
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/advanced")
async def advanced_search(filters: AdvancedSearchQuery):
    """
    Advanced search with specific filters
    
    - **threat_type**: Filter by type
    - **threat_level**: Filter by severity
    - **date_from**: Start date (ISO format)
    - **date_to**: End date (ISO format)
    - **confidence_min**: Minimum confidence score
    - **tags**: List of tags to match
    - **value_pattern**: Pattern to match in threat value
    
    Returns filtered threats
    """
    # Mock results
    results = [
        {
            "threat_id": "url_paypa1",
            "threat_type": "url",
            "value": "paypa1-secure.tk/login",
            "threat_level": "CRITICAL",
            "confidence": 0.94,
            "tags": ["phishing", "typosquatting"],
            "first_seen": "2024-01-15T10:30:00"
        }
    ]
    
    return {
        "filters": filters.dict(exclude_none=True),
        "total_results": len(results),
        "results": results
    }


@router.get("/ioc/{ioc_value}")
async def search_ioc(ioc_value: str):
    """
    Search for a specific IOC (Indicator of Compromise)
    
    - **ioc_value**: IOC to search for (IP, domain, hash, etc.)
    
    Returns all information about the IOC
    """
    # Auto-detect IOC type
    import re
    
    ioc_type = "unknown"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_value):
        ioc_type = "ip_address"
    elif re.match(r'^[a-f0-9]{32,64}$', ioc_value.lower()):
        ioc_type = "file_hash"
    elif '.' in ioc_value and not ioc_value.startswith('http'):
        ioc_type = "domain"
    elif ioc_value.startswith('http'):
        ioc_type = "url"
    
    return {
        "ioc_value": ioc_value,
        "detected_type": ioc_type,
        "threat_level": "HIGH",
        "confidence": 0.85,
        "first_seen": "2024-01-10T08:00:00",
        "last_seen": datetime.now().isoformat(),
        "occurrences": 47,
        "related_threats": 12,
        "campaigns": ["APT-2024-001"],
        "recommended_action": "Block and monitor"
    }


@router.post("/bulk")
async def bulk_search(iocs: List[str]):
    """
    Bulk IOC search
    
    - **iocs**: List of IOCs to search for
    
    Returns results for all IOCs
    """
    results = []
    
    for ioc in iocs:
        results.append({
            "ioc": ioc,
            "found": True,
            "threat_level": "MEDIUM",
            "confidence": 0.75
        })
    
    return {
        "total_searched": len(iocs),
        "found": len(results),
        "results": results
    }


@router.get("/campaigns")
async def search_campaigns(
    name: Optional[str] = None,
    threat_actor: Optional[str] = None,
    active_only: bool = True
):
    """
    Search threat campaigns
    
    - **name**: Campaign name pattern
    - **threat_actor**: Filter by threat actor
    - **active_only**: Only show active campaigns
    
    Returns matching campaigns
    """
    campaigns = [
        {
            "campaign_id": "APT-2024-001",
            "name": "Operation Dark Web",
            "threat_actor": "APT28",
            "attack_pattern": "Spear Phishing + Malware",
            "total_iocs": 156,
            "first_seen": "2024-01-01T00:00:00",
            "is_active": True,
            "affected_sectors": ["Finance", "Healthcare"]
        },
        {
            "campaign_id": "PHISH-2024-007",
            "name": "PayPal Phishing Wave",
            "threat_actor": "Unknown",
            "attack_pattern": "Typosquatting + Credential Harvesting",
            "total_iocs": 89,
            "first_seen": "2024-01-15T00:00:00",
            "is_active": True,
            "affected_sectors": ["E-commerce", "Banking"]
        }
    ]
    
    if name:
        campaigns = [c for c in campaigns if name.lower() in c['name'].lower()]
    
    if threat_actor:
        campaigns = [c for c in campaigns if c['threat_actor'] == threat_actor]
    
    if active_only:
        campaigns = [c for c in campaigns if c['is_active']]
    
    return {
        "total_campaigns": len(campaigns),
        "campaigns": campaigns
    }


@router.get("/suggest")
async def search_suggestions(partial: str):
    """
    Get search suggestions based on partial input
    
    - **partial**: Partial search term
    
    Returns suggested queries and IOCs
    """
    suggestions = {
        "queries": [
            f"Show me {partial} threats from last week",
            f"Find all {partial} campaigns",
            f"Analyze {partial} indicators"
        ],
        "iocs": [
            f"example-{partial}.com",
            f"{partial}-malware.exe",
            f"192.168.{partial}.1"
        ],
        "campaigns": [
            f"{partial.upper()}-2024-001"
        ]
    }
    
    return suggestions