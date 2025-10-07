"""
API Dependencies
Shared dependencies for FastAPI endpoints
"""

from fastapi import Depends, HTTPException, status, Header
from typing import Optional
from src.core.threat_graph import ThreatGraph
from src.core.bloom_filter import MalwareHashFilter
from src.ai.analyzer import ThreatAnalyzer
from src.ai.cache import AICache
from src.database.connection import get_db
from src.config.settings import get_settings
from sqlalchemy.orm import Session


settings = get_settings()


# Global instances (initialized in main.py)
_threat_graph: Optional[ThreatGraph] = None
_malware_filter: Optional[MalwareHashFilter] = None
_ai_analyzer: Optional[ThreatAnalyzer] = None
_ai_cache: Optional[AICache] = None


def set_threat_graph(graph: ThreatGraph):
    """Set global threat graph instance"""
    global _threat_graph
    _threat_graph = graph


def set_malware_filter(filter: MalwareHashFilter):
    """Set global malware filter instance"""
    global _malware_filter
    _malware_filter = filter


def set_ai_analyzer(analyzer: ThreatAnalyzer):
    """Set global AI analyzer instance"""
    global _ai_analyzer
    _ai_analyzer = analyzer


def set_ai_cache(cache: AICache):
    """Set global AI cache instance"""
    global _ai_cache
    _ai_cache = cache


def get_threat_graph() -> ThreatGraph:
    """Get threat graph dependency"""
    if _threat_graph is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat graph not initialized"
        )
    return _threat_graph


def get_malware_filter() -> MalwareHashFilter:
    """Get malware filter dependency"""
    if _malware_filter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Malware filter not initialized"
        )
    return _malware_filter


def get_ai_analyzer() -> ThreatAnalyzer:
    """Get AI analyzer dependency"""
    if _ai_analyzer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI analyzer not initialized"
        )
    return _ai_analyzer


def get_ai_cache() -> AICache:
    """Get AI cache dependency"""
    if _ai_cache is None:
        # Return a basic instance if not initialized
        return AICache()
    return _ai_cache


def get_current_user(
    x_api_key: Optional[str] = Header(None)
) -> str:
    """
    Get current user from API key
    
    Args:
        x_api_key: API key from header
        
    Returns:
        User identifier
        
    Raises:
        HTTPException: If authentication fails
    """
    if not settings.ENABLE_AUTH:
        return "anonymous"
    
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )
    
    # Here you would validate the API key against a database
    # For now, just accept any key
    return f"user_{x_api_key[:8]}"


def verify_admin(
    current_user: str = Depends(get_current_user)
) -> str:
    """
    Verify user has admin privileges
    
    Args:
        current_user: Current user identifier
        
    Returns:
        User identifier
        
    Raises:
        HTTPException: If user is not admin
    """
    # Here you would check if user is admin
    # For now, just check if not anonymous
    if current_user == "anonymous":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return current_user


class CommonQueryParams:
    """Common query parameters for list endpoints"""
    
    def __init__(
        self,
        skip: int = 0,
        limit: int = 100,
        sort_by: Optional[str] = None,
        order: str = "desc"
    ):
        self.skip = skip
        self.limit = min(limit, 1000)  # Max 1000 items
        self.sort_by = sort_by
        self.order = order.lower()


def get_db_session(db: Session = Depends(get_db)) -> Session:
    """Get database session"""
    return db