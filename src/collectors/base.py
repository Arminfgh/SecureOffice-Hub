"""
Base Threat Feed Collector
Abstract base class for all threat intelligence feed collectors
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from datetime import datetime
import httpx
from loguru import logger


class BaseThreatCollector(ABC):
    """Abstract base class for threat feed collectors"""
    
    def __init__(self, api_key: Optional[str] = None, api_url: Optional[str] = None):
        """
        Initialize collector
        
        Args:
            api_key: API key for the threat feed
            api_url: Base URL for the API
        """
        self.api_key = api_key
        self.api_url = api_url
        self.client = httpx.AsyncClient(timeout=30.0)
        self.last_update = None
        self.total_collected = 0
    
    @abstractmethod
    async def collect(self) -> List[Dict]:
        """
        Collect threats from the feed
        
        Returns:
            List of threat dictionaries
        """
        pass
    
    @abstractmethod
    def normalize_threat(self, raw_threat: Dict) -> Dict:
        """
        Normalize raw threat data to standard format
        
        Args:
            raw_threat: Raw threat data from feed
            
        Returns:
            Normalized threat dictionary
        """
        pass
    
    async def fetch_data(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """
        Fetch data from API endpoint
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            
        Returns:
            API response data
        """
        url = f"{self.api_url}/{endpoint}"
        headers = self._get_headers()
        
        try:
            response = await self.client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching from {url}: {e}")
            return {}
    
    async def post_data(self, endpoint: str, data: Dict) -> Dict:
        """
        POST data to API endpoint
        
        Args:
            endpoint: API endpoint
            data: Data to post
            
        Returns:
            API response data
        """
        url = f"{self.api_url}/{endpoint}"
        headers = self._get_headers()
        
        try:
            response = await self.client.post(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"HTTP error posting to {url}: {e}")
            return {}
    
    def _get_headers(self) -> Dict:
        """
        Get API request headers
        
        Returns:
            Headers dictionary
        """
        headers = {
            "Accept": "application/json",
            "User-Agent": "ThreatScope/1.0"
        }
        
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        return headers
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
    
    def get_stats(self) -> Dict:
        """Get collector statistics"""
        return {
            "collector": self.__class__.__name__,
            "last_update": self.last_update,
            "total_collected": self.total_collected,
            "api_url": self.api_url,
            "has_api_key": bool(self.api_key)
        }
    
    def _create_standard_threat(
        self,
        threat_type: str,
        value: str,
        threat_level: str = "MEDIUM",
        confidence: float = 0.5,
        metadata: Optional[Dict] = None
    ) -> Dict:
        """
        Create standardized threat dictionary
        
        Args:
            threat_type: Type of threat
            value: Threat value
            threat_level: Severity level
            confidence: Confidence score
            metadata: Additional metadata
            
        Returns:
            Standardized threat dictionary
        """
        return {
            "threat_type": threat_type,
            "value": value,
            "threat_level": threat_level,
            "confidence": confidence,
            "source": self.__class__.__name__,
            "collected_at": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
    
    async def batch_collect(self, batch_size: int = 100) -> List[List[Dict]]:
        """
        Collect threats in batches
        
        Args:
            batch_size: Size of each batch
            
        Returns:
            List of batches
        """
        all_threats = await self.collect()
        batches = []
        
        for i in range(0, len(all_threats), batch_size):
            batch = all_threats[i:i + batch_size]
            batches.append(batch)
        
        return batches
    
    async def validate_api_key(self) -> bool:
        """
        Validate API key
        
        Returns:
            True if API key is valid
        """
        try:
            # Override in subclass with actual validation
            return bool(self.api_key)
        except:
            return False