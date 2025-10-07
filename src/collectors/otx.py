"""
AlienVault OTX Collector
Collects threat intelligence from AlienVault Open Threat Exchange
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from src.collectors.base import BaseThreatCollector
from loguru import logger


class OTXCollector(BaseThreatCollector):
    """Collector for AlienVault OTX threat intelligence"""
    
    def __init__(self, api_key: str):
        """
        Initialize OTX collector
        
        Args:
            api_key: AlienVault OTX API key
        """
        super().__init__(
            api_key=api_key,
            api_url="https://otx.alienvault.com/api/v1"
        )
    
    def _get_headers(self) -> Dict:
        """Override to use OTX-specific header"""
        return {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatScope/1.0"
        }
    
    async def collect(self, limit: int = 100) -> List[Dict]:
        """
        Collect threats from OTX pulses
        
        Args:
            limit: Maximum number of pulses to fetch
            
        Returns:
            List of normalized threats
        """
        threats = []
        
        try:
            # Get subscribed pulses
            endpoint = "pulses/subscribed"
            params = {"limit": limit, "page": 1}
            
            response = await self.fetch_data(endpoint, params)
            
            if "results" in response:
                for pulse in response["results"]:
                    # Extract IOCs from pulse
                    pulse_threats = self._extract_iocs_from_pulse(pulse)
                    threats.extend(pulse_threats)
                
                self.total_collected += len(threats)
                self.last_update = datetime.now().isoformat()
                
                logger.info(f"Collected {len(threats)} IOCs from {len(response['results'])} OTX pulses")
            
        except Exception as e:
            logger.error(f"Error collecting from OTX: {e}")
        
        return threats
    
    def _extract_iocs_from_pulse(self, pulse: Dict) -> List[Dict]:
        """
        Extract IOCs from a pulse
        
        Args:
            pulse: OTX pulse data
            
        Returns:
            List of normalized threats
        """
        threats = []
        indicators = pulse.get("indicators", [])
        
        for indicator in indicators:
            threat = self.normalize_threat(indicator, pulse)
            if threat:
                threats.append(threat)
        
        return threats
    
    async def get_pulse(self, pulse_id: str) -> Dict:
        """
        Get a specific pulse by ID
        
        Args:
            pulse_id: Pulse identifier
            
        Returns:
            Pulse data
        """
        endpoint = f"pulses/{pulse_id}"
        return await self.fetch_data(endpoint)
    
    async def search_pulses(self, query: str) -> List[Dict]:
        """
        Search for pulses
        
        Args:
            query: Search query
            
        Returns:
            List of matching pulses
        """
        endpoint = "search/pulses"
        params = {"q": query}
        
        response = await self.fetch_data(endpoint, params)
        return response.get("results", [])
    
    async def get_ip_indicators(self, ip_address: str) -> Dict:
        """
        Get indicators for a specific IP
        
        Args:
            ip_address: IP to lookup
            
        Returns:
            IP indicator data
        """
        endpoint = f"indicators/IPv4/{ip_address}"
        return await self.fetch_data(endpoint)
    
    async def get_domain_indicators(self, domain: str) -> Dict:
        """
        Get indicators for a specific domain
        
        Args:
            domain: Domain to lookup
            
        Returns:
            Domain indicator data
        """
        endpoint = f"indicators/domain/{domain}"
        return await self.fetch_data(endpoint)
    
    async def get_url_indicators(self, url: str) -> Dict:
        """
        Get indicators for a specific URL
        
        Args:
            url: URL to lookup
            
        Returns:
            URL indicator data
        """
        endpoint = f"indicators/url/{url}"
        return await self.fetch_data(endpoint)
    
    def normalize_threat(self, raw_threat: Dict, pulse: Optional[Dict] = None) -> Optional[Dict]:
        """
        Normalize OTX indicator to standard format
        
        Args:
            raw_threat: Raw indicator from OTX
            pulse: Parent pulse data
            
        Returns:
            Normalized threat dictionary
        """
        indicator_type = raw_threat.get("type", "").lower()
        indicator_value = raw_threat.get("indicator", "")
        
        if not indicator_value:
            return None
        
        # Map OTX types to ThreatScope types
        type_mapping = {
            "ipv4": "ip_address",
            "ipv6": "ip_address",
            "domain": "domain",
            "hostname": "domain",
            "url": "url",
            "filehash-md5": "file_hash",
            "filehash-sha1": "file_hash",
            "filehash-sha256": "file_hash",
            "email": "email",
            "cve": "cve"
        }
        
        threat_type = type_mapping.get(indicator_type, "unknown")
        
        if threat_type == "unknown":
            return None
        
        # Determine threat level based on pulse tags
        threat_level = "MEDIUM"
        if pulse:
            tags = [tag.lower() for tag in pulse.get("tags", [])]
            if any(tag in tags for tag in ["apt", "malware", "ransomware"]):
                threat_level = "CRITICAL"
            elif any(tag in tags for tag in ["phishing", "trojan"]):
                threat_level = "HIGH"
        
        metadata = {
            "otx_pulse_id": pulse.get("id") if pulse else None,
            "otx_pulse_name": pulse.get("name") if pulse else None,
            "description": raw_threat.get("description"),
            "created": raw_threat.get("created"),
            "title": raw_threat.get("title"),
            "is_active": raw_threat.get("is_active", True),
            "tags": pulse.get("tags", []) if pulse else []
        }
        
        # Add pulse metadata
        if pulse:
            metadata.update({
                "pulse_created": pulse.get("created"),
                "pulse_modified": pulse.get("modified"),
                "pulse_author": pulse.get("author_name"),
                "pulse_tlp": pulse.get("tlp"),
                "pulse_references": pulse.get("references", [])
            })
        
        return self._create_standard_threat(
            threat_type=threat_type,
            value=indicator_value,
            threat_level=threat_level,
            confidence=0.75,  # OTX indicators generally reliable
            metadata=metadata
        )
    
    async def get_trending_pulses(self) -> List[Dict]:
        """
        Get trending pulses
        
        Returns:
            List of trending pulses
        """
        endpoint = "pulses/subscribed"
        params = {"sort": "-created", "limit": 50}
        
        response = await self.fetch_data(endpoint, params)
        return response.get("results", [])