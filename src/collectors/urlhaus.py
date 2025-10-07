"""
URLhaus Collector
Collects malware distribution URLs from URLhaus (abuse.ch)
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from src.collectors.base import BaseThreatCollector
from loguru import logger


class URLhausCollector(BaseThreatCollector):
    """Collector for URLhaus malware URL intelligence"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize URLhaus collector
        
        Args:
            api_key: URLhaus API key (optional, increases rate limits)
        """
        super().__init__(
            api_key=api_key,
            api_url="https://urlhaus-api.abuse.ch/v1"
        )
    
    async def collect(self, days: int = 7, limit: int = 1000) -> List[Dict]:
        """
        Collect recent malware URLs from URLhaus
        
        Args:
            days: Number of days to look back
            limit: Maximum number of URLs
            
        Returns:
            List of normalized threats
        """
        threats = []
        
        try:
            # Get recent URLs
            endpoint = "urls/recent"
            params = {"limit": limit}
            
            response = await self.fetch_data(endpoint, params)
            
            if "urls" in response:
                for url_data in response["urls"]:
                    # Filter by date
                    date_added = url_data.get("date_added")
                    if date_added:
                        url_date = datetime.fromisoformat(date_added.replace("Z", "+00:00"))
                        cutoff = datetime.now() - timedelta(days=days)
                        
                        if url_date < cutoff:
                            continue
                    
                    threat = self.normalize_threat(url_data)
                    if threat:
                        threats.append(threat)
                
                self.total_collected += len(threats)
                self.last_update = datetime.now().isoformat()
                
                logger.info(f"Collected {len(threats)} malware URLs from URLhaus")
            
        except Exception as e:
            logger.error(f"Error collecting from URLhaus: {e}")
        
        return threats
    
    async def lookup_url(self, url: str) -> Dict:
        """
        Lookup a specific URL
        
        Args:
            url: URL to lookup
            
        Returns:
            URL information
        """
        endpoint = "url"
        data = {"url": url}
        
        response = await self.post_data(endpoint, data)
        return response
    
    async def lookup_host(self, host: str) -> Dict:
        """
        Lookup URLs by host
        
        Args:
            host: Hostname to lookup
            
        Returns:
            Host information with URLs
        """
        endpoint = "host"
        data = {"host": host}
        
        response = await self.post_data(endpoint, data)
        return response
    
    async def lookup_payload(self, hash_value: str, hash_type: str = "sha256") -> Dict:
        """
        Lookup URLs delivering a specific payload
        
        Args:
            hash_value: File hash
            hash_type: Hash type (md5 or sha256)
            
        Returns:
            Payload information with URLs
        """
        endpoint = "payload"
        data = {
            f"{hash_type}_hash": hash_value
        }
        
        response = await self.post_data(endpoint, data)
        return response
    
    async def get_recent_payloads(self) -> List[Dict]:
        """
        Get recent malware payloads
        
        Returns:
            List of recent payloads
        """
        endpoint = "payloads/recent"
        
        response = await self.fetch_data(endpoint)
        return response.get("payloads", [])
    
    def normalize_threat(self, raw_threat: Dict) -> Optional[Dict]:
        """
        Normalize URLhaus data to standard format
        
        Args:
            raw_threat: Raw URL data from URLhaus
            
        Returns:
            Normalized threat dictionary
        """
        url = raw_threat.get("url")
        if not url:
            return None
        
        # Determine threat level based on status
        url_status = raw_threat.get("url_status", "online")
        threat_status = raw_threat.get("threat", "malware_download")
        
        if url_status == "online":
            threat_level = "CRITICAL"
        elif url_status == "offline":
            threat_level = "HIGH"  # Still dangerous if comes back
        else:
            threat_level = "MEDIUM"
        
        # Adjust based on threat type
        if threat_status == "malware_download":
            pass  # Keep current level
        elif "ransomware" in threat_status.lower():
            threat_level = "CRITICAL"
        
        metadata = {
            "urlhaus_id": raw_threat.get("id"),
            "urlhaus_reference": raw_threat.get("urlhaus_reference"),
            "url_status": url_status,
            "threat_type": threat_status,
            "date_added": raw_threat.get("date_added"),
            "reporter": raw_threat.get("reporter"),
            "larted": raw_threat.get("larted"),
            "takedown_time_seconds": raw_threat.get("takedown_time_seconds"),
            "tags": raw_threat.get("tags", []),
            "payloads": []
        }
        
        # Add payload information if available
        payloads = raw_threat.get("payloads", [])
        for payload in payloads:
            metadata["payloads"].append({
                "firstseen": payload.get("firstseen"),
                "filename": payload.get("filename"),
                "file_type": payload.get("file_type"),
                "response_size": payload.get("response_size"),
                "response_md5": payload.get("response_md5"),
                "response_sha256": payload.get("response_sha256"),
                "signature": payload.get("signature"),
                "virustotal": payload.get("virustotal")
            })
        
        return self._create_standard_threat(
            threat_type="url",
            value=url,
            threat_level=threat_level,
            confidence=0.9,  # URLhaus is highly reliable
            metadata=metadata
        )
    
    async def download_url_list(self, output_file: str):
        """
        Download complete URL list
        
        Args:
            output_file: Path to save URL list
        """
        endpoint = "urls/csv"
        
        response = await self.fetch_data(endpoint)
        
        with open(output_file, 'w') as f:
            f.write(response)
        
        logger.info(f"Downloaded URLhaus list to {output_file}")
    
    def get_threat_types(self) -> List[str]:
        """
        Get list of URLhaus threat types
        
        Returns:
            List of threat types
        """
        return [
            "malware_download",
            "ransomware_download",
            "trojan_download",
            "backdoor_download",
            "banking_trojan",
            "botnet_cc",
            "exploit_kit"
        ]