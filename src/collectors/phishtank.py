"""
PhishTank Collector
Collects phishing URLs from PhishTank
"""

from typing import List, Dict, Optional
from datetime import datetime
from src.collectors.base import BaseThreatCollector
from loguru import logger
import json
import gzip


class PhishTankCollector(BaseThreatCollector):
    """Collector for PhishTank phishing URL intelligence"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize PhishTank collector
        
        Args:
            api_key: PhishTank API key (optional)
        """
        super().__init__(
            api_key=api_key,
            api_url="http://data.phishtank.com/data"
        )
    
    async def collect(self, verified_only: bool = True) -> List[Dict]:
        """
        Collect phishing URLs from PhishTank
        
        Args:
            verified_only: Only collect verified phishing URLs
            
        Returns:
            List of normalized threats
        """
        threats = []
        
        try:
            # PhishTank provides JSON data
            if self.api_key:
                endpoint = f"{self.api_key}/online-valid.json"
            else:
                endpoint = "online-valid.json"
            
            response = await self.fetch_data(endpoint)
            
            # PhishTank returns array directly
            if isinstance(response, list):
                for phish_data in response:
                    # Filter by verification status
                    if verified_only and not phish_data.get("verified") == "yes":
                        continue
                    
                    threat = self.normalize_threat(phish_data)
                    if threat:
                        threats.append(threat)
                
                self.total_collected += len(threats)
                self.last_update = datetime.now().isoformat()
                
                logger.info(f"Collected {len(threats)} phishing URLs from PhishTank")
            
        except Exception as e:
            logger.error(f"Error collecting from PhishTank: {e}")
        
        return threats
    
    async def check_url(self, url: str) -> Dict:
        """
        Check if a URL is in PhishTank database
        
        Args:
            url: URL to check
            
        Returns:
            PhishTank data if found
        """
        # PhishTank check API
        endpoint = f"{self.api_key}/checkurl/" if self.api_key else "checkurl/"
        data = {
            "url": url,
            "format": "json"
        }
        
        response = await self.post_data(endpoint, data)
        return response
    
    async def submit_phish(self, url: str) -> bool:
        """
        Submit a phishing URL to PhishTank
        
        Args:
            url: Phishing URL to submit
            
        Returns:
            True if successful
        """
        if not self.api_key:
            logger.warning("API key required to submit to PhishTank")
            return False
        
        endpoint = f"{self.api_key}/submit/"
        data = {
            "url": url,
            "format": "json"
        }
        
        response = await self.post_data(endpoint, data)
        return response.get("success", False)
    
    def normalize_threat(self, raw_threat: Dict) -> Optional[Dict]:
        """
        Normalize PhishTank data to standard format
        
        Args:
            raw_threat: Raw phishing data from PhishTank
            
        Returns:
            Normalized threat dictionary
        """
        url = raw_threat.get("url")
        if not url:
            return None
        
        # Determine threat level
        is_online = raw_threat.get("online") == "yes"
        is_verified = raw_threat.get("verified") == "yes"
        
        if is_online and is_verified:
            threat_level = "CRITICAL"
        elif is_verified:
            threat_level = "HIGH"
        elif is_online:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        # Extract target information
        target = raw_threat.get("target", "Unknown")
        
        metadata = {
            "phishtank_id": raw_threat.get("phish_id"),
            "phish_detail_url": raw_threat.get("phish_detail_url"),
            "submission_time": raw_threat.get("submission_time"),
            "verification_time": raw_threat.get("verification_time"),
            "online": is_online,
            "verified": is_verified,
            "target": target,
            "phish_detail_page": f"http://www.phishtank.com/phish_detail.php?phish_id={raw_threat.get('phish_id')}"
        }
        
        # Confidence based on verification
        confidence = 0.95 if is_verified else 0.7
        
        return self._create_standard_threat(
            threat_type="url",
            value=url,
            threat_level=threat_level,
            confidence=confidence,
            metadata=metadata
        )
    
    async def download_database(self, output_file: str, format: str = "json"):
        """
        Download complete PhishTank database
        
        Args:
            output_file: Path to save database
            format: Format (json, csv, or serialized php)
        """
        if format == "json":
            endpoint = f"{self.api_key}/online-valid.json.gz" if self.api_key else "online-valid.json.gz"
        elif format == "csv":
            endpoint = f"{self.api_key}/online-valid.csv.gz" if self.api_key else "online-valid.csv.gz"
        else:
            endpoint = f"{self.api_key}/online-valid.xml.gz" if self.api_key else "online-valid.xml.gz"
        
        # Note: This would need special handling for binary/compressed data
        logger.info(f"Download PhishTank database from: {self.api_url}/{endpoint}")
    
    def get_stats(self) -> Dict:
        """Get PhishTank collector statistics"""
        stats = super().get_stats()
        stats.update({
            "requires_api_key_for_submission": True,
            "data_update_frequency": "Every hour",
            "verification_process": "Community verified"
        })
        return stats