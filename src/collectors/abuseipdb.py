"""
AbuseIPDB Collector
Collects malicious IP addresses from AbuseIPDB
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from src.collectors.base import BaseThreatCollector
from loguru import logger


class AbuseIPDBCollector(BaseThreatCollector):
    """Collector for AbuseIPDB threat intelligence"""
    
    def __init__(self, api_key: str):
        """
        Initialize AbuseIPDB collector
        
        Args:
            api_key: AbuseIPDB API key
        """
        super().__init__(
            api_key=api_key,
            api_url="https://api.abuseipdb.com/api/v2"
        )
    
    def _get_headers(self) -> Dict:
        """Override to use AbuseIPDB-specific header"""
        return {
            "Accept": "application/json",
            "Key": self.api_key
        }
    
    async def collect(self, days: int = 7, confidence_min: int = 75) -> List[Dict]:
        """
        Collect malicious IPs from AbuseIPDB
        
        Args:
            days: Number of days to look back
            confidence_min: Minimum confidence score (0-100)
            
        Returns:
            List of normalized threats
        """
        threats = []
        
        try:
            # Get blacklist
            endpoint = "blacklist"
            params = {
                "confidenceMinimum": confidence_min,
                "limit": 10000
            }
            
            response = await self.fetch_data(endpoint, params)
            
            if "data" in response:
                for ip_data in response["data"]:
                    threat = self.normalize_threat(ip_data)
                    threats.append(threat)
                
                self.total_collected += len(threats)
                self.last_update = datetime.now().isoformat()
                
                logger.info(f"Collected {len(threats)} IPs from AbuseIPDB")
            
        except Exception as e:
            logger.error(f"Error collecting from AbuseIPDB: {e}")
        
        return threats
    
    async def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict:
        """
        Check a specific IP address
        
        Args:
            ip_address: IP to check
            max_age_days: Max age of reports to consider
            
        Returns:
            Threat data for the IP
        """
        endpoint = "check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": True
        }
        
        response = await self.fetch_data(endpoint, params)
        
        if "data" in response:
            return self.normalize_threat(response["data"])
        
        return {}
    
    async def report_ip(
        self,
        ip_address: str,
        categories: List[int],
        comment: str
    ) -> bool:
        """
        Report an IP to AbuseIPDB
        
        Args:
            ip_address: IP to report
            categories: List of abuse category IDs
            comment: Description of abuse
            
        Returns:
            True if successful
        """
        endpoint = "report"
        data = {
            "ip": ip_address,
            "categories": ",".join(map(str, categories)),
            "comment": comment
        }
        
        response = await self.post_data(endpoint, data)
        return "data" in response
    
    def normalize_threat(self, raw_threat: Dict) -> Dict:
        """
        Normalize AbuseIPDB data to standard format
        
        Args:
            raw_threat: Raw IP data from AbuseIPDB
            
        Returns:
            Normalized threat dictionary
        """
        ip_address = raw_threat.get("ipAddress", "")
        abuse_score = raw_threat.get("abuseConfidenceScore", 0)
        
        # Map confidence score to threat level
        if abuse_score >= 90:
            threat_level = "CRITICAL"
        elif abuse_score >= 75:
            threat_level = "HIGH"
        elif abuse_score >= 50:
            threat_level = "MEDIUM"
        elif abuse_score >= 25:
            threat_level = "LOW"
        else:
            threat_level = "INFO"
        
        # Convert confidence to 0-1 scale
        confidence = abuse_score / 100.0
        
        metadata = {
            "abuse_confidence_score": abuse_score,
            "total_reports": raw_threat.get("totalReports", 0),
            "num_distinct_users": raw_threat.get("numDistinctUsers", 0),
            "last_reported_at": raw_threat.get("lastReportedAt"),
            "country_code": raw_threat.get("countryCode"),
            "country_name": raw_threat.get("countryName"),
            "usage_type": raw_threat.get("usageType"),
            "isp": raw_threat.get("isp"),
            "domain": raw_threat.get("domain"),
            "is_whitelisted": raw_threat.get("isWhitelisted", False),
            "is_tor": raw_threat.get("isTor", False)
        }
        
        # Add category information if available
        if "reports" in raw_threat:
            categories = set()
            for report in raw_threat["reports"]:
                categories.update(report.get("categories", []))
            metadata["abuse_categories"] = list(categories)
        
        return self._create_standard_threat(
            threat_type="ip_address",
            value=ip_address,
            threat_level=threat_level,
            confidence=confidence,
            metadata=metadata
        )
    
    async def get_recent_reports(self, max_age_days: int = 1) -> List[Dict]:
        """
        Get recent abuse reports
        
        Args:
            max_age_days: Max age of reports
            
        Returns:
            List of recent threats
        """
        # AbuseIPDB doesn't have a direct "recent reports" endpoint
        # Use blacklist with recent filter
        return await self.collect(days=max_age_days, confidence_min=50)
    
    def get_abuse_categories(self) -> Dict[int, str]:
        """
        Get AbuseIPDB category mappings
        
        Returns:
            Dictionary of category IDs to names
        """
        return {
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }