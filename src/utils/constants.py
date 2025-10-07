"""
Application Constants
Centralized constants and configuration values
"""

from typing import Dict, List

# Application Information
APP_NAME = "ThreatScope"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "AI-Powered Threat Intelligence Platform"
APP_AUTHOR = "ThreatScope Team"


# Threat Levels
class ThreatLevel:
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    
    ALL = [CRITICAL, HIGH, MEDIUM, LOW, SAFE]
    ACTIONABLE = [CRITICAL, HIGH, MEDIUM]


# Threat Types
class ThreatType:
    """Types of threat indicators"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"
    MALWARE = "malware"
    ACTOR = "actor"
    CAMPAIGN = "campaign"
    
    ALL = [IP_ADDRESS, DOMAIN, URL, FILE_HASH, EMAIL, CVE, MALWARE, ACTOR, CAMPAIGN]


# Relationship Types
class RelationType:
    """Types of relationships between threats"""
    HOSTS = "hosts"
    COMMUNICATES_WITH = "communicates_with"
    REDIRECTS_TO = "redirects_to"
    DROPS = "drops"
    EXPLOITS = "exploits"
    ATTRIBUTED_TO = "attributed_to"
    RELATED_TO = "related_to"
    PART_OF = "part_of"
    CONTAINS = "contains"
    CONNECTS_TO = "connects_to"
    USES = "uses"
    
    ALL = [
        HOSTS, COMMUNICATES_WITH, REDIRECTS_TO, DROPS,
        EXPLOITS, ATTRIBUTED_TO, RELATED_TO, PART_OF,
        CONTAINS, CONNECTS_TO, USES
    ]


# Hash Types
class HashType:
    """File hash types"""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    
    ALL = [MD5, SHA1, SHA256]
    
    LENGTHS = {
        MD5: 32,
        SHA1: 40,
        SHA256: 64
    }


# Suspicious TLDs
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free domains
    ".xyz", ".top", ".work", ".click",  # Cheap domains
    ".loan", ".download", ".racing",    # Spam-associated
    ".win", ".bid", ".faith",           # Commonly abused
]


# High-Risk Countries (for threat analysis)
HIGH_RISK_COUNTRIES = [
    "RU",  # Russia
    "CN",  # China
    "KP",  # North Korea
    "IR",  # Iran
    "SY",  # Syria
]


# Common Phishing Keywords
PHISHING_KEYWORDS = [
    "verify", "account", "suspended", "confirm", "update",
    "secure", "login", "password", "alert", "urgent",
    "expire", "billing", "payment", "invoice", "refund",
    "tax", "delivery", "package", "shipment", "prize"
]


# Known Malware Families
MALWARE_FAMILIES = [
    "Emotet", "TrickBot", "Ryuk", "Cobalt Strike",
    "Dridex", "Zeus", "Qakbot", "IcedID",
    "Ransomware", "Trojan", "Backdoor", "RAT",
    "Spyware", "Adware", "Rootkit", "Worm"
]


# APT Groups
APT_GROUPS = [
    "APT28", "APT29", "APT32", "APT33", "APT34",
    "Lazarus Group", "Fancy Bear", "Cozy Bear",
    "Carbanak", "FIN7", "FIN8", "TA505"
]


# MITRE ATT&CK Tactics
MITRE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]


# Industry Sectors
INDUSTRY_SECTORS = [
    "Financial Services",
    "Healthcare",
    "Government",
    "Education",
    "Retail",
    "Manufacturing",
    "Technology",
    "Energy",
    "Telecommunications",
    "Transportation"
]


# HTTP Status Codes (for API)
class HTTPStatus:
    """Common HTTP status codes"""
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429
    INTERNAL_SERVER_ERROR = 500
    SERVICE_UNAVAILABLE = 503


# API Rate Limits
class RateLimit:
    """Rate limit configurations"""
    DEFAULT_PER_MINUTE = 60
    DEFAULT_PER_HOUR = 1000
    DEFAULT_PER_DAY = 10000
    
    ANALYSIS_PER_MINUTE = 10
    ANALYSIS_PER_HOUR = 100
    
    SEARCH_PER_MINUTE = 30
    SEARCH_PER_HOUR = 500


# Cache TTL (in seconds)
class CacheTTL:
    """Cache time-to-live values"""
    SHORT = 300      # 5 minutes
    MEDIUM = 1800    # 30 minutes
    LONG = 3600      # 1 hour
    VERY_LONG = 86400  # 24 hours
    
    AI_ANALYSIS = LONG
    THREAT_DATA = MEDIUM
    FEED_DATA = VERY_LONG


# File Upload Limits
class FileUpload:
    """File upload restrictions"""
    MAX_SIZE_MB = 10
    MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024
    
    ALLOWED_EXTENSIONS = ['.txt', '.csv', '.json', '.xml', '.log']
    ALLOWED_MIME_TYPES = [
        'text/plain',
        'text/csv',
        'application/json',
        'application/xml',
        'text/xml'
    ]


# Regex Patterns
class RegexPatterns:
    """Common regex patterns for validation"""
    IPV4 = r'^(\d{1,3}\.){3}\d{1,3}$'
    IPV6 = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'
    DOMAIN = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    EMAIL = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    MD5 = r'^[a-f0-9]{32}$'
    SHA1 = r'^[a-f0-9]{40}$'
    SHA256 = r'^[a-f0-9]{64}$'
    CVE = r'^CVE-\d{4}-\d{4,}$'


# Color Schemes
class Colors:
    """Color codes for UI elements"""
    CRITICAL = "#FF0000"  # Red
    HIGH = "#FF6B00"      # Orange
    MEDIUM = "#FFA500"    # Yellow-Orange
    LOW = "#FFD700"       # Yellow
    SAFE = "#00FF00"      # Green
    UNKNOWN = "#808080"   # Gray
    
    # UI Colors
    PRIMARY = "#667eea"
    SECONDARY = "#764ba2"
    SUCCESS = "#00c851"
    WARNING = "#ffbb33"
    ERROR = "#ff4444"
    INFO = "#33b5e5"


# Default Pagination
class Pagination:
    """Pagination defaults"""
    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE = 1000
    DEFAULT_PAGE = 1


# Threat Intelligence Sources
THREAT_SOURCES = {
    "abuseipdb": {
        "name": "AbuseIPDB",
        "type": "IP Reputation",
        "url": "https://www.abuseipdb.com",
        "requires_key": True
    },
    "otx": {
        "name": "AlienVault OTX",
        "type": "Multi-source IOCs",
        "url": "https://otx.alienvault.com",
        "requires_key": True
    },
    "urlhaus": {
        "name": "URLhaus",
        "type": "Malware URLs",
        "url": "https://urlhaus.abuse.ch",
        "requires_key": False
    },
    "phishtank": {
        "name": "PhishTank",
        "type": "Phishing URLs",
        "url": "https://www.phishtank.com",
        "requires_key": False
    }
}


# Error Messages
class ErrorMessages:
    """Common error messages"""
    INVALID_INPUT = "Invalid input provided"
    UNAUTHORIZED = "Authentication required"
    FORBIDDEN = "Insufficient permissions"
    NOT_FOUND = "Resource not found"
    RATE_LIMIT = "Rate limit exceeded"
    SERVER_ERROR = "Internal server error"
    SERVICE_UNAVAILABLE = "Service temporarily unavailable"
    
    INVALID_IP = "Invalid IP address format"
    INVALID_DOMAIN = "Invalid domain name"
    INVALID_URL = "Invalid URL format"
    INVALID_HASH = "Invalid hash format"
    INVALID_EMAIL = "Invalid email address"


# Success Messages
class SuccessMessages:
    """Common success messages"""
    CREATED = "Resource created successfully"
    UPDATED = "Resource updated successfully"
    DELETED = "Resource deleted successfully"
    ANALYZED = "Analysis completed successfully"
    IMPORTED = "Data imported successfully"


# Export Formats
class ExportFormat:
    """Supported export formats"""
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    EXCEL = "xlsx"
    XML = "xml"
    
    ALL = [JSON, CSV, PDF, EXCEL, XML]