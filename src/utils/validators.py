"""
Input Validators
Validation functions for threat indicators and inputs
"""

import re
import validators
from typing import Optional, Tuple
from urllib.parse import urlparse


def is_valid_ip(ip: str) -> bool:
    """
    Validate IP address (IPv4 or IPv6)
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IP
    """
    # IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    # IPv6
    return validators.ipv6(ip)


def is_valid_domain(domain: str) -> bool:
    """
    Validate domain name
    
    Args:
        domain: Domain name
        
    Returns:
        True if valid domain
    """
    return validators.domain(domain)


def is_valid_url(url: str) -> bool:
    """
    Validate URL
    
    Args:
        url: URL string
        
    Returns:
        True if valid URL
    """
    return validators.url(url)


def is_valid_email(email: str) -> bool:
    """
    Validate email address
    
    Args:
        email: Email address
        
    Returns:
        True if valid email
    """
    return validators.email(email)


def is_valid_hash(hash_value: str, hash_type: str = None) -> Tuple[bool, Optional[str]]:
    """
    Validate file hash and detect type
    
    Args:
        hash_value: Hash string
        hash_type: Expected hash type (md5, sha1, sha256) or None to auto-detect
        
    Returns:
        Tuple of (is_valid, detected_type)
    """
    hash_value = hash_value.lower().strip()
    
    # Hash patterns
    patterns = {
        'md5': (r'^[a-f0-9]{32}$', 32),
        'sha1': (r'^[a-f0-9]{40}$', 40),
        'sha256': (r'^[a-f0-9]{64}$', 64)
    }
    
    if hash_type:
        # Validate specific type
        if hash_type.lower() in patterns:
            pattern, length = patterns[hash_type.lower()]
            if re.match(pattern, hash_value) and len(hash_value) == length:
                return True, hash_type.lower()
        return False, None
    else:
        # Auto-detect type
        for htype, (pattern, length) in patterns.items():
            if re.match(pattern, hash_value) and len(hash_value) == length:
                return True, htype
        return False, None


def is_valid_cve(cve: str) -> bool:
    """
    Validate CVE identifier
    
    Args:
        cve: CVE identifier (e.g., CVE-2024-1234)
        
    Returns:
        True if valid CVE
    """
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve.upper()))


def sanitize_url(url: str) -> str:
    """
    Sanitize and normalize URL
    
    Args:
        url: URL to sanitize
        
    Returns:
        Sanitized URL
    """
    url = url.strip()
    
    # Add http:// if no scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    return url


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL
    
    Args:
        url: URL string
        
    Returns:
        Domain name or None
    """
    try:
        parsed = urlparse(sanitize_url(url))
        return parsed.netloc
    except:
        return None


def is_private_ip(ip: str) -> bool:
    """
    Check if IP is private/internal
    
    Args:
        ip: IP address
        
    Returns:
        True if private IP
    """
    if not is_valid_ip(ip):
        return False
    
    # Private IP ranges
    private_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^169\.254\.',
        r'^::1$',
        r'^fc00:',
        r'^fd00:'
    ]
    
    return any(re.match(pattern, ip) for pattern in private_patterns)


def validate_threat_level(level: str) -> bool:
    """
    Validate threat severity level
    
    Args:
        level: Severity level
        
    Returns:
        True if valid level
    """
    valid_levels = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    return level.upper() in valid_levels


def validate_confidence_score(score: float) -> bool:
    """
    Validate confidence score
    
    Args:
        score: Confidence score
        
    Returns:
        True if valid (0.0 to 1.0)
    """
    return 0.0 <= score <= 1.0


def detect_ioc_type(ioc: str) -> str:
    """
    Auto-detect IOC type
    
    Args:
        ioc: Indicator of Compromise
        
    Returns:
        Detected type (ip_address, domain, url, file_hash, email, cve, unknown)
    """
    ioc = ioc.strip()
    
    # Check each type
    if is_valid_ip(ioc):
        return "ip_address"
    
    if is_valid_cve(ioc):
        return "cve"
    
    if is_valid_email(ioc):
        return "email"
    
    is_hash, hash_type = is_valid_hash(ioc)
    if is_hash:
        return "file_hash"
    
    if is_valid_url(ioc):
        return "url"
    
    if is_valid_domain(ioc):
        return "domain"
    
    return "unknown"


def validate_ioc(ioc: str, expected_type: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validate IOC and optionally check type
    
    Args:
        ioc: Indicator of Compromise
        expected_type: Expected IOC type (optional)
        
    Returns:
        Tuple of (is_valid, detected_type)
    """
    detected_type = detect_ioc_type(ioc)
    
    if detected_type == "unknown":
        return False, detected_type
    
    if expected_type and detected_type != expected_type:
        return False, detected_type
    
    return True, detected_type