"""
Mock Responses for Testing
Simulated API and AI responses for unit tests
"""

from typing import Dict, List


# OpenAI Mock Responses
MOCK_AI_URL_ANALYSIS = {
    "threat_level": "CRITICAL",
    "confidence": 0.94,
    "indicators": [
        "Typosquatting detected (paypa1 vs paypal)",
        "Suspicious TLD (.tk is free domain)",
        "Known phishing pattern",
        "No HTTPS encryption"
    ],
    "threat_type": "phishing",
    "explanation": "This URL impersonates PayPal using a lookalike domain. The .tk TLD is commonly used for phishing. BLOCK IMMEDIATELY.",
    "recommendations": [
        "Block URL immediately",
        "Add to blacklist",
        "Alert users about phishing campaign",
        "Report to PhishTank"
    ]
}

MOCK_AI_IP_ANALYSIS = {
    "threat_level": "HIGH",
    "confidence": 0.88,
    "indicators": [
        "High abuse confidence score",
        "Known botnet IP",
        "Multiple C2 connections",
        "Originating from high-risk country"
    ],
    "threat_types": ["botnet", "c2_server", "malware_distribution"],
    "explanation": "This IP address is part of an active botnet network. It has been reported 47 times for malicious activity including C2 communications.",
    "recommendations": [
        "Block IP at firewall",
        "Monitor for similar IPs from same ASN",
        "Check for compromised internal systems",
        "Report to AbuseIPDB"
    ]
}

MOCK_AI_HASH_ANALYSIS = {
    "threat_level": "CRITICAL",
    "confidence": 0.92,
    "indicators": [
        "Known malware signature",
        "Matches Emotet family",
        "Distributed via phishing emails",
        "Persistence mechanisms detected"
    ],
    "malware_family": "Emotet",
    "explanation": "This file hash matches a known Emotet trojan variant. Emotet is a banking trojan that also acts as a malware loader.",
    "iocs": [
        "Registry modifications",
        "Network connections to C2 servers",
        "Process injection techniques",
        "Credential harvesting"
    ],
    "recommendations": [
        "Quarantine all instances immediately",
        "Perform full malware scan",
        "Reset compromised credentials",
        "Monitor for lateral movement",
        "Block associated C2 IPs"
    ]
}

MOCK_AI_CORRELATION = {
    "campaign_detected": True,
    "confidence": 0.89,
    "campaign_name": "APT-2024-001 - Operation Dark Web",
    "attack_pattern": "T1566.001 - Spearphishing Attachment (MITRE ATT&CK)",
    "threat_actor": "APT28 (Suspected)",
    "relationships": [
        {
            "source": "phishing_url",
            "target": "malware_hash",
            "relationship": "drops",
            "confidence": 0.92
        },
        {
            "source": "malware_hash",
            "target": "c2_ip",
            "relationship": "communicates_with",
            "confidence": 0.88
        }
    ],
    "explanation": "Analysis indicates these indicators are part of a coordinated APT campaign. The attack chain follows typical APT28 TTPs including spearphishing, malware deployment, and C2 communication.",
    "recommendations": [
        "Implement threat hunting for similar patterns",
        "Review email security controls",
        "Block all related IOCs",
        "Increase monitoring for APT28 TTPs",
        "Coordinate with threat intelligence teams"
    ]
}

MOCK_AI_NL_SEARCH = {
    "understood_query": "Find all phishing threats from Russia in the last week",
    "filters_applied": {
        "threat_type": "phishing",
        "country": "RU",
        "date_range": "last_7_days",
        "severity": ["HIGH", "CRITICAL"]
    },
    "matching_threats": ["url_phishing_001", "domain_phishing_002"],
    "insights": [
        "2 phishing campaigns identified from Russian infrastructure",
        "Both targeting financial services",
        "Increased activity in last 48 hours"
    ],
    "summary": "Found 2 high-severity phishing threats originating from Russia in the past week. Both are targeting financial services and show increased activity.",
    "follow_up_questions": [
        "Show me the associated IOCs for these threats",
        "What are the target industries?",
        "Find similar campaigns from other countries"
    ]
}


# Threat Feed Mock Responses
MOCK_ABUSEIPDB_RESPONSE = {
    "data": [
        {
            "ipAddress": "45.76.123.45",
            "abuseConfidenceScore": 88,
            "totalReports": 47,
            "numDistinctUsers": 15,
            "lastReportedAt": "2024-01-15T12:00:00Z",
            "countryCode": "RU",
            "countryName": "Russian Federation",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example Hosting",
            "domain": "example.com",
            "isWhitelisted": False,
            "isTor": False
        }
    ]
}

MOCK_OTX_PULSE_RESPONSE = {
    "results": [
        {
            "id": "pulse123",
            "name": "Russian APT Campaign",
            "description": "Active APT campaign targeting financial sector",
            "created": "2024-01-15T08:00:00Z",
            "modified": "2024-01-15T14:00:00Z",
            "author_name": "ThreatAnalyst",
            "tlp": "white",
            "tags": ["apt", "russia", "financial"],
            "references": ["https://example.com/report"],
            "indicators": [
                {
                    "type": "IPv4",
                    "indicator": "45.76.123.45",
                    "description": "C2 Server",
                    "created": "2024-01-15T08:00:00Z",
                    "is_active": True
                },
                {
                    "type": "domain",
                    "indicator": "evil-cdn.ru",
                    "description": "Malware distribution",
                    "created": "2024-01-15T08:00:00Z",
                    "is_active": True
                }
            ]
        }
    ]
}

MOCK_URLHAUS_RESPONSE = {
    "urls": [
        {
            "id": "12345",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
            "url": "http://malware-download.xyz/payload.exe",
            "url_status": "online",
            "threat": "malware_download",
            "date_added": "2024-01-14T11:20:00Z",
            "reporter": "security_analyst",
            "larted": True,
            "takedown_time_seconds": None,
            "tags": ["Emotet", "exe"],
            "payloads": [
                {
                    "firstseen": "2024-01-14T11:20:00Z",
                    "filename": "payload.exe",
                    "file_type": "exe",
                    "response_size": 524288,
                    "response_md5": "abc123def456",
                    "response_sha256": "a3f5b8c9d2e1f4a7b6c5d8e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
                    "signature": "Emotet",
                    "virustotal": {"result": "45/70"}
                }
            ]
        }
    ]
}

MOCK_PHISHTANK_RESPONSE = [
    {
        "phish_id": "8901234",
        "url": "http://paypa1-secure.tk/login",
        "phish_detail_url": "http://www.phishtank.com/phish_detail.php?phish_id=8901234",
        "submission_time": "2024-01-15T10:30:00Z",
        "verification_time": "2024-01-15T10:45:00Z",
        "online": "yes",
        "verified": "yes",
        "target": "PayPal"
    }
]


# API Response Templates
def get_mock_threat_response(threat_id: str = "test_threat_001") -> Dict:
    """Generate mock threat response"""
    return {
        "threat_id": threat_id,
        "threat_type": "url",
        "value": "http://test.com",
        "threat_level": "MEDIUM",
        "confidence": 0.75,
        "first_seen": "2024-01-15T10:00:00Z",
        "last_seen": "2024-01-15T12:00:00Z",
        "metadata": {
            "source": "test",
            "tags": ["test", "sample"]
        }
    }


def get_mock_analysis_response() -> Dict:
    """Generate mock analysis response"""
    return MOCK_AI_URL_ANALYSIS


def get_mock_search_results() -> Dict:
    """Generate mock search results"""
    return {
        "query": "test query",
        "total_results": 2,
        "results": [
            get_mock_threat_response("threat_001"),
            get_mock_threat_response("threat_002")
        ]
    }


def get_mock_graph_data() -> Dict:
    """Generate mock graph data"""
    return {
        "nodes": [
            {"id": "ip_001", "type": "ip_address", "label": "192.168.1.1", "threat_level": "HIGH"},
            {"id": "domain_001", "type": "domain", "label": "evil.com", "threat_level": "CRITICAL"}
        ],
        "edges": [
            {"source": "ip_001", "target": "domain_001", "relationship": "hosts"}
        ]
    }


# Error Responses
MOCK_API_ERROR = {
    "error": "Internal server error",
    "detail": "An unexpected error occurred",
    "status_code": 500
}

MOCK_VALIDATION_ERROR = {
    "detail": [
        {
            "loc": ["body", "url"],
            "msg": "field required",
            "type": "value_error.missing"
        }
    ]
}

MOCK_NOT_FOUND = {
    "error": "Resource not found",
    "detail": "The requested threat was not found",
    "status_code": 404
}

MOCK_UNAUTHORIZED = {
    "error": "Unauthorized",
    "detail": "Invalid or missing API key",
    "status_code": 401
}


# Helper Functions
def get_mock_response_by_type(response_type: str) -> Dict:
    """
    Get mock response by type
    
    Args:
        response_type: Type of response to return
        
    Returns:
        Mock response dictionary
    """
    responses = {
        "url_analysis": MOCK_AI_URL_ANALYSIS,
        "ip_analysis": MOCK_AI_IP_ANALYSIS,
        "hash_analysis": MOCK_AI_HASH_ANALYSIS,
        "correlation": MOCK_AI_CORRELATION,
        "nl_search": MOCK_AI_NL_SEARCH,
        "abuseipdb": MOCK_ABUSEIPDB_RESPONSE,
        "otx": MOCK_OTX_PULSE_RESPONSE,
        "urlhaus": MOCK_URLHAUS_RESPONSE,
        "phishtank": MOCK_PHISHTANK_RESPONSE,
        "error": MOCK_API_ERROR,
        "not_found": MOCK_NOT_FOUND,
        "unauthorized": MOCK_UNAUTHORIZED
    }
    
    return responses.get(response_type, {})