ThreatScope API Documentation
Base URL
http://localhost:8000
Authentication
API authentication uses API keys passed in the X-API-Key header.

bash
curl -H "X-API-Key: your_api_key_here" http://localhost:8000/api/threats
Rate Limits
Default: 60 requests/minute
Analysis: 10 requests/minute
Search: 30 requests/minute
Response Format
All responses follow this structure:

json
{
  "data": {},
  "error": null,
  "status_code": 200
}
Endpoints
Health & Status
GET /health
Get system health status.

Response:

json
{
  "status": "healthy",
  "components": {
    "threat_graph": {
      "status": "operational",
      "stats": {
        "total_nodes": 1523,
        "total_edges": 847
      }
    },
    "malware_filter": {
      "status": "operational",
      "stats": {
        "malware_hashes": 10243
      }
    }
  }
}
GET /stats
Get platform statistics.

Response:

json
{
  "graph": {
    "total_nodes": 1523,
    "total_edges": 847,
    "avg_degree": 1.11
  },
  "malware_filter": {
    "malware_hashes": 10243,
    "size_mb": 1.5
  }
}
Analysis Endpoints
POST /api/analyze/url
Analyze a URL for threats.

Request:

json
{
  "url": "http://paypa1-secure.tk/login"
}
Response:

json
{
  "url": "http://paypa1-secure.tk/login",
  "threat_level": "CRITICAL",
  "confidence": 0.94,
  "indicators": [
    "Typosquatting detected (paypa1 vs paypal)",
    "Suspicious TLD (.tk is free domain)",
    "Known phishing pattern"
  ],
  "threat_type": "phishing",
  "explanation": "This URL impersonates PayPal using a lookalike domain...",
  "recommendations": [
    "Block URL immediately",
    "Add to blacklist",
    "Alert users about phishing campaign"
  ],
  "analyzed_at": "2024-01-15T12:30:00Z",
  "from_cache": false
}
POST /api/analyze/ip
Analyze an IP address.

Request:

json
{
  "ip_address": "45.76.123.45",
  "context": {
    "country": "RU",
    "asn": "AS12345"
  }
}
Response:

json
{
  "ip_address": "45.76.123.45",
  "threat_level": "HIGH",
  "confidence": 0.88,
  "indicators": [
    "High abuse confidence score",
    "Known botnet IP",
    "Multiple C2 connections"
  ],
  "threat_types": ["botnet", "c2_server"],
  "explanation": "This IP address is part of an active botnet network...",
  "recommendations": [
    "Block IP at firewall",
    "Monitor for similar IPs"
  ],
  "analyzed_at": "2024-01-15T12:30:00Z"
}
POST /api/analyze/hash
Analyze a file hash.

Request:

json
{
  "file_hash": "a3f5b8c9d2e1f4a7b6c5d8e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
  "hash_type": "sha256",
  "context": {
    "filename": "document.exe",
    "file_size": "524288"
  }
}
Response:

json
{
  "file_hash": "a3f5b8c9d2e1f4a7b6c5d8e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
  "hash_type": "sha256",
  "threat_level": "CRITICAL",
  "confidence": 0.92,
  "indicators": [
    "Known malware signature",
    "Matches Emotet family"
  ],
  "malware_family": "Emotet",
  "explanation": "This file hash matches a known Emotet trojan variant...",
  "iocs": [
    "Registry modifications",
    "Network connections to C2 servers"
  ],
  "recommendations": [
    "Quarantine all instances immediately",
    "Perform full malware scan"
  ],
  "analyzed_at": "2024-01-15T12:30:00Z"
}
POST /api/analyze/correlate
Analyze correlation between multiple threats.

Request:

json
{
  "threats": [
    {"type": "ip", "value": "45.76.123.45"},
    {"type": "domain", "value": "evil.com"},
    {"type": "url", "value": "http://evil.com/malware"}
  ]
}
Response:

json
{
  "campaign_detected": true,
  "confidence": 0.89,
  "campaign_name": "APT-2024-001 - Operation Dark Web",
  "attack_pattern": "T1566.001 - Spearphishing Attachment",
  "threat_actor": "APT28 (Suspected)",
  "relationships": [
    {
      "source": "ip",
      "target": "domain",
      "relationship": "hosts",
      "confidence": 0.92
    }
  ],
  "explanation": "Analysis indicates these indicators are part of a coordinated APT campaign...",
  "recommendations": [
    "Implement threat hunting for similar patterns",
    "Block all related IOCs"
  ],
  "threats_analyzed": 3,
  "analyzed_at": "2024-01-15T12:30:00Z"
}
Threat Management
GET /api/threats
List all threats with optional filters.

Query Parameters:

threat_type (optional): Filter by type (ip_address, domain, url, file_hash)
threat_level (optional): Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
limit (default: 100): Max results
offset (default: 0): Pagination offset
Response:

json
{
  "total": 1523,
  "limit": 100,
  "offset": 0,
  "threats": [
    {
      "threat_id": "url_paypa1-secure.tk",
      "threat_type": "url",
      "value": "paypa1-secure.tk/login",
      "threat_level": "CRITICAL",
      "confidence": 0.94,
      "first_seen": "2024-01-15T10:30:00Z"
    }
  ]
}
GET /api/threats/{threat_id}
Get a specific threat by ID.

Response:

json
{
  "threat_id": "url_paypa1-secure.tk",
  "threat_type": "url",
  "value": "paypa1-secure.tk/login",
  "threat_level": "CRITICAL",
  "confidence": 0.94,
  "first_seen": "2024-01-15T10:30:00Z",
  "last_seen": "2024-01-15T12:45:00Z",
  "metadata": {
    "typosquatting": true,
    "suspicious_tld": true,
    "tags": ["phishing", "financial"]
  }
}
POST /api/threats
Create a new threat.

Request:

json
{
  "threat_type": "url",
  "value": "http://malicious-site.com",
  "threat_level": "HIGH",
  "confidence": 0.85,
  "metadata": {
    "source": "manual_report",
    "tags": ["phishing"]
  }
}
Response:

json
{
  "threat_id": "url_malicious-site.com",
  "threat_type": "url",
  "value": "http://malicious-site.com",
  "threat_level": "HIGH",
  "confidence": 0.85,
  "created_at": "2024-01-15T12:30:00Z"
}
GET /api/threats/{threat_id}/related
Get related threats.

Query Parameters:

depth (default: 1): Relationship depth (1-5)
min_confidence (default: 0.0): Minimum confidence (0.0-1.0)
Response:

json
{
  "threat_id": "url_paypa1-secure.tk",
  "depth": 2,
  "total_related": 5,
  "related_threats": [
    {
      "threat_id": "ip_45.76.123.45",
      "threat_type": "ip_address",
      "value": "45.76.123.45",
      "relation": "hosts",
      "confidence": 0.95,
      "distance": 1
    }
  ]
}
GET /api/threats/stats/summary
Get threat statistics summary.

Response:

json
{
  "total_threats": 15247,
  "by_severity": {
    "CRITICAL": 23,
    "HIGH": 156,
    "MEDIUM": 892,
    "LOW": 3421
  },
  "by_type": {
    "ip_address": 5234,
    "domain": 4123,
    "url": 3456,
    "file_hash": 2134
  },
  "active_campaigns": 7,
  "last_updated": "2024-01-15T12:30:00Z"
}
Search Endpoints
POST /api/search
Natural language threat search.

Request:

json
{
  "query": "Show me all phishing threats from Russia",
  "limit": 50
}
Response:

json
{
  "query": "Show me all phishing threats from Russia",
  "understood_as": "Finding phishing threats from Russia",
  "total_results": 12,
  "results": [
    {
      "threat_id": "url_phishing_001",
      "threat_type": "url",
      "value": "http://phish-site.ru",
      "threat_level": "HIGH"
    }
  ],
  "filters_applied": {
    "threat_type": "phishing",
    "country": "Russia"
  },
  "summary": "Found 12 phishing threats from Russia",
  "follow_up_suggestions": [
    "Show me related IP addresses",
    "Find similar phishing campaigns"
  ]
}
GET /api/search/ioc/{ioc_value}
Search for a specific IOC.

Response:

json
{
  "ioc_value": "45.76.123.45",
  "detected_type": "ip_address",
  "threat_level": "HIGH",
  "confidence": 0.85,
  "first_seen": "2024-01-10T08:00:00Z",
  "last_seen": "2024-01-15T12:00:00Z",
  "occurrences": 47,
  "related_threats": 12,
  "campaigns": ["APT-2024-001"],
  "recommended_action": "Block and monitor"
}
GET /api/search/campaigns
Search threat campaigns.

Query Parameters:

name (optional): Campaign name pattern
threat_actor (optional): Filter by threat actor
active_only (default: true): Only show active campaigns
Response:

json
{
  "total_campaigns": 7,
  "campaigns": [
    {
      "campaign_id": "APT-2024-001",
      "name": "Operation Dark Web",
      "threat_actor": "APT28",
      "attack_pattern": "Spear Phishing + Malware",
      "total_iocs": 156,
      "first_seen": "2024-01-01T00:00:00Z",
      "is_active": true,
      "affected_sectors": ["Finance", "Healthcare"]
    }
  ]
}
Error Responses
400 Bad Request
json
{
  "error": "Invalid input provided",
  "detail": "URL format is invalid",
  "status_code": 400
}
401 Unauthorized
json
{
  "error": "Unauthorized",
  "detail": "Invalid or missing API key",
  "status_code": 401
}
404 Not Found
json
{
  "error": "Resource not found",
  "detail": "Threat with ID 'xyz' was not found",
  "status_code": 404
}
429 Too Many Requests
json
{
  "error": "Rate limit exceeded",
  "detail": "Maximum 60 requests per minute",
  "status_code": 429
}
500 Internal Server Error
json
{
  "error": "Internal server error",
  "detail": "An unexpected error occurred",
  "status_code": 500
}
Code Examples
Python
python
import requests

API_BASE = "http://localhost:8000"
API_KEY = "your_api_key"

headers = {"X-API-Key": API_KEY}

# Analyze URL
response = requests.post(
    f"{API_BASE}/api/analyze/url",
    json={"url": "http://suspicious-site.com"},
    headers=headers
)

result = response.json()
print(f"Threat Level: {result['threat_level']}")
cURL
bash
# Analyze URL
curl -X POST "http://localhost:8000/api/analyze/url" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{"url": "http://suspicious-site.com"}'

# List threats
curl "http://localhost:8000/api/threats?threat_level=CRITICAL&limit=10" \
  -H "X-API-Key: your_api_key"
JavaScript
javascript
const API_BASE = "http://localhost:8000";
const API_KEY = "your_api_key";

async function analyzeURL(url) {
  const response = await fetch(`${API_BASE}/api/analyze/url`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY
    },
    body: JSON.stringify({ url })
  });
  
  return await response.json();
}

// Usage
analyzeURL("http://suspicious-site.com")
  .then(result => console.log(result.threat_level));
Interactive API Documentation
Visit /docs for interactive Swagger UI documentation:

http://localhost:8000/docs
Visit /redoc for alternative ReDoc documentation:

http://localhost:8000/redoc
