"""
AI Prompt Templates
Structured prompts for OpenAI threat analysis
"""

from typing import Dict, List


class PromptTemplates:
    """Collection of AI prompt templates"""
    
    # System prompts
    SYSTEM_SECURITY_EXPERT = """You are a cybersecurity expert specializing in threat analysis and threat intelligence. 
You analyze indicators of compromise (IOCs), identify attack patterns, and provide actionable security recommendations.
Always provide clear, accurate, and actionable insights based on threat intelligence best practices."""

    SYSTEM_MALWARE_ANALYST = """You are a malware analysis expert with deep knowledge of malware families, 
attack vectors, and indicators of compromise. You analyze files, hashes, and behavioral patterns to identify 
malicious software and provide detailed threat assessments."""

    SYSTEM_THREAT_HUNTER = """You are a threat hunting specialist who excels at finding patterns in security data, 
correlating events, and identifying advanced persistent threats (APTs). You think like an attacker to anticipate 
their next moves."""

    # URL Analysis Template
    URL_ANALYSIS = """Analyze this URL for cybersecurity threats: {url}

Consider the following threat indicators:
- **Typosquatting**: Look for lookalike domains (e.g., paypa1 vs paypal, g00gle vs google)
- **Suspicious TLDs**: Free or commonly abused TLDs (.tk, .ml, .ga, .cf, .gq)
- **URL Obfuscation**: Encoding, IP addresses instead of domains, shortened URLs
- **Phishing Patterns**: Login pages, account verification, password resets
- **Malware Distribution**: File downloads, exploit kits
- **Domain Reputation**: Known malicious patterns, recently registered domains

Provide a JSON response with:
1. threat_level: one of [SAFE, LOW, MEDIUM, HIGH, CRITICAL]
2. confidence: 0.0 to 1.0
3. indicators: list of specific red flags found
4. threat_type: primary threat type (phishing, malware, scam, etc.)
5. explanation: detailed explanation of why this is/isn't malicious
6. recommendations: list of recommended actions

Be specific and cite exact indicators you found."""

    # IP Analysis Template
    IP_ANALYSIS = """Analyze this IP address for cybersecurity threats: {ip_address}

{context}

Evaluate the following:
- **Known Malicious IPs**: Check against common threat intelligence patterns
- **Geolocation Anomalies**: Suspicious or high-risk countries
- **ASN Reputation**: Autonomous System Number reputation
- **Network Behavior**: Port scanning, brute force, DDoS activities
- **Botnet Indicators**: C2 communication patterns
- **Historical Activity**: Previous incidents or reports

Provide a JSON response with:
1. threat_level: one of [SAFE, LOW, MEDIUM, HIGH, CRITICAL]
2. confidence: 0.0 to 1.0
3. indicators: list of suspicious indicators
4. threat_types: list of potential threat types
5. explanation: detailed analysis
6. recommendations: recommended defensive actions

Consider both the IP itself and any provided context."""

    # File Hash Analysis Template
    HASH_ANALYSIS = """Analyze this file hash for malware: {file_hash} ({hash_type})

{context}

Assess the following:
- **Known Malware Signatures**: Match against known malware families
- **Hash Reputation**: Check for previous incidents
- **File Characteristics**: Based on context (filename, size, type)
- **Malware Family Indicators**: Patterns suggesting specific malware
- **Distribution Methods**: How this malware typically spreads

Provide a JSON response with:
1. threat_level: one of [SAFE, LOW, MEDIUM, HIGH, CRITICAL]
2. confidence: 0.0 to 1.0
3. indicators: list of malware indicators
4. malware_family: suspected malware family name (if identifiable)
5. explanation: detailed malware analysis
6. iocs: list of related indicators of compromise
7. recommendations: recommended remediation actions

Be specific about malware behaviors and capabilities."""

    # Threat Correlation Template
    THREAT_CORRELATION = """Analyze these threat indicators for correlations and campaign patterns:

{threats_data}

Perform the following analysis:
1. **Pattern Recognition**: Identify common patterns across indicators
2. **Campaign Detection**: Determine if these are part of a coordinated attack
3. **Temporal Analysis**: Look for timing patterns
4. **Infrastructure Overlap**: Shared hosting, domains, or IPs
5. **TTPs Analysis**: Tactics, Techniques, and Procedures (MITRE ATT&CK)
6. **Attribution Indicators**: Clues about threat actors

Provide a JSON response with:
1. campaign_detected: boolean - are these part of a coordinated campaign?
2. confidence: 0.0 to 1.0
3. campaign_name: descriptive name for the campaign (if detected)
4. attack_pattern: MITRE ATT&CK pattern or custom description
5. threat_actor: suspected threat actor group (if identifiable)
6. relationships: list of specific relationships between indicators
7. explanation: detailed correlation analysis
8. recommendations: strategic recommendations for defense

Focus on actionable intelligence."""

    # Natural Language Search Template
    NL_SEARCH = """Process this threat intelligence query: "{query}"

Available threat data (sample):
{data_sample}

Task: Understand the user's intent and help them find relevant threats.

Provide a JSON response with:
1. understood_query: your interpretation of what the user is asking
2. filters_applied: specific filters you would apply (severity, type, date, etc.)
3. matching_threats: list of threat IDs that match the criteria
4. insights: key insights from the matching results
5. summary: natural language summary of findings
6. follow_up_questions: 2-3 suggested follow-up queries

Be conversational and helpful in your summary."""

    # Report Generation Template
    REPORT_GENERATION = """Generate a professional threat intelligence report for the {time_range}.

Threat data:
{threats_summary}

Create a comprehensive markdown report with:

# Executive Summary
- Brief overview of threat landscape
- Key statistics and trends
- Critical findings requiring immediate attention

# Threat Analysis
## By Severity
- Critical, High, Medium, Low threat breakdown
- Trending threats

## By Type
- Malware, Phishing, IPs, Domains, etc.
- Notable patterns

## Geographic Distribution
- Top threat source countries
- Regional patterns

# Attack Patterns & TTPs
- Common attack vectors identified
- MITRE ATT&CK techniques observed
- Emerging threat patterns

# Indicators of Compromise (IOCs)
- High-priority IOCs to block
- Organized by type

# Recommendations
1. Immediate Actions
2. Short-term Improvements
3. Long-term Strategy

# Conclusion
- Summary of threat landscape
- Outlook and predictions

Format in clean, professional markdown with clear sections and bullet points."""

    # Incident Response Template
    INCIDENT_RESPONSE = """Analyze this security incident:

{incident_data}

Provide incident response guidance:

Provide a JSON response with:
1. incident_severity: CRITICAL, HIGH, MEDIUM, or LOW
2. incident_type: type of security incident
3. affected_systems: list of potentially affected systems
4. containment_steps: immediate containment actions
5. investigation_steps: steps to investigate further
6. remediation_steps: steps to remediate the issue
7. prevention_steps: steps to prevent recurrence
8. estimated_impact: assessment of potential impact
9. timeline: suggested timeline for response

Focus on practical, actionable steps."""

    @staticmethod
    def format_url_prompt(url: str) -> str:
        """Format URL analysis prompt"""
        return PromptTemplates.URL_ANALYSIS.format(url=url)
    
    @staticmethod
    def format_ip_prompt(ip_address: str, context: str = "") -> str:
        """Format IP analysis prompt"""
        context_str = f"Additional context: {context}" if context else "No additional context available"
        return PromptTemplates.IP_ANALYSIS.format(
            ip_address=ip_address,
            context=context_str
        )
    
    @staticmethod
    def format_hash_prompt(file_hash: str, hash_type: str, context: str = "") -> str:
        """Format hash analysis prompt"""
        context_str = f"Additional context: {context}" if context else "No additional context available"
        return PromptTemplates.HASH_ANALYSIS.format(
            file_hash=file_hash,
            hash_type=hash_type,
            context=context_str
        )
    
    @staticmethod
    def format_correlation_prompt(threats_data: str) -> str:
        """Format threat correlation prompt"""
        return PromptTemplates.THREAT_CORRELATION.format(
            threats_data=threats_data
        )
    
    @staticmethod
    def format_search_prompt(query: str, data_sample: str) -> str:
        """Format natural language search prompt"""
        return PromptTemplates.NL_SEARCH.format(
            query=query,
            data_sample=data_sample
        )
    
    @staticmethod
    def format_report_prompt(time_range: str, threats_summary: str) -> str:
        """Format report generation prompt"""
        return PromptTemplates.REPORT_GENERATION.format(
            time_range=time_range,
            threats_summary=threats_summary
        )