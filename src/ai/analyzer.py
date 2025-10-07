"""
AI Threat Analyzer
OpenAI-powered threat intelligence analysis
"""

import openai
from typing import Dict, List, Optional
from datetime import datetime
import json
import re
from src.config.settings import get_settings


class ThreatAnalyzer:
    """AI-powered threat analyzer using OpenAI"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize ThreatAnalyzer
        
        Args:
            api_key: OpenAI API key (uses settings if not provided)
        """
        settings = get_settings()
        self.api_key = api_key or settings.OPENAI_API_KEY
        
        if not self.api_key:
            raise ValueError("OpenAI API key not provided")
        
        self.client = openai.OpenAI(api_key=self.api_key)
        self.model = settings.OPENAI_MODEL
    
    async def analyze_url(self, url: str) -> Dict:
        """
        Analyze URL for threats using AI
        
        Args:
            url: URL to analyze
            
        Returns:
            Analysis results dictionary
        """
        prompt = f"""Analyze this URL for potential security threats:

URL: {url}

Provide a detailed security analysis including:
1. Threat Level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
2. Confidence Score (0.0 to 1.0)
3. Threat Type (phishing, malware, typosquatting, etc.)
4. Specific Red Flags/Indicators
5. Detailed Explanation
6. Recommended Actions

Focus on:
- Typosquatting (similar to known brands)
- Suspicious TLDs (.tk, .ml, .ga, .cf, etc.)
- Keywords often used in phishing (verify, secure, login, account, update)
- URL patterns indicating malicious intent
- Known malicious patterns

Respond in JSON format:
{{
    "threat_level": "HIGH|MEDIUM|LOW|SAFE|CRITICAL",
    "confidence": 0.95,
    "threat_type": "phishing",
    "indicators": ["indicator1", "indicator2"],
    "explanation": "detailed explanation",
    "recommendations": ["action1", "action2"]
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in threat intelligence analysis. Provide accurate, actionable threat assessments."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            
            content = response.choices[0].message.content
            
            # Parse JSON response
            result = self._parse_json_response(content)
            
            # Add metadata
            result['url'] = url
            result['analyzed_at'] = datetime.now().isoformat()
            result['analysis_type'] = 'url_analysis'
            
            return result
            
        except Exception as e:
            print(f"❌ OpenAI API Error: {str(e)}")
            # Return fallback analysis
            return self._fallback_url_analysis(url)
    
    async def analyze_ip(self, ip_address: str, context: Optional[Dict] = None) -> Dict:
        """
        Analyze IP address for threats
        
        Args:
            ip_address: IP address to analyze
            context: Additional context
            
        Returns:
            Analysis results
        """
        context_str = json.dumps(context) if context else "No additional context"
        
        prompt = f"""Analyze this IP address for security threats:

IP Address: {ip_address}
Context: {context_str}

Provide analysis including:
1. Threat Level
2. Confidence Score
3. Threat Type (botnet, C2, scanner, etc.)
4. Geographic/ASN concerns
5. Known malicious activity
6. Recommendations

Respond in JSON format with: threat_level, confidence, threat_type, indicators, explanation, recommendations"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing IP addresses for threats."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=800
            )
            
            content = response.choices[0].message.content
            result = self._parse_json_response(content)
            
            result['ip_address'] = ip_address
            result['analyzed_at'] = datetime.now().isoformat()
            result['analysis_type'] = 'ip_analysis'
            
            return result
            
        except Exception as e:
            print(f"❌ OpenAI API Error: {str(e)}")
            return self._fallback_ip_analysis(ip_address)
    
    async def analyze_file_hash(
        self,
        file_hash: str,
        hash_type: str = "sha256",
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze file hash for malware
        
        Args:
            file_hash: File hash value
            hash_type: Type of hash
            context: Additional context
            
        Returns:
            Analysis results
        """
        context_str = json.dumps(context) if context else "No additional context"
        
        prompt = f"""Analyze this file hash for malware:

Hash: {file_hash}
Type: {hash_type}
Context: {context_str}

Provide malware analysis including:
1. Threat Level
2. Confidence Score
3. Malware Family (if known)
4. Indicators of Compromise
5. Behavioral analysis
6. Recommendations

Respond in JSON format."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a malware analyst expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=800
            )
            
            content = response.choices[0].message.content
            result = self._parse_json_response(content)
            
            result['file_hash'] = file_hash
            result['hash_type'] = hash_type
            result['analyzed_at'] = datetime.now().isoformat()
            result['analysis_type'] = 'hash_analysis'
            
            return result
            
        except Exception as e:
            print(f"❌ OpenAI API Error: {str(e)}")
            return self._fallback_hash_analysis(file_hash, hash_type)
    
    async def correlate_threats(self, threats: List[Dict]) -> Dict:
        """
        Correlate multiple threats to find campaigns
        
        Args:
            threats: List of threat indicators
            
        Returns:
            Correlation analysis
        """
        threats_str = json.dumps(threats, indent=2)
        
        prompt = f"""Analyze these threat indicators for correlations and campaigns:

Threats:
{threats_str}

Identify:
1. Are these threats related?
2. Do they form a campaign?
3. Attack pattern/TTPs
4. Attribution indicators
5. Threat actor characteristics
6. Recommendations

Respond in JSON format."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a threat intelligence analyst expert in APT campaigns."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1200
            )
            
            content = response.choices[0].message.content
            result = self._parse_json_response(content)
            
            result['analyzed_threats'] = len(threats)
            result['analyzed_at'] = datetime.now().isoformat()
            result['analysis_type'] = 'correlation_analysis'
            
            return result
            
        except Exception as e:
            print(f"❌ OpenAI API Error: {str(e)}")
            return self._fallback_correlation_analysis(threats)
    
    def _parse_json_response(self, content: str) -> Dict:
        """Parse JSON from AI response"""
        try:
            # Try direct JSON parse
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            
            # Try to extract any JSON object
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
            
            # Fallback: return structured error
            return {
                "threat_level": "UNKNOWN",
                "confidence": 0.0,
                "threat_type": "unknown",
                "indicators": [],
                "explanation": "Failed to parse AI response",
                "recommendations": ["Manual analysis required"]
            }
    
    def _fallback_url_analysis(self, url: str) -> Dict:
        """Fallback URL analysis without AI"""
        indicators = []
        threat_level = "MEDIUM"
        confidence = 0.6
        
        # Check for typosquatting patterns
        typo_patterns = ['paypa1', 'amaz0n', 'g00gle', 'micros0ft', 'fac3book']
        if any(pattern in url.lower() for pattern in typo_patterns):
            indicators.append("Potential typosquatting detected")
            threat_level = "HIGH"
            confidence = 0.8
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        if any(url.endswith(tld) for tld in suspicious_tlds):
            indicators.append("Suspicious TLD (free/disposable domain)")
            threat_level = "HIGH"
            confidence = 0.85
        
        # Check for phishing keywords
        phishing_keywords = ['verify', 'secure', 'login', 'account', 'update', 'confirm']
        if any(keyword in url.lower() for keyword in phishing_keywords):
            indicators.append("Contains phishing-related keywords")
        
        return {
            "url": url,
            "threat_level": threat_level,
            "confidence": confidence,
            "threat_type": "potential_phishing",
            "indicators": indicators if indicators else ["No obvious threats detected"],
            "explanation": "Basic pattern-based analysis (OpenAI unavailable)",
            "recommendations": ["Perform deeper manual analysis", "Check URL reputation services"],
            "analyzed_at": datetime.now().isoformat(),
            "analysis_type": "url_analysis",
            "fallback": True
        }
    
    def _fallback_ip_analysis(self, ip_address: str) -> Dict:
        """Fallback IP analysis without AI"""
        return {
            "ip_address": ip_address,
            "threat_level": "MEDIUM",
            "confidence": 0.5,
            "threat_type": "unknown",
            "indicators": ["Analysis requires OpenAI API"],
            "explanation": "Basic analysis only (OpenAI unavailable)",
            "recommendations": ["Check IP reputation services", "Verify with threat feeds"],
            "analyzed_at": datetime.now().isoformat(),
            "analysis_type": "ip_analysis",
            "fallback": True
        }
    
    def _fallback_hash_analysis(self, file_hash: str, hash_type: str) -> Dict:
        """Fallback hash analysis without AI"""
        return {
            "file_hash": file_hash,
            "hash_type": hash_type,
            "threat_level": "MEDIUM",
            "confidence": 0.5,
            "threat_type": "unknown",
            "indicators": ["Analysis requires OpenAI API"],
            "explanation": "Basic analysis only (OpenAI unavailable)",
            "recommendations": ["Submit to VirusTotal", "Check malware databases"],
            "analyzed_at": datetime.now().isoformat(),
            "analysis_type": "hash_analysis",
            "fallback": True
        }
    
    def _fallback_correlation_analysis(self, threats: List[Dict]) -> Dict:
        """Fallback correlation analysis without AI"""
        return {
            "campaign_detected": False,
            "confidence": 0.0,
            "analyzed_threats": len(threats),
            "indicators": ["Correlation analysis requires OpenAI API"],
            "explanation": "Cannot perform correlation without AI",
            "recommendations": ["Manual correlation analysis required"],
            "analyzed_at": datetime.now().isoformat(),
            "analysis_type": "correlation_analysis",
            "fallback": True
        }