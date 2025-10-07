"""
Analysis API Routes
Endpoints for AI-powered threat analysis
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from src.ai.analyzer import ThreatAnalyzer
from src.core.threat_graph import ThreatGraph
from datetime import datetime


router = APIRouter()


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")
    

class IPAnalysisRequest(BaseModel):
    ip_address: str = Field(..., description="IP address to analyze")
    context: Optional[Dict] = Field(None, description="Additional context")


class FileHashAnalysisRequest(BaseModel):
    file_hash: str = Field(..., description="File hash")
    hash_type: str = Field("sha256", description="Hash type (md5, sha1, sha256)")
    context: Optional[Dict] = Field(None, description="Additional context")


class ThreatCorrelationRequest(BaseModel):
    threats: List[Dict] = Field(..., description="List of threat indicators")


# Global threat graph instance (will be injected)
_threat_graph: Optional[ThreatGraph] = None


def set_threat_graph(graph: ThreatGraph):
    """Set the global threat graph instance"""
    global _threat_graph
    _threat_graph = graph


def get_threat_graph() -> ThreatGraph:
    """Get the threat graph instance"""
    if _threat_graph is None:
        raise HTTPException(status_code=500, detail="ThreatGraph not initialized")
    return _threat_graph


@router.post("/url")
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a URL for potential threats
    
    - **url**: URL to analyze
    
    Returns AI-powered threat assessment
    """
    try:
        analyzer = ThreatAnalyzer()
        result = await analyzer.analyze_url(request.url)
        
        # Add to threat graph
        try:
            graph = get_threat_graph()
            
            # Add URL node
            url_id = graph.add_threat(
                threat_type="url",
                value=request.url,
                metadata={
                    "threat_level": result.get("threat_level"),
                    "confidence": result.get("confidence"),
                    "threat_type": result.get("threat_type"),
                    "indicators": result.get("indicators", []),
                    "analyzed_at": result.get("analyzed_at")
                }
            )
            
            # Add related IOCs if present
            related_iocs = result.get("related_iocs", [])
            for ioc in related_iocs:
                ioc_type = ioc.get("type")
                ioc_value = ioc.get("value")
                
                if ioc_type and ioc_value:
                    ioc_id = graph.add_threat(
                        threat_type=ioc_type,
                        value=ioc_value,
                        metadata={"source": "ai_analysis"}
                    )
                    
                    # Link to URL
                    relation = "hosts" if ioc_type in ["ip_address", "domain"] else "related_to"
                    graph.link(url_id, ioc_id, relation, confidence=0.8)
            
            result["graph_node_id"] = url_id
            print(f"✅ Added URL to threat graph: {url_id}")
            
        except Exception as graph_error:
            print(f"⚠️ Could not add to graph: {str(graph_error)}")
            # Continue anyway, graph is optional
        
        return result
        
    except Exception as e:
        print(f"❌ Error in analyze_url: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/ip")
async def analyze_ip(request: IPAnalysisRequest):
    """
    Analyze an IP address for threats
    
    - **ip_address**: IP address to analyze
    - **context**: Optional additional context
    
    Returns threat assessment with recommendations
    """
    try:
        analyzer = ThreatAnalyzer()
        result = await analyzer.analyze_ip(request.ip_address, request.context)
        
        # Add to threat graph
        try:
            graph = get_threat_graph()
            ip_id = graph.add_threat(
                threat_type="ip_address",
                value=request.ip_address,
                metadata={
                    "threat_level": result.get("threat_level"),
                    "confidence": result.get("confidence"),
                    "threat_type": result.get("threat_type"),
                    "analyzed_at": result.get("analyzed_at")
                }
            )
            result["graph_node_id"] = ip_id
            print(f"✅ Added IP to threat graph: {ip_id}")
        except Exception as graph_error:
            print(f"⚠️ Could not add to graph: {str(graph_error)}")
        
        return result
        
    except Exception as e:
        print(f"❌ Error in analyze_ip: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/hash")
async def analyze_hash(request: FileHashAnalysisRequest):
    """
    Analyze a file hash for malware
    
    - **file_hash**: File hash value
    - **hash_type**: Type of hash (md5, sha1, sha256)
    - **context**: Optional file context
    
    Returns malware analysis results
    """
    try:
        analyzer = ThreatAnalyzer()
        result = await analyzer.analyze_file_hash(
            request.file_hash,
            request.hash_type,
            request.context
        )
        
        # Add to threat graph
        try:
            graph = get_threat_graph()
            hash_id = graph.add_threat(
                threat_type="file_hash",
                value=request.file_hash,
                metadata={
                    "hash_type": request.hash_type,
                    "threat_level": result.get("threat_level"),
                    "confidence": result.get("confidence"),
                    "analyzed_at": result.get("analyzed_at")
                }
            )
            result["graph_node_id"] = hash_id
            print(f"✅ Added hash to threat graph: {hash_id}")
        except Exception as graph_error:
            print(f"⚠️ Could not add to graph: {str(graph_error)}")
        
        return result
        
    except Exception as e:
        print(f"❌ Error in analyze_hash: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/correlate")
async def correlate_threats(request: ThreatCorrelationRequest):
    """
    Correlate multiple threat indicators to find campaigns
    
    - **threats**: List of threat indicators with type and value
    
    Returns correlation analysis and campaign detection
    """
    try:
        analyzer = ThreatAnalyzer()
        result = await analyzer.correlate_threats(request.threats)
        
        # Add campaign to graph if detected
        try:
            if result.get("campaign_detected"):
                graph = get_threat_graph()
                campaign_id = graph.add_threat(
                    threat_type="campaign",
                    value=f"campaign_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    metadata={
                        "confidence": result.get("confidence"),
                        "threat_count": len(request.threats),
                        "analyzed_at": result.get("analyzed_at")
                    }
                )
                result["graph_node_id"] = campaign_id
                print(f"✅ Added campaign to threat graph: {campaign_id}")
        except Exception as graph_error:
            print(f"⚠️ Could not add to graph: {str(graph_error)}")
        
        return result
        
    except Exception as e:
        print(f"❌ Error in correlate_threats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Correlation failed: {str(e)}")


@router.get("/demo/phishing")
async def demo_phishing_analysis():
    """
    Demo endpoint with pre-built phishing analysis
    Returns a sample analysis without calling OpenAI
    """
    demo_result = {
        "url": "paypa1-secure.tk/login",
        "threat_level": "CRITICAL",
        "confidence": 0.94,
        "threat_type": "phishing",
        "indicators": [
            "Typosquatting detected (paypa1 vs paypal)",
            "Suspicious TLD (.tk = free/disposable domain)",
            "Keyword 'secure' commonly used in phishing",
            "Login page simulation detected"
        ],
        "explanation": "This URL impersonates PayPal using character substitution (1 instead of l). The .tk domain is commonly abused for phishing campaigns due to being free and disposable. The presence of 'secure' and 'login' in the URL path is a common social engineering tactic. BLOCK IMMEDIATELY.",
        "recommendations": [
            "Block URL in firewall/proxy immediately",
            "Add domain to organizational blocklist",
            "Alert security team and end users",
            "Check for related IOCs in environment",
            "Report to anti-phishing services"
        ],
        "related_iocs": [
            {"type": "domain", "value": "paypa1-secure.tk"},
            {"type": "domain", "value": "paypal-verify.ml"},
            {"type": "ip_address", "value": "192.0.2.15"}
        ],
        "analyzed_at": datetime.now().isoformat(),
        "analysis_type": "url_analysis",
        "demo": True
    }
    
    # Add demo data to graph
    try:
        graph = get_threat_graph()
        url_id = graph.add_threat("url", "paypa1-secure.tk/login", {"demo": True, "threat_level": "CRITICAL"})
        domain_id = graph.add_threat("domain", "paypa1-secure.tk", {"demo": True, "threat_level": "CRITICAL"})
        ip_id = graph.add_threat("ip_address", "192.0.2.15", {"demo": True, "threat_level": "HIGH"})
        
        graph.link(domain_id, url_id, "hosts", confidence=0.95)
        graph.link(ip_id, domain_id, "resolves_to", confidence=0.9)
        
        demo_result["graph_node_id"] = url_id
        print("✅ Added demo data to threat graph")
    except Exception as e:
        print(f"⚠️ Could not add demo data to graph: {str(e)}")
    
    return demo_result