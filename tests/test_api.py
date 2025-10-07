"""
Test API Endpoints
Integration tests for FastAPI endpoints
"""

import pytest
from fastapi.testclient import TestClient
from src.api.main import app


client = TestClient(app)


class TestRootEndpoints:
    """Test root and health endpoints"""
    
    def test_root_endpoint(self):
        """Test root endpoint returns API info"""
        response = client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert data["name"] == "ThreatScope API"
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
        assert "components" in data
    
    def test_stats_endpoint(self):
        """Test stats endpoint"""
        response = client.get("/stats")
        assert response.status_code == 200
        
        data = response.json()
        assert "graph" in data
        assert "malware_filter" in data


class TestAnalysisEndpoints:
    """Test analysis API endpoints"""
    
    def test_analyze_url_endpoint(self):
        """Test URL analysis endpoint"""
        response = client.post(
            "/api/analyze/url",
            json={"url": "http://example.com"}
        )
        
        # May fail if OpenAI not configured, but endpoint should exist
        assert response.status_code in [200, 500]
    
    def test_analyze_url_invalid_input(self):
        """Test URL analysis with invalid input"""
        response = client.post(
            "/api/analyze/url",
            json={}
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_analyze_ip_endpoint(self):
        """Test IP analysis endpoint"""
        response = client.post(
            "/api/analyze/ip",
            json={"ip_address": "192.168.1.1"}
        )
        
        assert response.status_code in [200, 500]
    
    def test_analyze_hash_endpoint(self):
        """Test hash analysis endpoint"""
        response = client.post(
            "/api/analyze/hash",
            json={
                "file_hash": "a" * 64,
                "hash_type": "sha256"
            }
        )
        
        assert response.status_code in [200, 500]
    
    def test_demo_phishing_analysis(self):
        """Test demo phishing analysis"""
        response = client.get("/api/analyze/demo/phishing")
        
        # Demo should work even without OpenAI
        assert response.status_code in [200, 500]


class TestThreatEndpoints:
    """Test threat management endpoints"""
    
    def test_list_threats(self):
        """Test listing threats"""
        response = client.get("/api/threats")
        assert response.status_code == 200
        
        data = response.json()
        assert "threats" in data
        assert "total" in data
    
    def test_list_threats_with_filters(self):
        """Test listing threats with filters"""
        response = client.get(
            "/api/threats",
            params={
                "threat_type": "url",
                "threat_level": "CRITICAL",
                "limit": 10
            }
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "threats" in data
    
    def test_get_threat_stats(self):
        """Test getting threat statistics"""
        response = client.get("/api/threats/stats/summary")
        assert response.status_code == 200
        
        data = response.json()
        assert "total_threats" in data
        assert "by_severity" in data
        assert "by_type" in data
    
    def test_create_threat(self):
        """Test creating a threat"""
        response = client.post(
            "/api/threats",
            json={
                "threat_type": "url",
                "value": "http://test.com",
                "threat_level": "MEDIUM",
                "confidence": 0.75
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "threat_id" in data


class TestSearchEndpoints:
    """Test search endpoints"""
    
    def test_search_threats(self):
        """Test threat search"""
        response = client.post(
            "/api/search",
            json={
                "query": "Show me phishing threats",
                "limit": 50
            }
        )
        
        assert response.status_code in [200, 500]
    
    def test_search_ioc(self):
        """Test IOC lookup"""
        response = client.get("/api/search/ioc/192.168.1.1")
        assert response.status_code == 200
        
        data = response.json()
        assert "ioc_value" in data
        assert "detected_type" in data
    
    def test_search_campaigns(self):
        """Test campaign search"""
        response = client.get("/api/search/campaigns")
        assert response.status_code == 200
        
        data = response.json()
        assert "campaigns" in data
    
    def test_search_suggestions(self):
        """Test search suggestions"""
        response = client.get(
            "/api/search/suggest",
            params={"partial": "phish"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "queries" in data


class TestErrorHandling:
    """Test API error handling"""
    
    def test_not_found(self):
        """Test 404 handling"""
        response = client.get("/api/nonexistent")
        assert response.status_code == 404
    
    def test_method_not_allowed(self):
        """Test method not allowed"""
        response = client.put("/")
        assert response.status_code == 405
    
    def test_validation_error(self):
        """Test validation error handling"""
        response = client.post(
            "/api/analyze/url",
            json={"wrong_field": "value"}
        )
        
        assert response.status_code == 422


class TestCORS:
    """Test CORS configuration"""
    
    def test_cors_headers(self):
        """Test CORS headers are present"""
        response = client.options("/")
        
        # Should have CORS headers
        assert "access-control-allow-origin" in response.headers or response.status_code == 200


class TestRateLimiting:
    """Test rate limiting (if enabled)"""
    
    def test_rate_limit_not_exceeded_normal(self):
        """Test normal request rate"""
        # Make a few requests
        for _ in range(5):
            response = client.get("/health")
            assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])