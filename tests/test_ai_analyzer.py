"""
Test AI Analyzer
Unit tests for AI-powered threat analysis
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.ai.analyzer import ThreatAnalyzer


class TestThreatAnalyzer:
    """Test cases for ThreatAnalyzer"""
    
    def setup_method(self):
        """Setup for each test"""
        with patch('src.ai.analyzer.openai.OpenAI'):
            self.analyzer = ThreatAnalyzer(api_key="test_key")
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_initialization(self, mock_openai):
        """Test analyzer initialization"""
        analyzer = ThreatAnalyzer(api_key="test_key")
        assert analyzer.client is not None
        assert analyzer.model is not None
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_analyze_url_structure(self, mock_openai):
        """Test URL analysis returns correct structure"""
        # Mock OpenAI response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"threat_level": "CRITICAL", "confidence": 0.9}'
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        result = analyzer.analyze_url("http://test.com")
        
        assert 'threat_level' in result
        assert 'confidence' in result
        assert 'analyzed_at' in result
        assert 'url' in result
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_analyze_ip_structure(self, mock_openai):
        """Test IP analysis returns correct structure"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"threat_level": "HIGH", "confidence": 0.8}'
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        result = analyzer.analyze_ip("192.168.1.1")
        
        assert 'threat_level' in result
        assert 'confidence' in result
        assert 'ip_address' in result
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_analyze_hash_structure(self, mock_openai):
        """Test hash analysis returns correct structure"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"threat_level": "CRITICAL", "confidence": 0.95}'
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        result = analyzer.analyze_file_hash("a" * 64, "sha256")
        
        assert 'threat_level' in result
        assert 'confidence' in result
        assert 'file_hash' in result
        assert 'hash_type' in result
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_correlate_threats(self, mock_openai):
        """Test threat correlation analysis"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"campaign_detected": true, "confidence": 0.85}'
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        threats = [
            {"type": "ip", "value": "192.168.1.1"},
            {"type": "domain", "value": "evil.com"}
        ]
        
        result = analyzer.correlate_threats(threats)
        
        assert 'campaign_detected' in result
        assert 'confidence' in result
        assert 'threats_analyzed' in result
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_natural_language_query(self, mock_openai):
        """Test natural language search"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"understood_query": "test", "matching_threats": []}'
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        result = analyzer.natural_language_query("Show me Russian threats", [])
        
        assert 'understood_query' in result
        assert 'query' in result
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_generate_report(self, mock_openai):
        """Test report generation"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "# Threat Report\nTest content"
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        threats = [{"type": "ip", "value": "1.2.3.4"}]
        result = analyzer.generate_report(threats, "last 7 days")
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_analyze_url_with_context(self, mock_openai):
        """Test URL analysis with additional context"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"threat_level": "HIGH"}'
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        result = analyzer.analyze_url("http://test.com")
        
        # Check that OpenAI was called
        assert mock_client.chat.completions.create.called
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_error_handling(self, mock_openai):
        """Test error handling in analysis"""
        mock_client = Mock()
        mock_client.chat.completions.create.side_effect = Exception("API Error")
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        # Should raise exception
        with pytest.raises(Exception):
            analyzer.analyze_url("http://test.com")
    
    @patch('src.ai.analyzer.openai.OpenAI')
    def test_temperature_setting(self, mock_openai):
        """Test that temperature is set correctly"""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"threat_level": "LOW"}'
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        
        analyzer = ThreatAnalyzer(api_key="test_key")
        analyzer.client = mock_client
        
        analyzer.analyze_url("http://test.com")
        
        # Check temperature was set
        call_args = mock_client.chat.completions.create.call_args
        assert 'temperature' in call_args[1]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])