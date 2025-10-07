"""
Test Threat Graph
Unit tests for threat graph functionality
"""

import pytest
from src.core.threat_graph import ThreatGraph


class TestThreatGraph:
    """Test cases for ThreatGraph"""
    
    def setup_method(self):
        """Setup for each test"""
        self.graph = ThreatGraph()
    
    def test_add_threat(self):
        """Test adding a threat to the graph"""
        threat_id = self.graph.add_threat(
            threat_type="ip_address",
            value="192.168.1.1",
            metadata={"country": "US"}
        )
        
        assert threat_id == "ip_address_192.168.1.1"
        assert self.graph.graph.has_node(threat_id)
    
    def test_link_threats(self):
        """Test linking two threats"""
        ip_id = self.graph.add_threat("ip_address", "192.168.1.1")
        domain_id = self.graph.add_threat("domain", "evil.com")
        
        self.graph.link(ip_id, domain_id, "hosts", confidence=0.9)
        
        assert self.graph.graph.has_edge(ip_id, domain_id)
        edge_data = self.graph.graph.get_edge_data(ip_id, domain_id)
        assert edge_data["relation_type"] == "hosts"
        assert edge_data["confidence"] == 0.9
    
    def test_get_related_threats(self):
        """Test finding related threats"""
        # Create threat chain: IP -> Domain -> URL
        ip_id = self.graph.add_threat("ip_address", "192.168.1.1")
        domain_id = self.graph.add_threat("domain", "evil.com")
        url_id = self.graph.add_threat("url", "http://evil.com/malware")
        
        self.graph.link(ip_id, domain_id, "hosts")
        self.graph.link(domain_id, url_id, "contains")
        
        # Get related threats from IP
        related = self.graph.get_related_threats(ip_id, depth=2)
        
        assert len(related) > 0
        related_ids = [r["node_id"] for r in related]
        assert domain_id in related_ids
        assert url_id in related_ids
    
    def test_find_campaigns(self):
        """Test campaign detection"""
        # Create a cluster of related threats
        for i in range(5):
            threat_id = self.graph.add_threat("url", f"phishing{i}.com")
            if i > 0:
                prev_id = f"url_phishing{i-1}.com"
                self.graph.link(prev_id, threat_id, "related_to")
        
        campaigns = self.graph.find_campaigns(min_cluster_size=3)
        
        assert len(campaigns) > 0
        assert len(campaigns[0]) >= 3
    
    def test_threat_score(self):
        """Test threat scoring based on centrality"""
        # Create a hub threat (many connections)
        hub_id = self.graph.add_threat("ip_address", "192.168.1.1")
        
        for i in range(5):
            target_id = self.graph.add_threat("domain", f"domain{i}.com")
            self.graph.link(hub_id, target_id, "hosts")
        
        score = self.graph.get_threat_score(hub_id)
        
        assert score > 0.0
        assert score <= 1.0
    
    def test_shortest_path(self):
        """Test finding shortest path between threats"""
        ip_id = self.graph.add_threat("ip_address", "192.168.1.1")
        domain_id = self.graph.add_threat("domain", "evil.com")
        url_id = self.graph.add_threat("url", "http://evil.com/malware")
        
        self.graph.link(ip_id, domain_id, "hosts")
        self.graph.link(domain_id, url_id, "contains")
        
        path = self.graph.shortest_path(ip_id, url_id)
        
        assert path is not None
        assert path[0] == ip_id
        assert path[-1] == url_id
        assert len(path) == 3
    
    def test_export_subgraph(self):
        """Test exporting subgraph"""
        ip_id = self.graph.add_threat("ip_address", "192.168.1.1")
        domain_id = self.graph.add_threat("domain", "evil.com")
        
        self.graph.link(ip_id, domain_id, "hosts")
        
        export = self.graph.export_subgraph([ip_id, domain_id], format='json')
        
        assert export is not None
        assert isinstance(export, str)
        assert "nodes" in export or "links" in export
    
    def test_graph_stats(self):
        """Test getting graph statistics"""
        self.graph.add_threat("ip_address", "192.168.1.1")
        self.graph.add_threat("domain", "evil.com")
        
        stats = self.graph.get_stats()
        
        assert "total_nodes" in stats
        assert "total_edges" in stats
        assert stats["total_nodes"] == 2
    
    def test_prune_old_threats(self):
        """Test pruning old threats"""
        # This would need to manipulate dates
        # For now, just test that the method exists and doesn't error
        removed = self.graph.prune_old_threats(days=30)
        assert removed >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])