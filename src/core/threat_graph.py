"""
Threat Graph - Network-based relationship mapping for IOCs
Uses NetworkX for efficient graph operations and threat correlation
"""

import networkx as nx
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from enum import Enum
import json


class ThreatType(Enum):
    """Types of threat indicators"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"
    MALWARE = "malware"
    ACTOR = "actor"


class RelationType(Enum):
    """Types of relationships between threats"""
    HOSTS = "hosts"
    COMMUNICATES_WITH = "communicates_with"
    REDIRECTS_TO = "redirects_to"
    DROPS = "drops"
    EXPLOITS = "exploits"
    ATTRIBUTED_TO = "attributed_to"
    RELATED_TO = "related_to"
    PART_OF = "part_of"


class ThreatGraph:
    """Graph-based threat intelligence correlation system"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self._node_count = 0
        
    def add_threat(
        self, 
        threat_type: str, 
        value: str, 
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add a threat node to the graph
        
        Args:
            threat_type: Type of threat (ip, domain, url, etc.)
            value: The actual threat value
            metadata: Additional threat information
            
        Returns:
            Node ID
        """
        node_id = f"{threat_type}_{value}"
        
        if not self.graph.has_node(node_id):
            self._node_count += 1
            
        self.graph.add_node(
            node_id,
            threat_type=threat_type,
            value=value,
            metadata=metadata or {},
            first_seen=datetime.now().isoformat(),
            last_updated=datetime.now().isoformat()
        )
        
        return node_id
    
    def link(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        confidence: float = 1.0,
        metadata: Optional[Dict] = None
    ):
        """
        Create a relationship between two threats
        
        Args:
            source_id: Source node ID
            target_id: Target node ID
            relation_type: Type of relationship
            confidence: Confidence score (0.0 to 1.0)
            metadata: Additional relationship info
        """
        self.graph.add_edge(
            source_id,
            target_id,
            relation_type=relation_type,
            confidence=confidence,
            metadata=metadata or {},
            created_at=datetime.now().isoformat()
        )
    
    def get_related_threats(
        self,
        node_id: str,
        depth: int = 1,
        min_confidence: float = 0.0
    ) -> List[Dict]:
        """
        Find all threats related to a given node
        
        Args:
            node_id: Starting node ID
            depth: How many hops to traverse
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of related threat dictionaries
        """
        if not self.graph.has_node(node_id):
            return []
        
        related = []
        visited = set()
        queue = [(node_id, 0)]
        
        while queue:
            current, current_depth = queue.pop(0)
            
            if current in visited or current_depth > depth:
                continue
                
            visited.add(current)
            
            # Get all neighbors (both incoming and outgoing)
            neighbors = list(self.graph.successors(current)) + \
                       list(self.graph.predecessors(current))
            
            for neighbor in neighbors:
                if neighbor in visited:
                    continue
                
                # Check confidence on edges
                edge_data = self.graph.get_edge_data(current, neighbor)
                if not edge_data:
                    edge_data = self.graph.get_edge_data(neighbor, current)
                
                if edge_data and edge_data.get('confidence', 1.0) >= min_confidence:
                    node_data = self.graph.nodes[neighbor]
                    related.append({
                        'node_id': neighbor,
                        'threat_type': node_data['threat_type'],
                        'value': node_data['value'],
                        'metadata': node_data.get('metadata', {}),
                        'relation': edge_data.get('relation_type'),
                        'confidence': edge_data.get('confidence', 1.0),
                        'distance': current_depth + 1
                    })
                    
                    if current_depth + 1 < depth:
                        queue.append((neighbor, current_depth + 1))
        
        return related
    
    def find_campaigns(self, min_cluster_size: int = 3) -> List[List[str]]:
        """
        Identify potential threat campaigns using community detection
        
        Args:
            min_cluster_size: Minimum nodes for a campaign
            
        Returns:
            List of campaigns (each campaign is a list of node IDs)
        """
        # Handle empty or too small graphs
        if self.graph.number_of_nodes() < min_cluster_size:
            return []
        
        try:
            # Convert to undirected for community detection
            undirected = self.graph.to_undirected()
            
            # Use Louvain community detection
            import networkx.algorithms.community as nx_comm
            communities = nx_comm.louvain_communities(undirected)
            
            # Filter by size
            campaigns = [
                list(community) 
                for community in communities 
                if len(community) >= min_cluster_size
            ]
            
            return campaigns
        except Exception as e:
            # Return empty list if community detection fails
            return []
    
    def get_threat_score(self, node_id: str) -> float:
        """
        Calculate threat score based on graph centrality
        
        Args:
            node_id: Node to score
            
        Returns:
            Threat score (0.0 to 1.0)
        """
        if not self.graph.has_node(node_id):
            return 0.0
        
        # Handle graphs with too few nodes for meaningful centrality
        num_nodes = self.graph.number_of_nodes()
        if num_nodes < 2:
            return 0.5  # Default score for isolated nodes
        
        # Combine multiple centrality metrics
        try:
            degree_cent = nx.degree_centrality(self.graph).get(node_id, 0)
            between_cent = nx.betweenness_centrality(self.graph).get(node_id, 0)
            
            # Weighted combination
            score = (degree_cent * 0.6) + (between_cent * 0.4)
            return min(score * 1.5, 1.0)  # Scale up but cap at 1.0
            
        except Exception as e:
            # Fallback to simple degree-based score
            degree = self.graph.degree(node_id)
            max_degree = max(dict(self.graph.degree()).values()) if num_nodes > 1 else 1
            return min(degree / max_degree, 1.0)
    
    def shortest_path(
        self,
        source_id: str,
        target_id: str
    ) -> Optional[List[str]]:
        """
        Find shortest path between two threats
        
        Args:
            source_id: Starting node
            target_id: Ending node
            
        Returns:
            List of node IDs in the path, or None if no path exists
        """
        if not self.graph.has_node(source_id) or not self.graph.has_node(target_id):
            return None
            
        try:
            return nx.shortest_path(self.graph, source_id, target_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
    
    def export_subgraph(
        self,
        node_ids: List[str],
        format: str = 'json'
    ) -> str:
        """
        Export a subgraph for visualization
        
        Args:
            node_ids: Nodes to include
            format: Export format ('json', 'gexf', 'graphml')
            
        Returns:
            Serialized graph data
        """
        # Filter to only existing nodes
        valid_nodes = [n for n in node_ids if self.graph.has_node(n)]
        
        if not valid_nodes:
            return json.dumps({"nodes": [], "links": []}) if format == 'json' else ""
        
        subgraph = self.graph.subgraph(valid_nodes)
        
        if format == 'json':
            data = nx.node_link_data(subgraph)
            return json.dumps(data, indent=2)
        elif format == 'gexf':
            return '\n'.join(nx.generate_gexf(subgraph))
        elif format == 'graphml':
            return '\n'.join(nx.generate_graphml(subgraph))
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def get_stats(self) -> Dict:
        """Get graph statistics"""
        num_nodes = self.graph.number_of_nodes()
        num_edges = self.graph.number_of_edges()
        
        # Handle empty graph
        if num_nodes == 0:
            return {
                'total_nodes': 0,
                'total_edges': 0,
                'avg_degree': 0.0,
                'density': 0.0,
                'is_connected': False
            }
        
        # Calculate statistics safely
        degrees = dict(self.graph.degree())
        avg_degree = sum(degrees.values()) / num_nodes
        
        # Check connectivity only if graph has nodes
        is_connected = False
        try:
            if num_nodes > 0:
                is_connected = nx.is_weakly_connected(self.graph)
        except Exception:
            is_connected = False
        
        return {
            'total_nodes': num_nodes,
            'total_edges': num_edges,
            'avg_degree': avg_degree,
            'density': nx.density(self.graph),
            'is_connected': is_connected
        }
    
    def prune_old_threats(self, days: int = 30) -> int:
        """
        Remove threats older than specified days
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of nodes removed
        """
        from datetime import timedelta
        
        if self.graph.number_of_nodes() == 0:
            return 0
        
        cutoff = datetime.now() - timedelta(days=days)
        nodes_to_remove = []
        
        for node_id, data in self.graph.nodes(data=True):
            try:
                last_updated = datetime.fromisoformat(data.get('last_updated', ''))
                if last_updated < cutoff:
                    nodes_to_remove.append(node_id)
            except (ValueError, TypeError):
                # Skip nodes with invalid timestamps
                continue
        
        self.graph.remove_nodes_from(nodes_to_remove)
        return len(nodes_to_remove)
    
    def clear(self):
        """Clear all nodes and edges from the graph"""
        self.graph.clear()
        self._node_count = 0
    
    def get_node(self, node_id: str) -> Optional[Dict]:
        """
        Get node data by ID
        
        Args:
            node_id: Node identifier
            
        Returns:
            Node data dictionary or None if not found
        """
        if not self.graph.has_node(node_id):
            return None
        
        return dict(self.graph.nodes[node_id])
    
    def get_all_nodes(self) -> List[Dict]:
        """
        Get all nodes in the graph
        
        Returns:
            List of all node data dictionaries
        """
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            node_data = dict(data)
            node_data['node_id'] = node_id
            nodes.append(node_data)
        return nodes
    
    def get_all_edges(self) -> List[Dict]:
        """
        Get all edges in the graph
        
        Returns:
            List of all edge data dictionaries
        """
        edges = []
        for source, target, data in self.graph.edges(data=True):
            edge_data = dict(data)
            edge_data['source'] = source
            edge_data['target'] = target
            edges.append(edge_data)
        return edges