"""
Domain Trie - Blazing fast domain prefix matching
Efficient domain/subdomain lookup for threat detection
"""

from typing import List, Dict, Optional, Set
from datetime import datetime


class TrieNode:
    """Node in the domain trie"""
    
    def __init__(self):
        self.children = {}
        self.is_end_of_domain = False
        self.threat_data = None
        self.metadata = {}


class DomainTrie:
    """
    Trie data structure for efficient domain matching
    Stores domains in reverse order (com.google.mail) for efficient subdomain matching
    """
    
    def __init__(self):
        self.root = TrieNode()
        self.domain_count = 0
    
    def _reverse_domain(self, domain: str) -> List[str]:
        """
        Reverse domain parts for trie insertion
        Example: mail.google.com -> ['com', 'google', 'mail']
        """
        return domain.lower().strip().split('.')[::-1]
    
    def add_domain(
        self,
        domain: str,
        threat_level: str = 'MEDIUM',
        metadata: Optional[Dict] = None
    ):
        """
        Add a domain to the trie
        
        Args:
            domain: Domain name (e.g., 'evil.com')
            threat_level: Threat severity
            metadata: Additional threat info
        """
        parts = self._reverse_domain(domain)
        node = self.root
        
        for part in parts:
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
        
        node.is_end_of_domain = True
        node.threat_data = {
            'domain': domain,
            'threat_level': threat_level,
            'added_at': datetime.now().isoformat()
        }
        node.metadata = metadata or {}
        
        self.domain_count += 1
    
    def search_exact(self, domain: str) -> Optional[Dict]:
        """
        Search for exact domain match
        
        Args:
            domain: Domain to search
            
        Returns:
            Threat data if found, None otherwise
        """
        parts = self._reverse_domain(domain)
        node = self.root
        
        for part in parts:
            if part not in node.children:
                return None
            node = node.children[part]
        
        if node.is_end_of_domain:
            return node.threat_data
        return None
    
    def search_prefix(self, domain: str) -> List[Dict]:
        """
        Find all domains matching a prefix
        Example: searching 'google.com' finds 'mail.google.com', 'drive.google.com'
        
        Args:
            domain: Domain prefix
            
        Returns:
            List of matching domains
        """
        parts = self._reverse_domain(domain)
        node = self.root
        
        # Navigate to prefix
        for part in parts:
            if part not in node.children:
                return []
            node = node.children[part]
        
        # Collect all domains under this prefix
        results = []
        self._collect_all_domains(node, results)
        return results
    
    def _collect_all_domains(self, node: TrieNode, results: List[Dict]):
        """Recursively collect all domains from a node"""
        if node.is_end_of_domain:
            results.append(node.threat_data)
        
        for child in node.children.values():
            self._collect_all_domains(child, results)
    
    def is_subdomain_of_threat(self, domain: str) -> bool:
        """
        Check if domain is a subdomain of any known threat
        Example: 'login.evil.com' is subdomain of 'evil.com'
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain is under a known threat domain
        """
        parts = self._reverse_domain(domain)
        node = self.root
        
        # Check each level
        for i, part in enumerate(parts):
            if part not in node.children:
                return False
            
            node = node.children[part]
            
            # If we hit a threat domain, the query is a subdomain
            if node.is_end_of_domain:
                return True
        
        return False
    
    def find_parent_domain(self, domain: str) -> Optional[Dict]:
        """
        Find the parent threat domain
        Example: 'login.phishing.evil.com' -> finds 'evil.com' if it exists
        
        Args:
            domain: Domain to check
            
        Returns:
            Parent threat data if found
        """
        parts = self._reverse_domain(domain)
        node = self.root
        parent_threat = None
        
        for part in parts:
            if part not in node.children:
                break
            
            node = node.children[part]
            
            if node.is_end_of_domain:
                parent_threat = node.threat_data
        
        return parent_threat
    
    def get_all_domains(self) -> List[str]:
        """Get all domains in the trie"""
        results = []
        self._collect_all_domains(self.root, results)
        return [d['domain'] for d in results]
    
    def remove_domain(self, domain: str) -> bool:
        """
        Remove a domain from the trie
        
        Args:
            domain: Domain to remove
            
        Returns:
            True if removed, False if not found
        """
        parts = self._reverse_domain(domain)
        node = self.root
        path = [(self.root, None)]
        
        # Navigate to domain
        for part in parts:
            if part not in node.children:
                return False
            node = node.children[part]
            path.append((node, part))
        
        if not node.is_end_of_domain:
            return False
        
        # Mark as removed
        node.is_end_of_domain = False
        node.threat_data = None
        self.domain_count -= 1
        
        # Clean up empty nodes
        for i in range(len(path) - 1, 0, -1):
            current_node, part = path[i]
            parent_node, _ = path[i - 1]
            
            # Remove if no children and not end of domain
            if not current_node.children and not current_node.is_end_of_domain:
                del parent_node.children[part]
            else:
                break
        
        return True
    
    def search_wildcard(self, pattern: str) -> List[Dict]:
        """
        Search with wildcard support
        Example: '*.google.com' matches 'mail.google.com', 'drive.google.com'
        
        Args:
            pattern: Pattern with * wildcard
            
        Returns:
            Matching domains
        """
        if '*' not in pattern:
            result = self.search_exact(pattern)
            return [result] if result else []
        
        # Split by wildcard
        parts = pattern.split('*')
        
        if len(parts) == 2 and parts[0] == '' and parts[1]:
            # Pattern: *.domain.com
            return self.search_prefix(parts[1].lstrip('.'))
        
        # For more complex patterns, use the prefix search
        base_domain = parts[-1].lstrip('.')
        return self.search_prefix(base_domain)
    
    def get_stats(self) -> Dict:
        """Get trie statistics"""
        return {
            'total_domains': self.domain_count,
            'trie_depth': self._get_max_depth(self.root),
            'total_nodes': self._count_nodes(self.root)
        }
    
    def _get_max_depth(self, node: TrieNode, depth: int = 0) -> int:
        """Calculate maximum depth of trie"""
        if not node.children:
            return depth
        
        return max(self._get_max_depth(child, depth + 1) 
                   for child in node.children.values())
    
    def _count_nodes(self, node: TrieNode) -> int:
        """Count total nodes in trie"""
        count = 1
        for child in node.children.values():
            count += self._count_nodes(child)
        return count
    
    def export_to_list(self) -> List[Dict]:
        """Export all domains as a list"""
        results = []
        self._collect_all_domains(self.root, results)
        return results