"""
Merkle Tree - Tamper-proof audit trail for compliance
Ensures integrity of threat analysis logs
"""

import hashlib
from typing import List, Optional, Dict
from datetime import datetime
import json


class MerkleNode:
    """Node in the Merkle tree"""
    
    def __init__(self, data: str, left=None, right=None):
        self.data = data
        self.left = left
        self.right = right
        self.hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of node data"""
        if self.left and self.right:
            # Internal node: hash of concatenated child hashes
            combined = self.left.hash + self.right.hash
        else:
            # Leaf node: hash of data
            combined = self.data
        
        return hashlib.sha256(combined.encode()).hexdigest()


class MerkleTree:
    """
    Merkle Tree for tamper-proof audit logs
    Creates a cryptographic chain of threat analysis records
    """
    
    def __init__(self):
        self.root = None
        self.leaves = []
        self.audit_logs = []
    
    def add_audit_log(self, action: str, details: Dict) -> str:
        """
        Add an audit log entry
        
        Args:
            action: Action performed (analyze, add_threat, etc.)
            details: Log details
            
        Returns:
            Hash of the log entry
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details,
            'previous_hash': self.root.hash if self.root else '0' * 64
        }
        
        # Serialize log entry
        log_data = json.dumps(log_entry, sort_keys=True)
        
        # Create leaf node
        leaf = MerkleNode(log_data)
        self.leaves.append(leaf)
        self.audit_logs.append(log_entry)
        
        # Rebuild tree
        self._build_tree()
        
        return leaf.hash
    
    def _build_tree(self):
        """Build Merkle tree from leaf nodes"""
        if not self.leaves:
            return
        
        nodes = self.leaves.copy()
        
        # Build tree bottom-up
        while len(nodes) > 1:
            temp_nodes = []
            
            # Pair up nodes
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
                
                # Create parent node
                parent_data = left.hash + right.hash
                parent = MerkleNode(parent_data, left, right)
                temp_nodes.append(parent)
            
            nodes = temp_nodes
        
        self.root = nodes[0]
    
    def get_root_hash(self) -> Optional[str]:
        """Get the root hash of the tree"""
        return self.root.hash if self.root else None
    
    def verify_integrity(self) -> bool:
        """
        Verify the integrity of the audit trail
        
        Returns:
            True if audit trail is intact, False if tampered
        """
        if not self.leaves:
            return True
        
        # Rebuild tree and compare root hash
        original_root = self.root.hash if self.root else None
        
        # Temporarily rebuild
        temp_leaves = [MerkleNode(json.dumps(log, sort_keys=True)) 
                       for log in self.audit_logs]
        
        temp_nodes = temp_leaves.copy()
        while len(temp_nodes) > 1:
            temp = []
            for i in range(0, len(temp_nodes), 2):
                left = temp_nodes[i]
                right = temp_nodes[i + 1] if i + 1 < len(temp_nodes) else temp_nodes[i]
                parent_data = left.hash + right.hash
                parent = MerkleNode(parent_data, left, right)
                temp.append(parent)
            temp_nodes = temp
        
        new_root = temp_nodes[0].hash if temp_nodes else None
        
        return original_root == new_root
    
    def get_proof(self, leaf_index: int) -> List[Dict]:
        """
        Get Merkle proof for a specific leaf
        
        Args:
            leaf_index: Index of leaf to prove
            
        Returns:
            List of hashes needed to verify the leaf
        """
        if leaf_index >= len(self.leaves):
            return []
        
        proof = []
        nodes = self.leaves.copy()
        index = leaf_index
        
        while len(nodes) > 1:
            temp_nodes = []
            
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
                
                if i == index or i + 1 == index:
                    # Add sibling to proof
                    if i == index and i + 1 < len(nodes):
                        proof.append({
                            'position': 'right',
                            'hash': right.hash
                        })
                    elif i + 1 == index:
                        proof.append({
                            'position': 'left',
                            'hash': left.hash
                        })
                
                parent_data = left.hash + right.hash
                parent = MerkleNode(parent_data, left, right)
                temp_nodes.append(parent)
            
            # Update index for next level
            index = index // 2
            nodes = temp_nodes
        
        return proof
    
    def verify_proof(self, leaf_hash: str, proof: List[Dict]) -> bool:
        """
        Verify a Merkle proof
        
        Args:
            leaf_hash: Hash of the leaf to verify
            proof: Merkle proof
            
        Returns:
            True if proof is valid
        """
        current_hash = leaf_hash
        
        for item in proof:
            if item['position'] == 'left':
                combined = item['hash'] + current_hash
            else:
                combined = current_hash + item['hash']
            
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        return current_hash == self.get_root_hash()
    
    def export_audit_trail(self) -> Dict:
        """Export complete audit trail with verification"""
        return {
            'root_hash': self.get_root_hash(),
            'total_entries': len(self.audit_logs),
            'entries': self.audit_logs,
            'integrity_verified': self.verify_integrity(),
            'exported_at': datetime.now().isoformat()
        }
    
    def get_stats(self) -> Dict:
        """Get Merkle tree statistics"""
        return {
            'total_logs': len(self.audit_logs),
            'root_hash': self.get_root_hash(),
            'integrity_status': 'intact' if self.verify_integrity() else 'compromised',
            'leaf_count': len(self.leaves)
        }