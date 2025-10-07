"""
Bloom Filter - Probabilistic data structure for fast malware hash lookups
Memory-efficient way to check if a hash exists in a massive dataset
"""

import hashlib
import math
from bitarray import bitarray
from typing import List, Optional


class BloomFilter:
    """
    Space-efficient probabilistic data structure for set membership testing
    False positives possible, but false negatives are not
    """
    
    def __init__(
        self,
        expected_elements: int = 1000000,
        false_positive_rate: float = 0.001
    ):
        """
        Initialize Bloom Filter
        
        Args:
            expected_elements: Expected number of elements
            false_positive_rate: Desired false positive rate (e.g., 0.001 = 0.1%)
        """
        self.expected_elements = expected_elements
        self.false_positive_rate = false_positive_rate
        
        # Calculate optimal size and hash count
        self.size = self._optimal_size(expected_elements, false_positive_rate)
        self.hash_count = self._optimal_hash_count(self.size, expected_elements)
        
        # Initialize bit array
        self.bit_array = bitarray(self.size)
        self.bit_array.setall(0)
        
        self.elements_added = 0
    
    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        """
        Calculate optimal bit array size
        m = -(n * ln(p)) / (ln(2)^2)
        """
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)
    
    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        """
        Calculate optimal number of hash functions
        k = (m/n) * ln(2)
        """
        k = (m / n) * math.log(2)
        return int(k)
    
    def _hash(self, item: str, seed: int) -> int:
        """
        Generate hash for item with given seed
        
        Args:
            item: Item to hash
            seed: Seed for hash function
            
        Returns:
            Hash value modulo bit array size
        """
        h = hashlib.sha256(f"{item}{seed}".encode()).hexdigest()
        return int(h, 16) % self.size
    
    def add(self, item: str):
        """
        Add an item to the Bloom filter
        
        Args:
            item: Item to add (e.g., malware hash)
        """
        for i in range(self.hash_count):
            index = self._hash(item, i)
            self.bit_array[index] = 1
        
        self.elements_added += 1
    
    def add_batch(self, items: List[str]):
        """
        Add multiple items efficiently
        
        Args:
            items: List of items to add
        """
        for item in items:
            self.add(item)
    
    def contains(self, item: str) -> bool:
        """
        Check if item might be in the set
        
        Args:
            item: Item to check
            
        Returns:
            True if item MIGHT be in set
            False if item is DEFINITELY NOT in set
        """
        for i in range(self.hash_count):
            index = self._hash(item, i)
            if not self.bit_array[index]:
                return False
        return True
    
    def __contains__(self, item: str) -> bool:
        """Enable 'in' operator"""
        return self.contains(item)
    
    def current_false_positive_rate(self) -> float:
        """
        Calculate actual false positive rate based on elements added
        
        Returns:
            Current false positive probability
        """
        if self.elements_added == 0:
            return 0.0
        
        # (1 - e^(-kn/m))^k
        exponent = -self.hash_count * self.elements_added / self.size
        probability = (1 - math.exp(exponent)) ** self.hash_count
        return probability
    
    def get_stats(self) -> dict:
        """Get Bloom filter statistics"""
        bits_set = self.bit_array.count(1)
        
        return {
            'size_bits': self.size,
            'size_mb': self.size / (8 * 1024 * 1024),
            'hash_count': self.hash_count,
            'elements_added': self.elements_added,
            'bits_set': bits_set,
            'fill_rate': bits_set / self.size,
            'expected_fp_rate': self.false_positive_rate,
            'current_fp_rate': self.current_false_positive_rate(),
            'capacity_used': self.elements_added / self.expected_elements
        }
    
    def save(self, filepath: str):
        """Save Bloom filter to disk"""
        import pickle
        
        with open(filepath, 'wb') as f:
            pickle.dump({
                'bit_array': self.bit_array,
                'size': self.size,
                'hash_count': self.hash_count,
                'elements_added': self.elements_added,
                'expected_elements': self.expected_elements,
                'false_positive_rate': self.false_positive_rate
            }, f)
    
    @classmethod
    def load(cls, filepath: str) -> 'BloomFilter':
        """Load Bloom filter from disk"""
        import pickle
        
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        bf = cls(
            expected_elements=data['expected_elements'],
            false_positive_rate=data['false_positive_rate']
        )
        bf.bit_array = data['bit_array']
        bf.size = data['size']
        bf.hash_count = data['hash_count']
        bf.elements_added = data['elements_added']
        
        return bf


class MalwareHashFilter:
    """Specialized Bloom filter for malware hash lookups"""
    
    def __init__(self, expected_hashes: int = 1000000):
        """
        Initialize malware hash filter
        
        Args:
            expected_hashes: Expected number of malware hashes
        """
        # Use very low false positive rate for security
        self.bloom = BloomFilter(
            expected_elements=expected_hashes,
            false_positive_rate=0.0001  # 0.01% false positive
        )
        
        self.hash_types = ['md5', 'sha1', 'sha256']
    
    def add_malware_hash(
        self,
        hash_value: str,
        hash_type: Optional[str] = None
    ):
        """
        Add a malware hash
        
        Args:
            hash_value: Hash value
            hash_type: Type of hash (md5, sha1, sha256)
        """
        # Normalize hash (lowercase, no whitespace)
        normalized = hash_value.lower().strip()
        
        # Add with type prefix for better accuracy
        if hash_type:
            key = f"{hash_type}:{normalized}"
        else:
            key = normalized
        
        self.bloom.add(key)
    
    def is_known_malware(
        self,
        hash_value: str,
        hash_type: Optional[str] = None
    ) -> bool:
        """
        Check if hash is known malware
        
        Args:
            hash_value: Hash to check
            hash_type: Type of hash
            
        Returns:
            True if hash MIGHT be malware
            False if hash is DEFINITELY NOT known malware
        """
        normalized = hash_value.lower().strip()
        
        if hash_type:
            key = f"{hash_type}:{normalized}"
        else:
            key = normalized
        
        return key in self.bloom
    
    def import_from_file(self, filepath: str, hash_type: str = 'sha256'):
        """
        Import hashes from a text file
        
        Args:
            filepath: Path to file with one hash per line
            hash_type: Type of hashes in file
        """
        with open(filepath, 'r') as f:
            for line in f:
                hash_value = line.strip()
                if hash_value:
                    self.add_malware_hash(hash_value, hash_type)
    
    def get_stats(self) -> dict:
        """Get filter statistics"""
        stats = self.bloom.get_stats()
        stats['malware_hashes'] = self.bloom.elements_added
        return stats