"""
Test Bloom Filter
Unit tests for bloom filter functionality
"""

import pytest
from src.core.bloom_filter import BloomFilter, MalwareHashFilter


class TestBloomFilter:
    """Test cases for BloomFilter"""
    
    def setup_method(self):
        """Setup for each test"""
        self.bloom = BloomFilter(expected_elements=1000, false_positive_rate=0.001)
    
    def test_initialization(self):
        """Test bloom filter initialization"""
        assert self.bloom.expected_elements == 1000
        assert self.bloom.false_positive_rate == 0.001
        assert self.bloom.size > 0
        assert self.bloom.hash_count > 0
    
    def test_add_item(self):
        """Test adding an item to bloom filter"""
        self.bloom.add("test_hash_123")
        assert "test_hash_123" in self.bloom
    
    def test_contains_added_item(self):
        """Test that added items are found"""
        items = ["hash1", "hash2", "hash3"]
        
        for item in items:
            self.bloom.add(item)
        
        for item in items:
            assert item in self.bloom
    
    def test_does_not_contain_unadded_item(self):
        """Test that unadded items are not found (usually)"""
        self.bloom.add("existing_hash")
        
        # This should return False (no false negatives)
        assert "non_existing_hash" not in self.bloom
    
    def test_add_batch(self):
        """Test adding multiple items at once"""
        items = [f"hash_{i}" for i in range(100)]
        self.bloom.add_batch(items)
        
        # All items should be found
        for item in items:
            assert item in self.bloom
    
    def test_false_positive_rate(self):
        """Test that false positive rate is within bounds"""
        # Add some items
        for i in range(100):
            self.bloom.add(f"hash_{i}")
        
        fp_rate = self.bloom.current_false_positive_rate()
        
        # Should be low for small number of items
        assert fp_rate < 0.1  # Less than 10%
    
    def test_get_stats(self):
        """Test getting bloom filter statistics"""
        self.bloom.add("test_item")
        
        stats = self.bloom.get_stats()
        
        assert 'size_bits' in stats
        assert 'hash_count' in stats
        assert 'elements_added' in stats
        assert stats['elements_added'] == 1
    
    def test_save_and_load(self, tmp_path):
        """Test saving and loading bloom filter"""
        # Add some items
        items = ["hash1", "hash2", "hash3"]
        for item in items:
            self.bloom.add(item)
        
        # Save
        filepath = tmp_path / "test_bloom.pkl"
        self.bloom.save(str(filepath))
        
        # Load
        loaded_bloom = BloomFilter.load(str(filepath))
        
        # Check all items are still there
        for item in items:
            assert item in loaded_bloom
    
    def test_optimal_size_calculation(self):
        """Test optimal size calculation"""
        size = BloomFilter._optimal_size(1000, 0.01)
        assert size > 0
        assert isinstance(size, int)
    
    def test_optimal_hash_count_calculation(self):
        """Test optimal hash count calculation"""
        hash_count = BloomFilter._optimal_hash_count(10000, 1000)
        assert hash_count > 0
        assert isinstance(hash_count, int)


class TestMalwareHashFilter:
    """Test cases for MalwareHashFilter"""
    
    def setup_method(self):
        """Setup for each test"""
        self.filter = MalwareHashFilter(expected_hashes=1000)
    
    def test_initialization(self):
        """Test malware filter initialization"""
        assert self.filter.bloom is not None
        assert self.filter.hash_types == ['md5', 'sha1', 'sha256']
    
    def test_add_malware_hash(self):
        """Test adding a malware hash"""
        hash_value = "a" * 64  # SHA256 hash
        self.filter.add_malware_hash(hash_value, "sha256")
        
        assert self.filter.is_known_malware(hash_value, "sha256")
    
    def test_is_known_malware(self):
        """Test checking if hash is known malware"""
        # Add a known malware hash
        known_hash = "b" * 64
        self.filter.add_malware_hash(known_hash, "sha256")
        
        # Should be found
        assert self.filter.is_known_malware(known_hash, "sha256")
        
        # Unknown hash should not be found
        unknown_hash = "c" * 64
        assert not self.filter.is_known_malware(unknown_hash, "sha256")
    
    def test_normalize_hash(self):
        """Test hash normalization"""
        # Test with uppercase
        hash_upper = "ABCDEF" * 10 + "ABCD"  # 64 chars
        self.filter.add_malware_hash(hash_upper, "sha256")
        
        # Should be found with lowercase
        assert self.filter.is_known_malware(hash_upper.lower(), "sha256")
    
    def test_import_from_file(self, tmp_path):
        """Test importing hashes from file"""
        # Create test file
        test_file = tmp_path / "test_hashes.txt"
        hashes = [
            "a" * 64,
            "b" * 64,
            "c" * 64
        ]
        
        with open(test_file, 'w') as f:
            for h in hashes:
                f.write(f"{h}\n")
        
        # Import
        self.filter.import_from_file(str(test_file), "sha256")
        
        # Check all hashes are added
        for h in hashes:
            assert self.filter.is_known_malware(h, "sha256")
    
    def test_get_stats(self):
        """Test getting filter statistics"""
        # Add some hashes
        for i in range(10):
            self.filter.add_malware_hash(f"{'a' * 60}{i:04d}", "sha256")
        
        stats = self.filter.get_stats()
        
        assert 'malware_hashes' in stats
        assert stats['malware_hashes'] == 10
    
    def test_different_hash_types(self):
        """Test different hash types"""
        md5_hash = "a" * 32
        sha1_hash = "b" * 40
        sha256_hash = "c" * 64
        
        self.filter.add_malware_hash(md5_hash, "md5")
        self.filter.add_malware_hash(sha1_hash, "sha1")
        self.filter.add_malware_hash(sha256_hash, "sha256")
        
        assert self.filter.is_known_malware(md5_hash, "md5")
        assert self.filter.is_known_malware(sha1_hash, "sha1")
        assert self.filter.is_known_malware(sha256_hash, "sha256")
    
    def test_whitespace_handling(self):
        """Test that whitespace is handled correctly"""
        hash_with_whitespace = "  " + "a" * 64 + "  \n"
        self.filter.add_malware_hash(hash_with_whitespace, "sha256")
        
        # Should be found without whitespace
        assert self.filter.is_known_malware("a" * 64, "sha256")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])