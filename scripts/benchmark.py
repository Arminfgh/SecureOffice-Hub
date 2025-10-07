"""
Performance Benchmark Script
Test performance of core data structures and operations
"""

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.threat_graph import ThreatGraph
from src.core.bloom_filter import BloomFilter, MalwareHashFilter
from src.core.domain_trie import DomainTrie
from src.core.priority_queue import ThreatPriorityQueue
from loguru import logger
import statistics


def benchmark_function(func, iterations=1000, *args, **kwargs):
    """
    Benchmark a function
    
    Args:
        func: Function to benchmark
        iterations: Number of iterations
        *args, **kwargs: Function arguments
        
    Returns:
        Performance statistics
    """
    times = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        func(*args, **kwargs)
        end = time.perf_counter()
        times.append(end - start)
    
    return {
        'min': min(times) * 1000,  # Convert to ms
        'max': max(times) * 1000,
        'mean': statistics.mean(times) * 1000,
        'median': statistics.median(times) * 1000,
        'stdev': statistics.stdev(times) * 1000 if len(times) > 1 else 0
    }


def benchmark_threat_graph():
    """Benchmark threat graph operations"""
    logger.info("🔍 Benchmarking Threat Graph...")
    
    graph = ThreatGraph()
    
    # Test: Add node
    logger.info("  Testing: Add node")
    stats = benchmark_function(
        graph.add_threat,
        iterations=1000,
        threat_type="ip_address",
        value="192.168.1.1"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    # Prepare graph with nodes
    for i in range(100):
        graph.add_threat("ip_address", f"192.168.1.{i}")
        graph.add_threat("domain", f"domain{i}.com")
        if i > 0:
            graph.link(f"ip_address_192.168.1.{i-1}", f"ip_address_192.168.1.{i}", "related_to")
    
    # Test: Get related threats
    logger.info("  Testing: Get related threats")
    stats = benchmark_function(
        graph.get_related_threats,
        iterations=100,
        node_id="ip_address_192.168.1.50",
        depth=2
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    # Test: Get threat score
    logger.info("  Testing: Calculate threat score")
    stats = benchmark_function(
        graph.get_threat_score,
        iterations=100,
        node_id="ip_address_192.168.1.50"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    logger.info(f"  Graph size: {graph.graph.number_of_nodes()} nodes, {graph.graph.number_of_edges()} edges\n")


def benchmark_bloom_filter():
    """Benchmark bloom filter operations"""
    logger.info("🔍 Benchmarking Bloom Filter...")
    
    bloom = BloomFilter(expected_elements=10000, false_positive_rate=0.001)
    
    # Test: Add item
    logger.info("  Testing: Add item")
    stats = benchmark_function(
        bloom.add,
        iterations=1000,
        item="test_hash_123"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    # Add items for lookup test
    for i in range(1000):
        bloom.add(f"hash_{i}")
    
    # Test: Lookup (contains)
    logger.info("  Testing: Lookup (contains)")
    stats = benchmark_function(
        bloom.contains,
        iterations=1000,
        item="hash_500"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    bloom_stats = bloom.get_stats()
    logger.info(f"  Filter size: {bloom_stats['size_mb']:.2f} MB")
    logger.info(f"  False positive rate: {bloom_stats['current_fp_rate']:.6f}\n")


def benchmark_domain_trie():
    """Benchmark domain trie operations"""
    logger.info("🔍 Benchmarking Domain Trie...")
    
    trie = DomainTrie()
    
    # Test: Add domain
    logger.info("  Testing: Add domain")
    stats = benchmark_function(
        trie.add_domain,
        iterations=1000,
        domain="example.com"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    # Add domains for search test
    for i in range(100):
        trie.add_domain(f"sub{i}.example.com")
        trie.add_domain(f"domain{i}.com")
    
    # Test: Exact search
    logger.info("  Testing: Exact search")
    stats = benchmark_function(
        trie.search_exact,
        iterations=1000,
        domain="sub50.example.com"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    # Test: Prefix search
    logger.info("  Testing: Prefix search")
    stats = benchmark_function(
        trie.search_prefix,
        iterations=100,
        domain="example.com"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    trie_stats = trie.get_stats()
    logger.info(f"  Trie size: {trie_stats['total_domains']} domains, {trie_stats['total_nodes']} nodes\n")


def benchmark_priority_queue():
    """Benchmark priority queue operations"""
    logger.info("🔍 Benchmarking Priority Queue...")
    
    queue = ThreatPriorityQueue()
    
    # Test: Add alert
    logger.info("  Testing: Add alert")
    stats = benchmark_function(
        queue.add_alert,
        iterations=1000,
        threat_id="test_threat",
        threat_type="url",
        value="http://test.com",
        threat_level="HIGH",
        confidence=0.8
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    # Add alerts for retrieval test
    for i in range(100):
        queue.add_alert(
            threat_id=f"threat_{i}",
            threat_type="url",
            value=f"http://test{i}.com",
            threat_level=["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
            confidence=0.5 + (i % 50) / 100
        )
    
    # Test: Get next alert
    logger.info("  Testing: Get next alert")
    stats = benchmark_function(
        queue.get_next_alert,
        iterations=100
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    queue_stats = queue.get_stats()
    logger.info(f"  Queue size: {queue_stats['queue_size']} alerts\n")


def benchmark_malware_filter():
    """Benchmark malware hash filter"""
    logger.info("🔍 Benchmarking Malware Hash Filter...")
    
    filter = MalwareHashFilter(expected_hashes=10000)
    
    # Test: Add hash
    logger.info("  Testing: Add malware hash")
    hash_value = "a" * 64  # SHA256
    stats = benchmark_function(
        filter.add_malware_hash,
        iterations=1000,
        hash_value=hash_value,
        hash_type="sha256"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    # Add hashes for lookup test
    for i in range(1000):
        filter.add_malware_hash(f"{'a' * 60}{i:04d}", "sha256")
    
    # Test: Check if malware
    logger.info("  Testing: Check if known malware")
    stats = benchmark_function(
        filter.is_known_malware,
        iterations=1000,
        hash_value=f"{'a' * 60}0500",
        hash_type="sha256"
    )
    logger.info(f"    Mean: {stats['mean']:.3f}ms | Median: {stats['median']:.3f}ms")
    
    filter_stats = filter.get_stats()
    logger.info(f"  Total hashes: {filter_stats['malware_hashes']}\n")


def run_all_benchmarks():
    """Run all benchmarks"""
    logger.info("=" * 60)
    logger.info("🚀 ThreatScope Performance Benchmark")
    logger.info("=" * 60)
    logger.info("")
    
    start_time = time.time()
    
    benchmark_threat_graph()
    benchmark_bloom_filter()
    benchmark_domain_trie()
    benchmark_priority_queue()
    benchmark_malware_filter()
    
    total_time = time.time() - start_time
    
    logger.info("=" * 60)
    logger.info(f"✅ All benchmarks completed in {total_time:.2f} seconds")
    logger.info("=" * 60)


def main():
    """Main entry point"""
    # Configure logger
    logger.remove()
    logger.add(sys.stdout, format="<green>{time:HH:mm:ss}</green> | {message}")
    
    run_all_benchmarks()


if __name__ == "__main__":
    main()