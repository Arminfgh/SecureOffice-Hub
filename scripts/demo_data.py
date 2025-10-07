"""
Demo Data Generator
Generate sample threat data for testing and demonstrations
"""

import sys
import random
from pathlib import Path
from datetime import datetime, timedelta
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.threat_graph import ThreatGraph
from src.core.bloom_filter import MalwareHashFilter
from loguru import logger


# Sample data pools
MALICIOUS_IPS = [
    "45.76.123.45", "192.0.2.15", "198.51.100.42",
    "203.0.113.89", "185.220.101.15", "91.219.237.26"
]

MALICIOUS_DOMAINS = [
    "evil-cdn.ru", "phishing-site.ml", "malware-download.xyz",
    "secure-login-verify.ml", "paypa1-secure.tk", "bank-verify.ga"
]

MALICIOUS_URLS = [
    "http://paypa1-secure.tk/login",
    "http://malware-download.xyz/payload.exe",
    "https://secure-login-verify.ml/account",
    "http://evil-cdn.ru/update.js"
]

MALWARE_HASHES = [
    "a3f5b8c9d2e1f4a7b6c5d8e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
    "b4e6c9a0d3f2e5b7c8a6d9b1e4f3a5c7d8b0e1f4a6c9b2d5e7f8a1c3b6d9e0f2",
    "c5f7d1a2e4b8c0d6e9a3f5b7c1d8e0a4f6b9c2d5e8a1f3b7c0d4e9a2f6b8c1d5"
]

MALWARE_FAMILIES = [
    "Emotet", "TrickBot", "Dridex", "Qakbot", "Cobalt Strike",
    "Ransomware", "Trojan", "Backdoor"
]

COUNTRIES = ["RU", "CN", "KP", "IR", "UA", "BR", "VN"]

THREAT_ACTORS = ["APT28", "APT29", "Lazarus Group", "FIN7", "TA505"]

CAMPAIGNS = [
    "Operation Dark Web",
    "PayPal Phishing Wave",
    "Banking Trojan Campaign",
    "Ransomware Outbreak"
]


def generate_random_ip():
    """Generate random IP address"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"


def generate_random_domain():
    """Generate random domain"""
    tlds = [".com", ".ru", ".cn", ".tk", ".ml", ".ga"]
    return f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 12)))}{random.choice(tlds)}"


def generate_random_hash():
    """Generate random SHA256 hash"""
    return ''.join(random.choices('0123456789abcdef', k=64))


def generate_demo_threats(count: int = 50):
    """
    Generate demo threat data
    
    Args:
        count: Number of threats to generate
        
    Returns:
        List of threat dictionaries
    """
    logger.info(f"Generating {count} demo threats...")
    
    threats = []
    
    for i in range(count):
        threat_type = random.choice(["ip_address", "domain", "url", "file_hash"])
        
        if threat_type == "ip_address":
            value = random.choice(MALICIOUS_IPS + [generate_random_ip() for _ in range(3)])
        elif threat_type == "domain":
            value = random.choice(MALICIOUS_DOMAINS + [generate_random_domain() for _ in range(3)])
        elif threat_type == "url":
            value = random.choice(MALICIOUS_URLS)
        else:  # file_hash
            value = random.choice(MALWARE_HASHES + [generate_random_hash() for _ in range(3)])
        
        threat_level = random.choices(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            weights=[10, 30, 40, 20]
        )[0]
        
        confidence = random.uniform(0.5, 1.0)
        
        # Random dates within last 30 days
        days_ago = random.randint(0, 30)
        first_seen = datetime.now() - timedelta(days=days_ago)
        last_seen = first_seen + timedelta(hours=random.randint(1, 48))
        
        threat = {
            "threat_id": f"{threat_type}_{i:04d}",
            "threat_type": threat_type,
            "value": value,
            "threat_level": threat_level,
            "confidence": round(confidence, 2),
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "metadata": {
                "country": random.choice(COUNTRIES),
                "tags": random.sample(["malware", "phishing", "botnet", "c2", "scanner"], k=random.randint(1, 3)),
                "source": random.choice(["AbuseIPDB", "OTX", "URLhaus", "PhishTank"])
            }
        }
        
        if threat_type == "file_hash":
            threat["metadata"]["malware_family"] = random.choice(MALWARE_FAMILIES)
        
        threats.append(threat)
    
    logger.info(f"✅ Generated {len(threats)} threats")
    return threats


def generate_demo_relationships(threats: list):
    """
    Generate relationships between threats
    
    Args:
        threats: List of threat dictionaries
        
    Returns:
        List of relationship dictionaries
    """
    logger.info("Generating threat relationships...")
    
    relationships = []
    
    # Create some realistic relationship chains
    for i in range(min(20, len(threats) - 1)):
        source = threats[i]
        target = threats[i + 1]
        
        # Determine relationship type based on threat types
        if source["threat_type"] == "ip_address" and target["threat_type"] == "domain":
            relation_type = "hosts"
        elif source["threat_type"] == "domain" and target["threat_type"] == "url":
            relation_type = "contains"
        elif source["threat_type"] == "url" and target["threat_type"] == "file_hash":
            relation_type = "drops"
        elif source["threat_type"] == "file_hash" and target["threat_type"] == "ip_address":
            relation_type = "communicates_with"
        else:
            relation_type = "related_to"
        
        relationships.append({
            "source_id": source["threat_id"],
            "target_id": target["threat_id"],
            "relation_type": relation_type,
            "confidence": round(random.uniform(0.7, 1.0), 2)
        })
    
    logger.info(f"✅ Generated {len(relationships)} relationships")
    return relationships


def generate_demo_campaigns():
    """Generate demo campaign data"""
    logger.info("Generating demo campaigns...")
    
    campaigns = []
    
    for i, campaign_name in enumerate(CAMPAIGNS[:3]):
        campaign = {
            "campaign_id": f"campaign_{i:03d}",
            "name": campaign_name,
            "threat_actor": random.choice(THREAT_ACTORS),
            "attack_pattern": "Spear Phishing + Malware",
            "total_iocs": random.randint(50, 200),
            "first_seen": (datetime.now() - timedelta(days=random.randint(7, 30))).isoformat(),
            "is_active": random.choice([True, False]),
            "affected_sectors": random.sample(
                ["Finance", "Healthcare", "Government", "Retail", "Technology"],
                k=random.randint(2, 4)
            )
        }
        campaigns.append(campaign)
    
    logger.info(f"✅ Generated {len(campaigns)} campaigns")
    return campaigns


def save_demo_data_to_json(threats, relationships, campaigns, output_dir="data"):
    """Save demo data to JSON files"""
    output_path = Path(output_dir) / "demo"
    output_path.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Saving demo data to {output_path}...")
    
    # Save threats
    threats_file = output_path / "demo_threats.json"
    with open(threats_file, 'w') as f:
        json.dump(threats, f, indent=2)
    logger.info(f"  ✅ Saved {len(threats)} threats to {threats_file}")
    
    # Save relationships
    relationships_file = output_path / "demo_relationships.json"
    with open(relationships_file, 'w') as f:
        json.dump(relationships, f, indent=2)
    logger.info(f"  ✅ Saved {len(relationships)} relationships to {relationships_file}")
    
    # Save campaigns
    campaigns_file = output_path / "demo_campaigns.json"
    with open(campaigns_file, 'w') as f:
        json.dump(campaigns, f, indent=2)
    logger.info(f"  ✅ Saved {len(campaigns)} campaigns to {campaigns_file}")
    
    # Save combined data
    combined_file = output_path / "demo_complete.json"
    with open(combined_file, 'w') as f:
        json.dump({
            "threats": threats,
            "relationships": relationships,
            "campaigns": campaigns,
            "generated_at": datetime.now().isoformat()
        }, f, indent=2)
    logger.info(f"  ✅ Saved complete dataset to {combined_file}")


def populate_threat_graph(threats, relationships):
    """Populate threat graph with demo data"""
    logger.info("Populating threat graph...")
    
    graph = ThreatGraph()
    
    # Add threats
    for threat in threats:
        graph.add_threat(
            threat_type=threat["threat_type"],
            value=threat["value"],
            metadata=threat["metadata"]
        )
    
    # Add relationships
    for rel in relationships:
        graph.link(
            source_id=rel["source_id"],
            target_id=rel["target_id"],
            relation_type=rel["relation_type"],
            confidence=rel["confidence"]
        )
    
    stats = graph.get_stats()
    logger.info(f"  ✅ Graph: {stats['total_nodes']} nodes, {stats['total_edges']} edges")
    
    return graph


def populate_bloom_filter(threats):
    """Populate bloom filter with demo hashes"""
    logger.info("Populating bloom filter...")
    
    bloom_filter = MalwareHashFilter(expected_hashes=1000)
    
    hash_count = 0
    for threat in threats:
        if threat["threat_type"] == "file_hash":
            bloom_filter.add_malware_hash(threat["value"], "sha256")
            hash_count += 1
    
    logger.info(f"  ✅ Added {hash_count} hashes to bloom filter")
    
    return bloom_filter


def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("🎲 ThreatScope Demo Data Generator")
    logger.info("=" * 60)
    logger.info("")
    
    # Generate data
    threats = generate_demo_threats(count=100)
    relationships = generate_demo_relationships(threats)
    campaigns = generate_demo_campaigns()
    
    # Save to files
    save_demo_data_to_json(threats, relationships, campaigns)
    
    # Populate data structures
    graph = populate_threat_graph(threats, relationships)
    bloom_filter = populate_bloom_filter(threats)
    
    logger.info("")
    logger.info("=" * 60)
    logger.info("✅ Demo data generation complete!")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Files created in data/demo/:")
    logger.info("  - demo_threats.json")
    logger.info("  - demo_relationships.json")
    logger.info("  - demo_campaigns.json")
    logger.info("  - demo_complete.json")


if __name__ == "__main__":
    main()