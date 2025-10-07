"""
Import Threat Feeds Script
Collect threat intelligence from various feeds and import into ThreatScope
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collectors.abuseipdb import AbuseIPDBCollector
from src.core.threat_graph import ThreatGraph
from src.core.bloom_filter import MalwareHashFilter
from src.config.settings import get_settings
from loguru import logger
import argparse


settings = get_settings()


async def import_abuseipdb():
    """Import threats from AbuseIPDB"""
    logger.info("Importing from AbuseIPDB...")
    
    if not settings.ABUSEIPDB_API_KEY:
        logger.warning("AbuseIPDB API key not configured, skipping...")
        return []
    
    collector = AbuseIPDBCollector(api_key=settings.ABUSEIPDB_API_KEY)
    threats = await collector.collect(days=7, confidence_min=75)
    await collector.close()
    
    logger.info(f"Collected {len(threats)} threats from AbuseIPDB")
    return threats


async def import_alienvault_otx():
    """Import threats from AlienVault OTX"""
    logger.info("Importing from AlienVault OTX...")
    
    if not settings.ALIENVAULT_OTX_API_KEY:
        logger.warning("AlienVault OTX API key not configured, skipping...")
        return []
    
    # TODO: Implement OTX collector
    logger.info("OTX collector not yet implemented")
    return []


async def import_urlhaus():
    """Import threats from URLhaus"""
    logger.info("Importing from URLhaus...")
    
    # TODO: Implement URLhaus collector
    logger.info("URLhaus collector not yet implemented")
    return []


async def import_phishtank():
    """Import threats from PhishTank"""
    logger.info("Importing from PhishTank...")
    
    # TODO: Implement PhishTank collector
    logger.info("PhishTank collector not yet implemented")
    return []


async def import_all_feeds():
    """Import threats from all configured feeds"""
    logger.info("Starting threat feed import...")
    
    all_threats = []
    
    # Collect from all sources
    abuseipdb_threats = await import_abuseipdb()
    all_threats.extend(abuseipdb_threats)
    
    otx_threats = await import_alienvault_otx()
    all_threats.extend(otx_threats)
    
    urlhaus_threats = await import_urlhaus()
    all_threats.extend(urlhaus_threats)
    
    phishtank_threats = await import_phishtank()
    all_threats.extend(phishtank_threats)
    
    logger.info(f"Total threats collected: {len(all_threats)}")
    
    return all_threats


async def process_threats(threats: list):
    """Process and store threats"""
    logger.info("Processing threats...")
    
    # Initialize data structures
    graph = ThreatGraph()
    bloom_filter = MalwareHashFilter(expected_hashes=1000000)
    
    # Process each threat
    for threat in threats:
        threat_type = threat.get("threat_type")
        value = threat.get("value")
        
        # Add to graph
        threat_id = graph.add_threat(
            threat_type=threat_type,
            value=value,
            metadata=threat.get("metadata", {})
        )
        
        # Add hashes to bloom filter
        if threat_type == "file_hash":
            bloom_filter.add_malware_hash(value, hash_type="sha256")
    
    # Save to disk
    logger.info("Saving threat data...")
    
    # Create data directories
    Path("data/threat_feeds").mkdir(parents=True, exist_ok=True)
    
    # Save bloom filter
    bloom_filter.bloom.save("data/threat_feeds/malware_hashes.bloom")
    logger.info("Saved bloom filter")
    
    # Save graph stats
    stats = graph.get_stats()
    logger.info(f"Graph stats: {stats}")
    
    logger.info("Import complete!")


async def continuous_import(interval_seconds: int = 3600):
    """Continuously import feeds at specified interval"""
    logger.info(f"Starting continuous import (every {interval_seconds} seconds)...")
    
    while True:
        try:
            threats = await import_all_feeds()
            await process_threats(threats)
            
            logger.info(f"Sleeping for {interval_seconds} seconds...")
            await asyncio.sleep(interval_seconds)
            
        except KeyboardInterrupt:
            logger.info("Stopping continuous import...")
            break
        except Exception as e:
            logger.error(f"Error in continuous import: {e}")
            await asyncio.sleep(60)  # Wait 1 minute on error


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Import threat intelligence feeds")
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run continuously at specified interval"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="Interval in seconds for continuous mode (default: 3600)"
    )
    parser.add_argument(
        "--source",
        choices=["all", "abuseipdb", "otx", "urlhaus", "phishtank"],
        default="all",
        help="Specific source to import from"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    logger.add(
        "logs/import_feeds.log",
        rotation="1 day",
        retention="30 days",
        level="INFO"
    )
    
    if args.continuous:
        asyncio.run(continuous_import(args.interval))
    else:
        # Single import
        if args.source == "all":
            threats = asyncio.run(import_all_feeds())
        elif args.source == "abuseipdb":
            threats = asyncio.run(import_abuseipdb())
        elif args.source == "otx":
            threats = asyncio.run(import_alienvault_otx())
        elif args.source == "urlhaus":
            threats = asyncio.run(import_urlhaus())
        elif args.source == "phishtank":
            threats = asyncio.run(import_phishtank())
        
        asyncio.run(process_threats(threats))


if __name__ == "__main__":
    main()