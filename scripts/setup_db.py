"""
Standalone Database Setup - Keine komplexen Imports!
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from dotenv import load_dotenv
import os

# Load .env
load_dotenv()

# Database URL aus .env
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threatscope.db")

# Engine erstellen
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Base für Models
Base = declarative_base()

# === MODELS DIREKT HIER DEFINIEREN ===

class Threat(Base):
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String(500), unique=True, index=True)
    ioc_type = Column(String(50))
    threat_type = Column(String(100))
    severity = Column(String(20))
    confidence = Column(Float)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    source = Column(String(100))
    description = Column(Text)
    tags = Column(JSON)


class ThreatRelation(Base):
    __tablename__ = "threat_relations"
    
    id = Column(Integer, primary_key=True)
    source_threat_id = Column(Integer, ForeignKey("threats.id"))
    target_threat_id = Column(Integer, ForeignKey("threats.id"))
    relation_type = Column(String(100))
    confidence = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(100))
    user = Column(String(100))
    ioc_value = Column(String(500))
    details = Column(JSON)
    merkle_hash = Column(String(64))


class FeedSource(Base):
    __tablename__ = "feed_sources"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True)
    endpoint = Column(String(500))
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)


# === SETUP FUNKTION ===

def setup_database():
    print("🔧 Creating database tables...")
    
    # Tabellen erstellen
    Base.metadata.create_all(engine)
    
    print("✅ Database setup complete!")
    print(f"📂 Database: {DATABASE_URL}")
    print("\n📋 Created tables:")
    for table in Base.metadata.tables.keys():
        print(f"  ✓ {table}")
    
    # Feed Sources hinzufügen
    Session = sessionmaker(bind=engine)
    session = Session()
    
    feeds = [
        {"name": "abuseipdb", "endpoint": "https://api.abuseipdb.com/api/v2/"},
        {"name": "alienvault_otx", "endpoint": "https://otx.alienvault.com/api/v1/"},
        {"name": "urlhaus", "endpoint": "https://urlhaus-api.abuse.ch/v1/"},
        {"name": "phishtank", "endpoint": "http://data.phishtank.com/data/"}
    ]
    
    print("\n🌐 Adding feed sources...")
    for feed_data in feeds:
        existing = session.query(FeedSource).filter_by(name=feed_data["name"]).first()
        if not existing:
            feed = FeedSource(**feed_data)
            session.add(feed)
            print(f"  + {feed_data['name']}")
    
    session.commit()
    session.close()
    
    print("\n🚀 Next steps:")
    print("1. python scripts/demo_data.py")
    print("2. uvicorn src.api.main:app --reload")
    print("3. streamlit run src/dashboard/app.py")


if __name__ == "__main__":
    setup_database()