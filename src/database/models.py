# src/database/models.py
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from src.database.connection import Base

class Threat(Base):
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String(500), unique=True, index=True, nullable=False)
    ioc_type = Column(String(50), nullable=False)
    threat_type = Column(String(100))
    severity = Column(String(20))
    confidence = Column(Float)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    source = Column(String(100))
    
    # ✅ KEIN metadata Feld mehr!
    extra_info = Column(JSON, nullable=True)
    
    description = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)
    
    # Relationships
    relations_as_source = relationship(
        "ThreatRelation",
        foreign_keys="ThreatRelation.source_threat_id",
        back_populates="source_threat"
    )


class ThreatRelation(Base):
    __tablename__ = "threat_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    source_threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False)
    target_threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False)
    relation_type = Column(String(100))
    confidence = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    source_threat = relationship(
        "Threat",
        foreign_keys=[source_threat_id],
        back_populates="relations_as_source"
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    action = Column(String(100), nullable=False)
    user = Column(String(100))
    ioc_value = Column(String(500))
    details = Column(JSON)
    merkle_hash = Column(String(64))