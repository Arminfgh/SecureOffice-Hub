"""
Priority Queue - Smart alert prioritization
Efficiently manages threat alerts by severity and urgency
"""

import heapq
from typing import List, Optional, Dict, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


class ThreatPriority(Enum):
    """Threat priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


@dataclass(order=True)
class Alert:
    """Alert with priority"""
    priority: int = field(compare=True)
    threat_id: str = field(compare=False)
    threat_type: str = field(compare=False)
    value: str = field(compare=False)
    threat_level: str = field(compare=False)
    confidence: float = field(compare=False)
    timestamp: str = field(compare=False)
    metadata: Dict = field(default_factory=dict, compare=False)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'priority': self.priority,
            'threat_id': self.threat_id,
            'threat_type': self.threat_type,
            'value': self.value,
            'threat_level': self.threat_level,
            'confidence': self.confidence,
            'timestamp': self.timestamp,
            'metadata': self.metadata
        }


class ThreatPriorityQueue:
    """
    Priority queue for threat alerts
    Uses min-heap for efficient retrieval of highest priority threats
    """
    
    def __init__(self):
        self.queue = []
        self.alert_count = 0
        self.processed_count = 0
        
        # Priority mappings
        self.severity_priority = {
            'CRITICAL': ThreatPriority.CRITICAL.value,
            'HIGH': ThreatPriority.HIGH.value,
            'MEDIUM': ThreatPriority.MEDIUM.value,
            'LOW': ThreatPriority.LOW.value,
            'SAFE': ThreatPriority.INFO.value
        }
    
    def add_alert(
        self,
        threat_id: str,
        threat_type: str,
        value: str,
        threat_level: str = 'MEDIUM',
        confidence: float = 0.5,
        metadata: Optional[Dict] = None
    ):
        """
        Add an alert to the queue
        
        Args:
            threat_id: Unique threat identifier
            threat_type: Type of threat (ip, url, hash, etc.)
            value: Threat value
            threat_level: Severity level
            confidence: Confidence score
            metadata: Additional alert data
        """
        # Calculate priority
        base_priority = self.severity_priority.get(threat_level, 3)
        
        # Adjust priority based on confidence
        # Higher confidence = higher priority (lower number)
        adjusted_priority = base_priority - (confidence * 0.5)
        
        alert = Alert(
            priority=adjusted_priority,
            threat_id=threat_id,
            threat_type=threat_type,
            value=value,
            threat_level=threat_level,
            confidence=confidence,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {}
        )
        
        heapq.heappush(self.queue, alert)
        self.alert_count += 1
    
    def get_next_alert(self) -> Optional[Alert]:
        """
        Get the highest priority alert
        
        Returns:
            Highest priority alert or None if queue is empty
        """
        if not self.queue:
            return None
        
        alert = heapq.heappop(self.queue)
        self.processed_count += 1
        return alert
    
    def peek_next_alert(self) -> Optional[Alert]:
        """
        Peek at the next alert without removing it
        
        Returns:
            Next alert or None
        """
        return self.queue[0] if self.queue else None
    
    def get_top_n_alerts(self, n: int = 10) -> List[Alert]:
        """
        Get top N alerts without removing them
        
        Args:
            n: Number of alerts to retrieve
            
        Returns:
            List of top N alerts
        """
        return heapq.nsmallest(n, self.queue)
    
    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """
        Get all alerts of a specific severity
        
        Args:
            severity: Severity level
            
        Returns:
            List of matching alerts
        """
        return [alert for alert in self.queue 
                if alert.threat_level == severity]
    
    def get_alerts_by_type(self, threat_type: str) -> List[Alert]:
        """
        Get all alerts of a specific type
        
        Args:
            threat_type: Type of threat
            
        Returns:
            List of matching alerts
        """
        return [alert for alert in self.queue 
                if alert.threat_type == threat_type]
    
    def remove_alert(self, threat_id: str) -> bool:
        """
        Remove a specific alert
        
        Args:
            threat_id: ID of alert to remove
            
        Returns:
            True if removed, False if not found
        """
        original_size = len(self.queue)
        self.queue = [alert for alert in self.queue 
                      if alert.threat_id != threat_id]
        heapq.heapify(self.queue)
        
        return len(self.queue) < original_size
    
    def clear_processed_alerts(self):
        """Clear all processed alerts"""
        self.queue.clear()
        self.alert_count = 0
        self.processed_count = 0
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return len(self.queue)
    
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return len(self.queue) == 0
    
    def get_stats(self) -> Dict:
        """Get queue statistics"""
        severity_counts = {}
        type_counts = {}
        
        for alert in self.queue:
            # Count by severity
            severity_counts[alert.threat_level] = \
                severity_counts.get(alert.threat_level, 0) + 1
            
            # Count by type
            type_counts[alert.threat_type] = \
                type_counts.get(alert.threat_type, 0) + 1
        
        return {
            'queue_size': len(self.queue),
            'total_alerts_processed': self.alert_count,
            'alerts_completed': self.processed_count,
            'severity_distribution': severity_counts,
            'type_distribution': type_counts,
            'next_alert': self.peek_next_alert().to_dict() if not self.is_empty() else None
        }
    
    def export_alerts(self) -> List[Dict]:
        """Export all alerts as list"""
        return [alert.to_dict() for alert in sorted(self.queue)]
    
    def batch_process(self, batch_size: int = 10) -> List[Alert]:
        """
        Process a batch of alerts
        
        Args:
            batch_size: Number of alerts to process
            
        Returns:
            List of processed alerts
        """
        processed = []
        
        for _ in range(min(batch_size, len(self.queue))):
            alert = self.get_next_alert()
            if alert:
                processed.append(alert)
        
        return processed