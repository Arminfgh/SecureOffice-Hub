"""
Custom Logging Configuration
Structured logging using Loguru
"""

import sys
from loguru import logger
from pathlib import Path
from src.config.settings import get_settings


settings = get_settings()


def setup_logging():
    """Configure application logging"""
    
    # Remove default handler
    logger.remove()
    
    # Console handler with colors
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=settings.LOG_LEVEL,
        colorize=True
    )
    
    # File handler for all logs
    log_path = Path(settings.LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    logger.add(
        settings.LOG_FILE,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level="DEBUG",
        rotation="500 MB",
        retention="30 days",
        compression="zip"
    )
    
    # Separate file for errors
    error_log = log_path.parent / "error.log"
    logger.add(
        error_log,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level="ERROR",
        rotation="100 MB",
        retention="90 days",
        compression="zip"
    )
    
    logger.info("Logging initialized")


def get_logger(name: str):
    """
    Get logger for specific module
    
    Args:
        name: Module name
        
    Returns:
        Logger instance
    """
    return logger.bind(name=name)


# Security audit logger
audit_logger = logger.bind(audit=True)


def log_security_event(event_type: str, details: dict):
    """
    Log security event
    
    Args:
        event_type: Type of security event
        details: Event details
    """
    audit_logger.info(
        f"SECURITY EVENT: {event_type}",
        extra=details
    )


def log_api_request(method: str, path: str, user: str = "anonymous"):
    """
    Log API request
    
    Args:
        method: HTTP method
        path: Request path
        user: User identifier
    """
    logger.info(f"API: {method} {path} by {user}")


def log_threat_detection(threat_type: str, value: str, severity: str):
    """
    Log threat detection
    
    Args:
        threat_type: Type of threat
        value: Threat value
        severity: Severity level
    """
    logger.warning(
        f"THREAT DETECTED: {threat_type}={value} [SEVERITY: {severity}]"
    )