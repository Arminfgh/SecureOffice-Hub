"""
Data Formatters
Utility functions for formatting and displaying data
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import json


def format_threat_level(level: str) -> str:
    """
    Format threat level with emoji
    
    Args:
        level: Threat level (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
        
    Returns:
        Formatted threat level with emoji
    """
    emoji_map = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "SAFE": "✅",
        "UNKNOWN": "⚪"
    }
    
    emoji = emoji_map.get(level.upper(), "⚪")
    return f"{emoji} {level.upper()}"


def format_confidence(confidence: float) -> str:
    """
    Format confidence score as percentage
    
    Args:
        confidence: Confidence score (0.0 to 1.0)
        
    Returns:
        Formatted percentage string
    """
    return f"{confidence * 100:.1f}%"


def format_datetime(dt: datetime, format: str = "human") -> str:
    """
    Format datetime in various formats
    
    Args:
        dt: Datetime object
        format: Format type (human, iso, short, long)
        
    Returns:
        Formatted datetime string
    """
    if format == "human":
        now = datetime.now()
        diff = now - dt
        
        if diff < timedelta(minutes=1):
            return "just now"
        elif diff < timedelta(hours=1):
            minutes = int(diff.total_seconds() / 60)
            return f"{minutes} min{'s' if minutes != 1 else ''} ago"
        elif diff < timedelta(days=1):
            hours = int(diff.total_seconds() / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff < timedelta(days=30):
            days = diff.days
            return f"{days} day{'s' if days != 1 else ''} ago"
        else:
            return dt.strftime("%b %d, %Y")
    
    elif format == "iso":
        return dt.isoformat()
    
    elif format == "short":
        return dt.strftime("%Y-%m-%d %H:%M")
    
    elif format == "long":
        return dt.strftime("%B %d, %Y at %I:%M %p")
    
    else:
        return str(dt)


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def format_number(number: int, compact: bool = False) -> str:
    """
    Format number with thousand separators or compact notation
    
    Args:
        number: Number to format
        compact: Use compact notation (1.5K instead of 1,500)
        
    Returns:
        Formatted number string
    """
    if compact:
        if number >= 1_000_000_000:
            return f"{number / 1_000_000_000:.1f}B"
        elif number >= 1_000_000:
            return f"{number / 1_000_000:.1f}M"
        elif number >= 1_000:
            return f"{number / 1_000:.1f}K"
        else:
            return str(number)
    else:
        return f"{number:,}"


def format_ip_with_country(ip: str, country_code: Optional[str] = None) -> str:
    """
    Format IP address with country flag
    
    Args:
        ip: IP address
        country_code: Country code (e.g., "US", "CN")
        
    Returns:
        Formatted IP with flag
    """
    if country_code:
        # Map country codes to flag emojis (simplified)
        flag_map = {
            "US": "🇺🇸", "CN": "🇨🇳", "RU": "🇷🇺", "DE": "🇩🇪",
            "GB": "🇬🇧", "FR": "🇫🇷", "IN": "🇮🇳", "BR": "🇧🇷"
        }
        flag = flag_map.get(country_code.upper(), "🏳️")
        return f"{flag} {ip}"
    return ip


def format_hash(hash_value: str, length: int = 16) -> str:
    """
    Format hash for display (truncate if too long)
    
    Args:
        hash_value: Full hash value
        length: Maximum length to display
        
    Returns:
        Formatted hash
    """
    if len(hash_value) > length:
        return f"{hash_value[:length]}..."
    return hash_value


def format_url(url: str, max_length: int = 50) -> str:
    """
    Format URL for display
    
    Args:
        url: Full URL
        max_length: Maximum length to display
        
    Returns:
        Formatted URL
    """
    if len(url) > max_length:
        return f"{url[:max_length]}..."
    return url


def format_ioc_type(ioc_type: str) -> str:
    """
    Format IOC type with icon
    
    Args:
        ioc_type: IOC type (ip_address, domain, url, etc.)
        
    Returns:
        Formatted type with icon
    """
    icon_map = {
        "ip_address": "📡",
        "domain": "🌐",
        "url": "🔗",
        "file_hash": "🔐",
        "email": "📧",
        "cve": "🔓",
        "malware": "🦠",
        "campaign": "🎯"
    }
    
    icon = icon_map.get(ioc_type, "📌")
    formatted_type = ioc_type.replace("_", " ").title()
    return f"{icon} {formatted_type}"


def format_json(data: Dict, indent: int = 2) -> str:
    """
    Format dictionary as pretty JSON
    
    Args:
        data: Dictionary to format
        indent: Indentation level
        
    Returns:
        Formatted JSON string
    """
    return json.dumps(data, indent=indent, default=str)


def format_percentage_change(old_value: float, new_value: float) -> str:
    """
    Format percentage change between two values
    
    Args:
        old_value: Old value
        new_value: New value
        
    Returns:
        Formatted percentage change (e.g., "+15.3%" or "-7.2%")
    """
    if old_value == 0:
        return "N/A"
    
    change = ((new_value - old_value) / old_value) * 100
    sign = "+" if change > 0 else ""
    return f"{sign}{change:.1f}%"


def format_duration(seconds: int) -> str:
    """
    Format duration in human-readable format
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration (e.g., "2h 15m" or "45s")
    """
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds}s" if remaining_seconds else f"{minutes}m"
    elif seconds < 86400:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        return f"{hours}h {remaining_minutes}m" if remaining_minutes else f"{hours}h"
    else:
        days = seconds // 86400
        remaining_hours = (seconds % 86400) // 3600
        return f"{days}d {remaining_hours}h" if remaining_hours else f"{days}d"


def format_list(items: List[str], max_items: int = 5, separator: str = ", ") -> str:
    """
    Format list of items for display
    
    Args:
        items: List of items
        max_items: Maximum items to show
        separator: Separator between items
        
    Returns:
        Formatted string
    """
    if not items:
        return "None"
    
    if len(items) <= max_items:
        return separator.join(items)
    else:
        shown = separator.join(items[:max_items])
        remaining = len(items) - max_items
        return f"{shown} (+{remaining} more)"


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate text to maximum length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def format_tags(tags: List[str]) -> str:
    """
    Format tags for display
    
    Args:
        tags: List of tags
        
    Returns:
        Formatted tags with badges
    """
    if not tags:
        return ""
    
    formatted_tags = [f"#{tag}" for tag in tags]
    return " ".join(formatted_tags)