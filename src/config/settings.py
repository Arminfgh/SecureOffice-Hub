"""
Application Settings
Environment-based configuration using Pydantic Settings
"""

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    """Application settings from environment variables"""
    
    # OpenAI Configuration
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4-turbo-preview"
    VIRUSTOTAL_API_KEY: str = ""

    # Database Configuration
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/threatscope"
    DB_ECHO: bool = False
    
    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL: int = 3600
    
    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_RELOAD: bool = True
    SECRET_KEY: str = "your-secret-key-change-this"
    
    # Threat Intelligence Feeds
    ABUSEIPDB_API_KEY: str = ""
    ALIENVAULT_OTX_API_KEY: str = ""
    URLHAUS_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    
    # Feed Update Settings
    FEED_UPDATE_INTERVAL: int = 3600  # seconds
    FEED_RETRY_ATTEMPTS: int = 3
    
    # Bloom Filter Configuration
    BLOOM_FILTER_SIZE: int = 1000000
    BLOOM_FILTER_HASH_COUNT: int = 7
    BLOOM_FILTER_ERROR_RATE: float = 0.001
    
    # Dashboard Configuration
    STREAMLIT_SERVER_PORT: int = 8501
    STREAMLIT_SERVER_ADDRESS: str = "0.0.0.0"
    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/threatscope.log"
    
    # Performance Tuning
    MAX_GRAPH_NODES: int = 10000
    ANALYSIS_TIMEOUT: int = 30
    MAX_CONCURRENT_REQUESTS: int = 100
    
    # Security Settings
    ENABLE_AUTH: bool = True
    SESSION_TIMEOUT: int = 3600
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8501"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()