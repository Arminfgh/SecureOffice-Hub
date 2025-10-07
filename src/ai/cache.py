"""
AI Response Cache
Cache OpenAI responses to reduce API costs and improve performance
"""

import hashlib
import json
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import redis
from src.config.settings import get_settings


settings = get_settings()


class AICache:
    """Cache for AI analysis responses"""
    
    def __init__(self, redis_url: Optional[str] = None, ttl: int = None):
        """
        Initialize cache
        
        Args:
            redis_url: Redis connection URL
            ttl: Time to live in seconds (default from settings)
        """
        self.redis_url = redis_url or settings.REDIS_URL
        self.ttl = ttl or settings.CACHE_TTL
        self.redis_client = None
        
        try:
            self.redis_client = redis.from_url(self.redis_url)
            self.redis_client.ping()
            self.enabled = True
        except:
            self.enabled = False
            self.fallback_cache = {}
    
    def _generate_cache_key(self, analysis_type: str, input_data: str) -> str:
        """
        Generate cache key from input
        
        Args:
            analysis_type: Type of analysis (url, ip, hash)
            input_data: Input data to analyze
            
        Returns:
            Cache key
        """
        # Create unique hash of input
        data_str = f"{analysis_type}:{input_data}"
        hash_obj = hashlib.sha256(data_str.encode())
        return f"ai_cache:{hash_obj.hexdigest()}"
    
    def get(self, analysis_type: str, input_data: str) -> Optional[Dict]:
        """
        Get cached analysis result
        
        Args:
            analysis_type: Type of analysis
            input_data: Input data
            
        Returns:
            Cached result or None
        """
        cache_key = self._generate_cache_key(analysis_type, input_data)
        
        if self.enabled and self.redis_client:
            try:
                cached = self.redis_client.get(cache_key)
                if cached:
                    result = json.loads(cached)
                    result['from_cache'] = True
                    return result
            except Exception as e:
                print(f"Cache get error: {e}")
        else:
            # Fallback to in-memory cache
            if cache_key in self.fallback_cache:
                entry = self.fallback_cache[cache_key]
                if entry['expires_at'] > datetime.now():
                    result = entry['data']
                    result['from_cache'] = True
                    return result
                else:
                    del self.fallback_cache[cache_key]
        
        return None
    
    def set(self, analysis_type: str, input_data: str, result: Dict):
        """
        Cache analysis result
        
        Args:
            analysis_type: Type of analysis
            input_data: Input data
            result: Analysis result to cache
        """
        cache_key = self._generate_cache_key(analysis_type, input_data)
        
        # Add cache metadata
        cached_result = result.copy()
        cached_result['cached_at'] = datetime.now().isoformat()
        
        if self.enabled and self.redis_client:
            try:
                self.redis_client.setex(
                    cache_key,
                    self.ttl,
                    json.dumps(cached_result)
                )
            except Exception as e:
                print(f"Cache set error: {e}")
        else:
            # Fallback to in-memory cache
            self.fallback_cache[cache_key] = {
                'data': cached_result,
                'expires_at': datetime.now() + timedelta(seconds=self.ttl)
            }
    
    def invalidate(self, analysis_type: str, input_data: str):
        """
        Invalidate a cached result
        
        Args:
            analysis_type: Type of analysis
            input_data: Input data
        """
        cache_key = self._generate_cache_key(analysis_type, input_data)
        
        if self.enabled and self.redis_client:
            try:
                self.redis_client.delete(cache_key)
            except Exception as e:
                print(f"Cache invalidate error: {e}")
        else:
            self.fallback_cache.pop(cache_key, None)
    
    def clear_all(self):
        """Clear all cached results"""
        if self.enabled and self.redis_client:
            try:
                # Delete all keys matching pattern
                for key in self.redis_client.scan_iter("ai_cache:*"):
                    self.redis_client.delete(key)
            except Exception as e:
                print(f"Cache clear error: {e}")
        else:
            self.fallback_cache.clear()
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        if self.enabled and self.redis_client:
            try:
                total_keys = len(list(self.redis_client.scan_iter("ai_cache:*")))
                info = self.redis_client.info('stats')
                
                return {
                    'enabled': True,
                    'backend': 'redis',
                    'total_cached_items': total_keys,
                    'ttl_seconds': self.ttl,
                    'hits': info.get('keyspace_hits', 0),
                    'misses': info.get('keyspace_misses', 0)
                }
            except:
                pass
        
        return {
            'enabled': False,
            'backend': 'memory',
            'total_cached_items': len(self.fallback_cache),
            'ttl_seconds': self.ttl
        }


class CachedAnalyzer:
    """Wrapper around ThreatAnalyzer with caching"""
    
    def __init__(self, analyzer, cache: Optional[AICache] = None):
        """
        Initialize cached analyzer
        
        Args:
            analyzer: ThreatAnalyzer instance
            cache: AICache instance (creates new if None)
        """
        self.analyzer = analyzer
        self.cache = cache or AICache()
    
    def analyze_url(self, url: str) -> Dict:
        """Analyze URL with caching"""
        # Check cache
        cached = self.cache.get('url', url)
        if cached:
            return cached
        
        # Perform analysis
        result = self.analyzer.analyze_url(url)
        
        # Cache result
        self.cache.set('url', url, result)
        
        return result
    
    def analyze_ip(self, ip_address: str, context: Optional[Dict] = None) -> Dict:
        """Analyze IP with caching"""
        cache_key = f"{ip_address}:{json.dumps(context)}" if context else ip_address
        
        cached = self.cache.get('ip', cache_key)
        if cached:
            return cached
        
        result = self.analyzer.analyze_ip(ip_address, context)
        self.cache.set('ip', cache_key, result)
        
        return result
    
    def analyze_file_hash(
        self,
        file_hash: str,
        hash_type: str = "sha256",
        context: Optional[Dict] = None
    ) -> Dict:
        """Analyze hash with caching"""
        cache_key = f"{file_hash}:{hash_type}:{json.dumps(context)}" if context else f"{file_hash}:{hash_type}"
        
        cached = self.cache.get('hash', cache_key)
        if cached:
            return cached
        
        result = self.analyzer.analyze_file_hash(file_hash, hash_type, context)
        self.cache.set('hash', cache_key, result)
        
        return result