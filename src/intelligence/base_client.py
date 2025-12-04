"""
Base Client for Threat Intelligence APIs
Provides caching, rate limiting, and error handling
"""

import requests
import logging
import time
import json
from typing import Dict, Optional
from datetime import datetime, timedelta
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)


class BaseIntelligenceClient:
    """
    Base class for all threat intelligence API clients
    Provides common functionality: caching, rate limiting, error handling
    """

    def __init__(self, api_key: str, cache_dir: Path, cache_ttl: int = 3600):
        """
        Args:
            api_key: API key for the service
            cache_dir: Directory to store cached responses
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
        """
        self.api_key = api_key
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        self.last_request_time = 0
        self.min_request_interval = 1.0  # Minimum seconds between requests

        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path for a given key"""
        # Use hash to create safe filename
        key_hash = hashlib.md5(cache_key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"

    def _get_cached(self, cache_key: str) -> Optional[Dict]:
        """
        Retrieve cached data if available and not expired

        Returns:
            Cached data or None if not found/expired
        """
        cache_path = self._get_cache_path(cache_key)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)

            # Check expiration
            cached_time = datetime.fromisoformat(cache_data['timestamp'])
            if datetime.now() - cached_time > timedelta(seconds=self.cache_ttl):
                logger.debug(f"Cache expired for key: {cache_key}")
                return None

            logger.info(f"Cache hit for key: {cache_key}")
            return cache_data['data']

        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None

    def _save_cache(self, cache_key: str, data: Dict):
        """Save data to cache"""
        cache_path = self._get_cache_path(cache_key)

        try:
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'key': cache_key,
                'data': data
            }

            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)

            logger.debug(f"Cached data for key: {cache_key}")

        except Exception as e:
            logger.error(f"Error saving cache: {e}")

    def _rate_limit(self):
        """Enforce rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _make_request(self, url: str, headers: Dict = None, params: Dict = None,
                     timeout: int = 10) -> Optional[Dict]:
        """
        Make HTTP request with error handling

        Returns:
            Response JSON or None on error
        """
        try:
            self._rate_limit()

            response = requests.get(
                url,
                headers=headers or {},
                params=params or {},
                timeout=timeout
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 204:
                return {'message': 'No content available'}
            elif response.status_code == 404:
                return {'error': 'Not found', 'status_code': 404}
            elif response.status_code == 429:
                logger.warning("Rate limit exceeded")
                return {'error': 'Rate limit exceeded', 'status_code': 429}
            elif response.status_code == 403:
                logger.error("API key invalid or forbidden")
                return {'error': 'Forbidden - check API key', 'status_code': 403}
            else:
                logger.error(f"HTTP {response.status_code}: {response.text}")
                return {'error': f'HTTP {response.status_code}', 'status_code': response.status_code}

        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for {url}")
            return {'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {'error': str(e)}

    def lookup(self, query: str, use_cache: bool = True) -> Dict:
        """
        Lookup information for a query (to be implemented by subclasses)

        Args:
            query: IP address or other identifier
            use_cache: Whether to use cached data

        Returns:
            Dictionary with lookup results
        """
        raise NotImplementedError("Subclasses must implement lookup()")

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        cache_files = list(self.cache_dir.glob("*.json"))

        total_size = sum(f.stat().st_size for f in cache_files)

        return {
            'cache_entries': len(cache_files),
            'cache_size_bytes': total_size,
            'cache_size_mb': total_size / (1024 * 1024),
            'cache_dir': str(self.cache_dir)
        }

    def clear_cache(self):
        """Clear all cached data"""
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
            logger.info("Cache cleared")
            return {'success': True, 'message': 'Cache cleared'}
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return {'success': False, 'error': str(e)}
