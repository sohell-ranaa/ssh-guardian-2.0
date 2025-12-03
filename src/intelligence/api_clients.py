"""
Third-Party Threat Intelligence API Clients
Supports: VirusTotal, AbuseIPDB, Shodan
Includes: Rate limiting, caching, free tier optimization
"""

import requests
import time
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class APIRateLimiter:
    """Rate limiter to respect API quotas"""

    def __init__(self, requests_per_day: int, requests_per_minute: int = None):
        self.requests_per_day = requests_per_day
        self.requests_per_minute = requests_per_minute or 60
        self.daily_requests = []
        self.minute_requests = []

    def can_make_request(self) -> bool:
        """Check if we can make a request without exceeding limits"""
        now = datetime.now()

        # Clean old requests
        self.daily_requests = [ts for ts in self.daily_requests if now - ts < timedelta(days=1)]
        self.minute_requests = [ts for ts in self.minute_requests if now - ts < timedelta(minutes=1)]

        # Check limits
        if len(self.daily_requests) >= self.requests_per_day:
            logger.warning(f"Daily rate limit reached ({self.requests_per_day}/day)")
            return False

        if len(self.minute_requests) >= self.requests_per_minute:
            logger.warning(f"Minute rate limit reached ({self.requests_per_minute}/min)")
            return False

        return True

    def record_request(self):
        """Record that a request was made"""
        now = datetime.now()
        self.daily_requests.append(now)
        self.minute_requests.append(now)


class IntelligenceCache:
    """Persistent cache for API results to minimize requests"""

    def __init__(self, cache_dir: Path, cache_ttl_hours: int = 24):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(hours=cache_ttl_hours)

    def _get_cache_key(self, api_name: str, query: str) -> str:
        """Generate cache key"""
        return hashlib.md5(f"{api_name}:{query}".encode()).hexdigest()

    def get(self, api_name: str, query: str) -> Optional[Dict]:
        """Get cached result if available and fresh"""
        cache_key = self._get_cache_key(api_name, query)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)

            # Check if cache is still fresh
            cached_time = datetime.fromisoformat(cached_data['cached_at'])
            if datetime.now() - cached_time > self.cache_ttl:
                cache_file.unlink()  # Remove stale cache
                return None

            logger.debug(f"Cache hit for {api_name}:{query}")
            return cached_data['result']

        except Exception as e:
            logger.error(f"Cache read error: {e}")
            return None

    def set(self, api_name: str, query: str, result: Dict):
        """Store result in cache"""
        cache_key = self._get_cache_key(api_name, query)
        cache_file = self.cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'cached_at': datetime.now().isoformat(),
                    'api': api_name,
                    'query': query,
                    'result': result
                }, f)
            logger.debug(f"Cached result for {api_name}:{query}")
        except Exception as e:
            logger.error(f"Cache write error: {e}")


class VirusTotalClient:
    """
    VirusTotal API Client
    Free tier: 250 requests/day, 4 requests/minute
    """

    def __init__(self, api_key: str, cache: IntelligenceCache):
        self.api_key = api_key
        self.cache = cache
        self.rate_limiter = APIRateLimiter(requests_per_day=250, requests_per_minute=4)
        self.base_url = "https://www.virustotal.com/api/v3"

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP reputation on VirusTotal
        Returns: Dict with reputation data
        """
        # Check cache first
        cached = self.cache.get('virustotal', ip_address)
        if cached:
            return cached

        # Check rate limit
        if not self.rate_limiter.can_make_request():
            logger.warning(f"VirusTotal rate limit exceeded, skipping {ip_address}")
            return self._get_empty_response()

        try:
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }

            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = requests.get(url, headers=headers, timeout=10)

            self.rate_limiter.record_request()

            if response.status_code == 200:
                data = response.json()
                result = self._parse_response(data)
                self.cache.set('virustotal', ip_address, result)
                return result
            elif response.status_code == 404:
                # IP not found in VT database
                result = self._get_empty_response()
                result['status'] = 'not_found'
                self.cache.set('virustotal', ip_address, result)
                return result
            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return self._get_empty_response()

        except Exception as e:
            logger.error(f"VirusTotal API exception: {e}")
            return self._get_empty_response()

    def _parse_response(self, data: Dict) -> Dict:
        """Parse VirusTotal API response"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})

            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            harmless = last_analysis_stats.get('harmless', 0)
            undetected = last_analysis_stats.get('undetected', 0)

            total_scans = malicious + suspicious + harmless + undetected
            detection_rate = (malicious + suspicious) / total_scans if total_scans > 0 else 0

            # Calculate risk score (0-100)
            risk_score = min(100, int(detection_rate * 100 + malicious * 5))

            return {
                'status': 'success',
                'source': 'virustotal',
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'harmless_count': harmless,
                'total_scans': total_scans,
                'detection_rate': round(detection_rate, 3),
                'risk_score': risk_score,
                'reputation': attributes.get('reputation', 0),
                'country': attributes.get('country', 'Unknown'),
                'asn': attributes.get('asn', 0),
                'as_owner': attributes.get('as_owner', 'Unknown'),
                'is_malicious': malicious > 0,
                'categories': attributes.get('categories', {}),
                'last_analysis_date': attributes.get('last_analysis_date', None)
            }
        except Exception as e:
            logger.error(f"VirusTotal response parse error: {e}")
            return self._get_empty_response()

    def _get_empty_response(self) -> Dict:
        """Return empty response structure"""
        return {
            'status': 'error',
            'source': 'virustotal',
            'malicious_count': 0,
            'suspicious_count': 0,
            'harmless_count': 0,
            'total_scans': 0,
            'detection_rate': 0,
            'risk_score': 0,
            'is_malicious': False
        }


class AbuseIPDBClient:
    """
    AbuseIPDB API Client
    Free tier: 1000 requests/day
    """

    def __init__(self, api_key: str, cache: IntelligenceCache):
        self.api_key = api_key
        self.cache = cache
        self.rate_limiter = APIRateLimiter(requests_per_day=1000, requests_per_minute=60)
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Check IP on AbuseIPDB
        max_age_days: Only consider reports within this timeframe
        """
        # Check cache
        cached = self.cache.get('abuseipdb', ip_address)
        if cached:
            return cached

        # Check rate limit
        if not self.rate_limiter.can_make_request():
            logger.warning(f"AbuseIPDB rate limit exceeded, skipping {ip_address}")
            return self._get_empty_response()

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }

            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": max_age_days,
                "verbose": ""
            }

            url = f"{self.base_url}/check"
            response = requests.get(url, headers=headers, params=params, timeout=10)

            self.rate_limiter.record_request()

            if response.status_code == 200:
                data = response.json()
                result = self._parse_response(data)
                self.cache.set('abuseipdb', ip_address, result)
                return result
            else:
                logger.error(f"AbuseIPDB API error: {response.status_code}")
                return self._get_empty_response()

        except Exception as e:
            logger.error(f"AbuseIPDB API exception: {e}")
            return self._get_empty_response()

    def _parse_response(self, data: Dict) -> Dict:
        """Parse AbuseIPDB response"""
        try:
            ip_data = data.get('data', {})

            abuse_confidence_score = ip_data.get('abuseConfidenceScore', 0)
            total_reports = ip_data.get('totalReports', 0)
            num_distinct_users = ip_data.get('numDistinctUsers', 0)

            # Calculate risk score
            risk_score = min(100, abuse_confidence_score)

            return {
                'status': 'success',
                'source': 'abuseipdb',
                'abuse_confidence_score': abuse_confidence_score,
                'total_reports': total_reports,
                'num_distinct_users': num_distinct_users,
                'risk_score': risk_score,
                'is_whitelisted': ip_data.get('isWhitelisted', False),
                'is_malicious': abuse_confidence_score > 50,
                'country_code': ip_data.get('countryCode', 'Unknown'),
                'usage_type': ip_data.get('usageType', 'Unknown'),
                'isp': ip_data.get('isp', 'Unknown'),
                'domain': ip_data.get('domain', 'Unknown'),
                'is_tor': ip_data.get('isTor', False),
                'last_reported_at': ip_data.get('lastReportedAt', None)
            }
        except Exception as e:
            logger.error(f"AbuseIPDB response parse error: {e}")
            return self._get_empty_response()

    def _get_empty_response(self) -> Dict:
        """Return empty response structure"""
        return {
            'status': 'error',
            'source': 'abuseipdb',
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'risk_score': 0,
            'is_malicious': False
        }


class ShodanClient:
    """
    Shodan API Client
    Free tier: Limited queries, basic info only
    """

    def __init__(self, api_key: str, cache: IntelligenceCache):
        self.api_key = api_key
        self.cache = cache
        self.rate_limiter = APIRateLimiter(requests_per_day=100, requests_per_minute=10)
        self.base_url = "https://api.shodan.io"

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Get Shodan information for IP
        Returns infrastructure and vulnerability data
        """
        # Check cache
        cached = self.cache.get('shodan', ip_address)
        if cached:
            return cached

        # Check rate limit
        if not self.rate_limiter.can_make_request():
            logger.warning(f"Shodan rate limit exceeded, skipping {ip_address}")
            return self._get_empty_response()

        try:
            params = {"key": self.api_key}
            url = f"{self.base_url}/shodan/host/{ip_address}"

            response = requests.get(url, params=params, timeout=10)

            self.rate_limiter.record_request()

            if response.status_code == 200:
                data = response.json()
                result = self._parse_response(data)
                self.cache.set('shodan', ip_address, result)
                return result
            elif response.status_code == 404:
                # IP not found
                result = self._get_empty_response()
                result['status'] = 'not_found'
                self.cache.set('shodan', ip_address, result)
                return result
            else:
                logger.error(f"Shodan API error: {response.status_code}")
                return self._get_empty_response()

        except Exception as e:
            logger.error(f"Shodan API exception: {e}")
            return self._get_empty_response()

    def _parse_response(self, data: Dict) -> Dict:
        """Parse Shodan response"""
        try:
            # Extract key information
            ports = data.get('ports', [])
            vulns = data.get('vulns', [])
            tags = data.get('tags', [])

            # Calculate risk based on vulnerabilities and exposed services
            risk_score = 0
            if vulns:
                risk_score += min(50, len(vulns) * 10)
            if 22 in ports:  # SSH port exposed
                risk_score += 20
            if any(tag in ['malware', 'compromised', 'tor'] for tag in tags):
                risk_score += 30

            risk_score = min(100, risk_score)

            return {
                'status': 'success',
                'source': 'shodan',
                'open_ports': ports,
                'num_ports': len(ports),
                'vulnerabilities': vulns,
                'num_vulnerabilities': len(vulns),
                'tags': tags,
                'risk_score': risk_score,
                'is_malicious': risk_score > 60,
                'hostnames': data.get('hostnames', []),
                'os': data.get('os', 'Unknown'),
                'organization': data.get('org', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'asn': data.get('asn', 'Unknown'),
                'country': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'last_update': data.get('last_update', None)
            }
        except Exception as e:
            logger.error(f"Shodan response parse error: {e}")
            return self._get_empty_response()

    def _get_empty_response(self) -> Dict:
        """Return empty response structure"""
        return {
            'status': 'error',
            'source': 'shodan',
            'open_ports': [],
            'num_ports': 0,
            'vulnerabilities': [],
            'num_vulnerabilities': 0,
            'risk_score': 0,
            'is_malicious': False
        }


class ThreatIntelligenceAggregator:
    """
    Aggregates results from multiple threat intelligence sources
    Provides unified risk scoring and analysis
    """

    def __init__(self, config: Dict[str, str], cache_dir: Path):
        """
        Initialize aggregator with API keys
        config: {
            'virustotal_api_key': 'key',
            'abuseipdb_api_key': 'key',
            'shodan_api_key': 'key'
        }
        """
        self.cache = IntelligenceCache(cache_dir)

        # Initialize clients only if API keys are provided
        self.vt_client = VirusTotalClient(config.get('virustotal_api_key'), self.cache) if config.get('virustotal_api_key') else None
        self.abuse_client = AbuseIPDBClient(config.get('abuseipdb_api_key'), self.cache) if config.get('abuseipdb_api_key') else None
        self.shodan_client = ShodanClient(config.get('shodan_api_key'), self.cache) if config.get('shodan_api_key') else None

        logger.info(f"ThreatIntelligenceAggregator initialized with clients: "
                   f"VT={self.vt_client is not None}, "
                   f"Abuse={self.abuse_client is not None}, "
                   f"Shodan={self.shodan_client is not None}")

    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform comprehensive IP analysis using all available sources
        Returns aggregated threat intelligence data
        """
        results = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'aggregated_score': 0,
            'is_malicious': False,
            'threat_level': 'unknown',
            'recommendations': []
        }

        # Query all available sources
        if self.vt_client:
            results['sources']['virustotal'] = self.vt_client.check_ip(ip_address)

        if self.abuse_client:
            results['sources']['abuseipdb'] = self.abuse_client.check_ip(ip_address)

        if self.shodan_client:
            results['sources']['shodan'] = self.shodan_client.check_ip(ip_address)

        # Aggregate scores
        results = self._aggregate_results(results)

        return results

    def _aggregate_results(self, results: Dict) -> Dict:
        """Aggregate scores from multiple sources"""
        sources = results['sources']
        scores = []
        is_malicious_votes = 0

        # Collect scores
        for source_name, source_data in sources.items():
            if source_data.get('status') == 'success':
                scores.append(source_data.get('risk_score', 0))
                if source_data.get('is_malicious'):
                    is_malicious_votes += 1

        # Calculate aggregated score
        if scores:
            # Weighted average with bias towards higher scores
            max_score = max(scores)
            avg_score = sum(scores) / len(scores)
            results['aggregated_score'] = int((max_score * 0.6) + (avg_score * 0.4))
        else:
            results['aggregated_score'] = 0

        # Determine if malicious (majority vote)
        results['is_malicious'] = is_malicious_votes >= 2 or (is_malicious_votes >= 1 and results['aggregated_score'] > 70)

        # Assign threat level
        score = results['aggregated_score']
        if score >= 80:
            results['threat_level'] = 'critical'
            results['recommendations'].append('Block IP immediately')
            results['recommendations'].append('Investigate all activity from this IP')
        elif score >= 60:
            results['threat_level'] = 'high'
            results['recommendations'].append('Monitor closely and consider blocking')
        elif score >= 40:
            results['threat_level'] = 'medium'
            results['recommendations'].append('Increase monitoring for this IP')
        elif score >= 20:
            results['threat_level'] = 'low'
            results['recommendations'].append('Standard monitoring')
        else:
            results['threat_level'] = 'clean'

        return results


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Example configuration
    config = {
        'virustotal_api_key': 'YOUR_VT_KEY',
        'abuseipdb_api_key': 'YOUR_ABUSE_KEY',
        'shodan_api_key': 'YOUR_SHODAN_KEY'
    }

    cache_dir = Path("/tmp/ssh_guardian_intel_cache")

    aggregator = ThreatIntelligenceAggregator(config, cache_dir)

    # Test with a known malicious IP (example)
    result = aggregator.analyze_ip("185.220.101.1")

    print(json.dumps(result, indent=2))
