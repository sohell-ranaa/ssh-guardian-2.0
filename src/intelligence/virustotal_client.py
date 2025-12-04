"""
VirusTotal API Client
Provides IP reputation and threat intelligence from VirusTotal
"""

import logging
from typing import Dict, Optional
from pathlib import Path
from .base_client import BaseIntelligenceClient

logger = logging.getLogger(__name__)


class VirusTotalClient(BaseIntelligenceClient):
    """
    VirusTotal API client for IP address intelligence

    Free tier limits: 4 requests per minute
    API docs: https://developers.virustotal.com/reference/ip-info
    """

    def __init__(self, api_key: str, cache_dir: Path, cache_ttl: int = 3600):
        """
        Initialize VirusTotal client

        Args:
            api_key: VirusTotal API key
            cache_dir: Directory for caching responses
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
        """
        super().__init__(api_key, cache_dir, cache_ttl)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.min_request_interval = 15.0  # 4 req/min = 15 sec between requests
        logger.info("VirusTotal client initialized")

    def lookup(self, ip_address: str, use_cache: bool = True) -> Dict:
        """
        Look up IP address in VirusTotal

        Args:
            ip_address: IP address to query
            use_cache: Whether to use cached data

        Returns:
            Dictionary with VirusTotal analysis results
        """
        cache_key = f"vt_{ip_address}"

        # Check cache first
        if use_cache:
            cached = self._get_cached(cache_key)
            if cached:
                return cached

        # Make API request
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        response = self._make_request(url, headers=headers)

        if response and not response.get('error'):
            result = self._parse_response(response)

            # Cache successful response
            if use_cache:
                self._save_cache(cache_key, result)

            return result
        else:
            # Return error information
            return {
                'error': response.get('error', 'Unknown error'),
                'status_code': response.get('status_code'),
                'service': 'virustotal'
            }

    def _parse_response(self, response: Dict) -> Dict:
        """
        Parse VirusTotal API response into standardized format

        Args:
            response: Raw API response

        Returns:
            Parsed and normalized data
        """
        try:
            data = response.get('data', {})
            attributes = data.get('attributes', {})

            # Extract analysis stats
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            harmless = last_analysis_stats.get('harmless', 0)
            undetected = last_analysis_stats.get('undetected', 0)
            timeout = last_analysis_stats.get('timeout', 0)

            total_scanners = malicious + suspicious + harmless + undetected + timeout

            # Extract additional information
            as_owner = attributes.get('as_owner', 'Unknown')
            country = attributes.get('country', 'Unknown')
            network = attributes.get('network', 'Unknown')

            # Get reputation score (if available)
            reputation = attributes.get('reputation', 0)

            # Determine threat status
            is_malicious = malicious > 0 or suspicious > 2
            threat_score = 0

            if total_scanners > 0:
                threat_score = ((malicious * 100) + (suspicious * 50)) / total_scanners

            # Extract detection details
            last_analysis_results = attributes.get('last_analysis_results', {})
            detections = []

            for scanner, result in last_analysis_results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'scanner': scanner,
                        'category': result.get('category'),
                        'result': result.get('result', 'Unknown')
                    })

            parsed = {
                'service': 'virustotal',
                'ip_address': data.get('id', 'Unknown'),
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'harmless_count': harmless,
                'undetected_count': undetected,
                'total_scanners': total_scanners,
                'is_malicious': is_malicious,
                'threat_score': round(threat_score, 2),
                'reputation': reputation,
                'network_info': {
                    'as_owner': as_owner,
                    'country': country,
                    'network': network
                },
                'detections': detections[:10],  # Top 10 detections
                'total_votes': attributes.get('total_votes', {}),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'raw_stats': last_analysis_stats
            }

            logger.info(f"VirusTotal: {malicious}/{total_scanners} flagged {data.get('id')} as malicious")

            return parsed

        except Exception as e:
            logger.error(f"Error parsing VirusTotal response: {e}")
            return {
                'error': f'Parse error: {str(e)}',
                'service': 'virustotal',
                'raw_response': response
            }

    def get_ip_comments(self, ip_address: str) -> Dict:
        """
        Get community comments for an IP address

        Args:
            ip_address: IP address to query

        Returns:
            Dictionary with comments
        """
        url = f"{self.base_url}/ip_addresses/{ip_address}/comments"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        response = self._make_request(url, headers=headers)

        if response and not response.get('error'):
            comments = []
            for item in response.get('data', []):
                attrs = item.get('attributes', {})
                comments.append({
                    'text': attrs.get('text', ''),
                    'date': attrs.get('date'),
                    'votes': attrs.get('votes', {})
                })

            return {
                'ip_address': ip_address,
                'comments': comments,
                'total': len(comments)
            }

        return {'error': 'Could not fetch comments', 'comments': []}

    def get_ip_votes(self, ip_address: str) -> Dict:
        """
        Get voting information for an IP address

        Args:
            ip_address: IP address to query

        Returns:
            Dictionary with vote counts
        """
        url = f"{self.base_url}/ip_addresses/{ip_address}/votes"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        response = self._make_request(url, headers=headers)

        if response and not response.get('error'):
            data = response.get('data', [])
            harmless_votes = sum(1 for v in data if v.get('attributes', {}).get('verdict') == 'harmless')
            malicious_votes = sum(1 for v in data if v.get('attributes', {}).get('verdict') == 'malicious')

            return {
                'ip_address': ip_address,
                'harmless': harmless_votes,
                'malicious': malicious_votes,
                'total': len(data)
            }

        return {'error': 'Could not fetch votes'}

    def get_related_domains(self, ip_address: str, limit: int = 10) -> Dict:
        """
        Get domains associated with an IP address

        Args:
            ip_address: IP address to query
            limit: Maximum number of domains to return

        Returns:
            Dictionary with related domains
        """
        url = f"{self.base_url}/ip_addresses/{ip_address}/resolutions"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        params = {'limit': limit}

        response = self._make_request(url, headers=headers, params=params)

        if response and not response.get('error'):
            domains = []
            for item in response.get('data', []):
                attrs = item.get('attributes', {})
                domains.append({
                    'domain': attrs.get('host_name', ''),
                    'date': attrs.get('date')
                })

            return {
                'ip_address': ip_address,
                'domains': domains,
                'total': len(domains)
            }

        return {'error': 'Could not fetch related domains', 'domains': []}
