"""
AbuseIPDB API Client
Provides IP abuse reports and confidence scores
"""

import logging
from typing import Dict, Optional, List
from pathlib import Path
from datetime import datetime, timedelta
from .base_client import BaseIntelligenceClient

logger = logging.getLogger(__name__)


class AbuseIPDBClient(BaseIntelligenceClient):
    """
    AbuseIPDB API client for IP reputation checking

    Free tier limits: 1000 requests per day
    API docs: https://docs.abuseipdb.com/
    """

    def __init__(self, api_key: str, cache_dir: Path, cache_ttl: int = 3600):
        """
        Initialize AbuseIPDB client

        Args:
            api_key: AbuseIPDB API key
            cache_dir: Directory for caching responses
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
        """
        super().__init__(api_key, cache_dir, cache_ttl)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.min_request_interval = 1.0  # Be respectful with API
        logger.info("AbuseIPDB client initialized")

    def lookup(self, ip_address: str, use_cache: bool = True, max_age_days: int = 90) -> Dict:
        """
        Look up IP address in AbuseIPDB

        Args:
            ip_address: IP address to query
            use_cache: Whether to use cached data
            max_age_days: Maximum age of reports to include (default: 90 days)

        Returns:
            Dictionary with AbuseIPDB analysis results
        """
        cache_key = f"abuseipdb_{ip_address}_{max_age_days}"

        # Check cache first
        if use_cache:
            cached = self._get_cached(cache_key)
            if cached:
                return cached

        # Make API request
        url = f"{self.base_url}/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_days,
            'verbose': ''  # Include detailed report data
        }

        response = self._make_request(url, headers=headers, params=params)

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
                'service': 'abuseipdb'
            }

    def _parse_response(self, response: Dict) -> Dict:
        """
        Parse AbuseIPDB API response into standardized format

        Args:
            response: Raw API response

        Returns:
            Parsed and normalized data
        """
        try:
            data = response.get('data', {})

            # Extract basic information
            ip_address = data.get('ipAddress', 'Unknown')
            is_public = data.get('isPublic', False)
            ip_version = data.get('ipVersion', 4)
            is_whitelisted = data.get('isWhitelisted', False)

            # Extract abuse metrics
            abuse_confidence_score = data.get('abuseConfidenceScore', 0)
            country_code = data.get('countryCode', 'Unknown')
            country_name = data.get('countryName', 'Unknown')
            usage_type = data.get('usageType', 'Unknown')
            isp = data.get('isp', 'Unknown')
            domain = data.get('domain', 'Unknown')
            hostnames = data.get('hostnames', [])
            tor = data.get('tor', False)

            # Extract report statistics
            total_reports = data.get('totalReports', 0)
            num_distinct_users = data.get('numDistinctUsers', 0)
            last_reported_at = data.get('lastReportedAt')

            # Extract detailed reports (if available)
            reports = []
            for report in data.get('reports', [])[:10]:  # Top 10 most recent
                reports.append({
                    'reported_at': report.get('reportedAt'),
                    'comment': report.get('comment', '')[:200],  # First 200 chars
                    'categories': report.get('categories', []),
                    'reporter_id': report.get('reporterId'),
                    'reporter_country': report.get('reporterCountryCode')
                })

            # Determine threat status
            is_threat = abuse_confidence_score >= 25  # 25% threshold
            threat_score = abuse_confidence_score  # Already 0-100

            # Determine threat level
            if abuse_confidence_score >= 80:
                threat_level = 'critical'
            elif abuse_confidence_score >= 60:
                threat_level = 'high'
            elif abuse_confidence_score >= 30:
                threat_level = 'medium'
            elif abuse_confidence_score >= 10:
                threat_level = 'low'
            else:
                threat_level = 'clean'

            # Build threat indicators
            threat_indicators = []
            if total_reports > 0:
                threat_indicators.append(
                    f"{total_reports} abuse reports from {num_distinct_users} users"
                )
            if is_whitelisted:
                threat_indicators.append("IP is whitelisted")
            if usage_type in ['Data Center/Web Hosting/Transit', 'Fixed Line ISP']:
                threat_indicators.append(f"Usage type: {usage_type}")

            parsed = {
                'service': 'abuseipdb',
                'ip_address': ip_address,
                'is_public': is_public,
                'ip_version': ip_version,
                'is_whitelisted': is_whitelisted,
                'abuse_confidence_score': abuse_confidence_score,
                'threat_score': threat_score,
                'threat_level': threat_level,
                'is_threat': is_threat,
                'location': {
                    'country_code': country_code,
                    'country_name': country_name
                },
                'network_info': {
                    'usage_type': usage_type,
                    'isp': isp,
                    'domain': domain,
                    'hostnames': hostnames,
                    'tor': tor
                },
                'report_stats': {
                    'total_reports': total_reports,
                    'distinct_reporters': num_distinct_users,
                    'last_reported_at': last_reported_at
                },
                'recent_reports': reports,
                'threat_indicators': threat_indicators
            }

            logger.info(
                f"AbuseIPDB: {ip_address} - "
                f"Confidence: {abuse_confidence_score}%, "
                f"Reports: {total_reports}"
            )

            return parsed

        except Exception as e:
            logger.error(f"Error parsing AbuseIPDB response: {e}")
            return {
                'error': f'Parse error: {str(e)}',
                'service': 'abuseipdb',
                'raw_response': response
            }

    def report_ip(self, ip_address: str, categories: List[int], comment: str = "") -> Dict:
        """
        Report an IP address to AbuseIPDB

        Args:
            ip_address: IP address to report
            categories: List of abuse category IDs (see AbuseIPDB docs)
            comment: Optional comment describing the abuse

        Returns:
            Dictionary with report submission result

        Category IDs:
            3: Fraud Orders
            4: DDoS Attack
            5: FTP Brute-Force
            6: Ping of Death
            7: Phishing
            8: Fraud VoIP
            9: Open Proxy
            10: Web Spam
            11: Email Spam
            14: Port Scan
            15: Hacking
            16: SQL Injection
            18: Brute-Force
            19: Bad Web Bot
            20: Exploited Host
            21: Web App Attack
            22: SSH
            23: IoT Targeted
        """
        url = f"{self.base_url}/report"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            'ip': ip_address,
            'categories': ','.join(map(str, categories)),
            'comment': comment
        }

        response = self._make_request(url, headers=headers, params=params)

        if response and not response.get('error'):
            return {
                'success': True,
                'ip_address': ip_address,
                'message': 'Report submitted successfully',
                'data': response.get('data', {})
            }

        return {
            'success': False,
            'error': response.get('error', 'Report submission failed'),
            'ip_address': ip_address
        }

    def check_block(self, network: str, max_age_days: int = 30) -> Dict:
        """
        Check entire CIDR block for abuse

        Args:
            network: CIDR notation (e.g., "192.168.1.0/24")
            max_age_days: Maximum age of reports

        Returns:
            Dictionary with block analysis
        """
        url = f"{self.base_url}/check-block"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            'network': network,
            'maxAgeInDays': max_age_days
        }

        response = self._make_request(url, headers=headers, params=params)

        if response and not response.get('error'):
            data = response.get('data', {})
            return {
                'network': network,
                'network_address': data.get('networkAddress'),
                'netmask': data.get('netmask'),
                'min_address': data.get('minAddress'),
                'max_address': data.get('maxAddress'),
                'num_possible_hosts': data.get('numPossibleHosts'),
                'address_space_desc': data.get('addressSpaceDesc'),
                'reported_addresses': data.get('reportedAddress', [])
            }

        return {
            'error': response.get('error', 'Block check failed'),
            'network': network
        }

    def get_blacklist(self, confidence_minimum: int = 90, limit: int = 100) -> Dict:
        """
        Get list of most reported IPs (requires paid plan)

        Args:
            confidence_minimum: Minimum abuse confidence score (25-100)
            limit: Number of results to return

        Returns:
            Dictionary with blacklist data
        """
        url = f"{self.base_url}/blacklist"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            'confidenceMinimum': confidence_minimum,
            'limit': limit
        }

        response = self._make_request(url, headers=headers, params=params)

        if response and not response.get('error'):
            data = response.get('data', [])
            return {
                'confidence_minimum': confidence_minimum,
                'total': len(data),
                'blacklist': data
            }

        return {
            'error': response.get('error', 'Blacklist fetch failed'),
            'note': 'This endpoint may require a paid subscription'
        }
