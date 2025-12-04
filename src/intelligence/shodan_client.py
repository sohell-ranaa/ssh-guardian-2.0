"""
Shodan API Client
Provides IP information, open ports, vulnerabilities, and service details
"""

import logging
from typing import Dict, Optional, List
from pathlib import Path
from .base_client import BaseIntelligenceClient

logger = logging.getLogger(__name__)


class ShodanClient(BaseIntelligenceClient):
    """
    Shodan API client for IP address intelligence

    Free tier limits: 1 query credit per month (100 results)
    API docs: https://developer.shodan.io/api
    """

    def __init__(self, api_key: str, cache_dir: Path, cache_ttl: int = 3600):
        """
        Initialize Shodan client

        Args:
            api_key: Shodan API key
            cache_dir: Directory for caching responses
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
        """
        super().__init__(api_key, cache_dir, cache_ttl)
        self.base_url = "https://api.shodan.io"
        self.min_request_interval = 1.0  # Be respectful with API calls
        logger.info("Shodan client initialized")

    def lookup(self, ip_address: str, use_cache: bool = True) -> Dict:
        """
        Look up IP address in Shodan

        Args:
            ip_address: IP address to query
            use_cache: Whether to use cached data

        Returns:
            Dictionary with Shodan analysis results
        """
        cache_key = f"shodan_{ip_address}"

        # Check cache first
        if use_cache:
            cached = self._get_cached(cache_key)
            if cached:
                return cached

        # Make API request
        url = f"{self.base_url}/shodan/host/{ip_address}"
        params = {'key': self.api_key}

        response = self._make_request(url, params=params)

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
                'service': 'shodan'
            }

    def _parse_response(self, response: Dict) -> Dict:
        """
        Parse Shodan API response into standardized format

        Args:
            response: Raw API response

        Returns:
            Parsed and normalized data
        """
        try:
            # Extract basic information
            ip_address = response.get('ip_str', 'Unknown')
            hostnames = response.get('hostnames', [])
            domains = response.get('domains', [])
            country = response.get('country_name', 'Unknown')
            country_code = response.get('country_code', 'Unknown')
            city = response.get('city', 'Unknown')
            org = response.get('org', 'Unknown')
            isp = response.get('isp', 'Unknown')

            # Extract port and service information
            ports = response.get('ports', [])
            services = []
            vulnerabilities = []

            data = response.get('data', [])
            for service_data in data:
                service_info = {
                    'port': service_data.get('port'),
                    'transport': service_data.get('transport', 'tcp'),
                    'product': service_data.get('product', 'Unknown'),
                    'version': service_data.get('version', ''),
                    'banner': service_data.get('data', '')[:200]  # First 200 chars
                }
                services.append(service_info)

                # Extract vulnerabilities
                vulns = service_data.get('vulns', {})
                for vuln_id in vulns.keys():
                    if vuln_id not in [v['id'] for v in vulnerabilities]:
                        vulnerabilities.append({
                            'id': vuln_id,
                            'port': service_data.get('port'),
                            'service': service_data.get('product', 'Unknown')
                        })

            # Extract tags (if any)
            tags = response.get('tags', [])

            # Calculate threat indicators
            threat_score = 0
            threat_indicators = []

            # Many open ports = higher risk
            if len(ports) > 10:
                threat_score += 30
                threat_indicators.append(f"{len(ports)} open ports detected")
            elif len(ports) > 5:
                threat_score += 15
                threat_indicators.append(f"{len(ports)} open ports")

            # Known vulnerabilities = high risk
            if len(vulnerabilities) > 0:
                threat_score += min(len(vulnerabilities) * 20, 60)
                threat_indicators.append(f"{len(vulnerabilities)} known vulnerabilities")

            # Certain tags indicate malicious activity
            malicious_tags = ['malware', 'botnet', 'tor', 'vpn', 'proxy', 'scanner']
            found_tags = [tag for tag in tags if tag.lower() in malicious_tags]
            if found_tags:
                threat_score += 40
                threat_indicators.append(f"Tagged as: {', '.join(found_tags)}")

            # Last seen date
            last_update = response.get('last_update', 'Unknown')

            parsed = {
                'service': 'shodan',
                'ip_address': ip_address,
                'hostnames': hostnames,
                'domains': domains,
                'location': {
                    'country': country,
                    'country_code': country_code,
                    'city': city
                },
                'organization': {
                    'name': org,
                    'isp': isp
                },
                'open_ports': ports,
                'port_count': len(ports),
                'services': services[:10],  # Top 10 services
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'tags': tags,
                'threat_score': min(threat_score, 100),
                'threat_indicators': threat_indicators,
                'is_threat': threat_score >= 40,
                'last_update': last_update,
                'os': response.get('os'),
                'asn': response.get('asn')
            }

            logger.info(f"Shodan: {ip_address} - {len(ports)} ports, {len(vulnerabilities)} vulns")

            return parsed

        except Exception as e:
            logger.error(f"Error parsing Shodan response: {e}")
            return {
                'error': f'Parse error: {str(e)}',
                'service': 'shodan',
                'raw_response': response
            }

    def search(self, query: str, limit: int = 10) -> Dict:
        """
        Search Shodan using a query

        Args:
            query: Search query (e.g., "apache country:US")
            limit: Maximum number of results

        Returns:
            Dictionary with search results
        """
        url = f"{self.base_url}/shodan/host/search"
        params = {
            'key': self.api_key,
            'query': query,
            'limit': limit
        }

        response = self._make_request(url, params=params)

        if response and not response.get('error'):
            results = []
            for match in response.get('matches', []):
                results.append({
                    'ip': match.get('ip_str'),
                    'port': match.get('port'),
                    'org': match.get('org', 'Unknown'),
                    'hostnames': match.get('hostnames', []),
                    'location': match.get('location', {})
                })

            return {
                'query': query,
                'total': response.get('total', 0),
                'results': results
            }

        return {
            'error': response.get('error', 'Search failed'),
            'query': query
        }

    def get_dns_info(self, ip_address: str) -> Dict:
        """
        Get DNS information for an IP address

        Args:
            ip_address: IP address to query

        Returns:
            Dictionary with DNS records
        """
        url = f"{self.base_url}/dns/reverse"
        params = {
            'key': self.api_key,
            'ips': ip_address
        }

        response = self._make_request(url, params=params)

        if response and not response.get('error'):
            return {
                'ip_address': ip_address,
                'hostnames': response.get(ip_address, [])
            }

        return {
            'error': 'Could not fetch DNS info',
            'ip_address': ip_address
        }

    def get_ports(self, ip_address: str) -> List[int]:
        """
        Get list of open ports for an IP (from cache or API)

        Args:
            ip_address: IP address to query

        Returns:
            List of open port numbers
        """
        result = self.lookup(ip_address)

        if not result.get('error'):
            return result.get('open_ports', [])

        return []

    def get_vulnerabilities(self, ip_address: str) -> List[Dict]:
        """
        Get list of vulnerabilities for an IP

        Args:
            ip_address: IP address to query

        Returns:
            List of vulnerability dictionaries
        """
        result = self.lookup(ip_address)

        if not result.get('error'):
            return result.get('vulnerabilities', [])

        return []
