"""
IP Pool Manager - Provides realistic IPs for simulation
Fetches from threat feeds, whitelist, and generates random IPs
"""

import os
import random
from pathlib import Path
from typing import List, Dict
import ipaddress

PROJECT_ROOT = Path(__file__).parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"


class IPPoolManager:
    """Manages IP pools for different simulation scenarios"""

    def __init__(self):
        self.threat_feeds_dir = DATA_DIR / "threat_feeds"
        self.whitelist_file = DATA_DIR / "ip_whitelist.txt"
        self._malicious_ips = []
        self._trusted_ips = []
        self._load_pools()

    def _load_pools(self):
        """Load IPs from threat feeds and whitelist"""
        # Load malicious IPs from threat feeds
        self._malicious_ips = self._load_malicious_ips()

        # Load trusted IPs from whitelist
        self._trusted_ips = self._load_trusted_ips()

        print(f"✅ Loaded {len(self._malicious_ips)} malicious IPs")
        print(f"✅ Loaded {len(self._trusted_ips)} trusted IPs")

    def _load_malicious_ips(self) -> List[str]:
        """Load malicious IPs from threat feed files"""
        ips = set()

        if not self.threat_feeds_dir.exists():
            print(f"⚠️ Threat feeds directory not found: {self.threat_feeds_dir}")
            return list(ips)

        # Read all threat feed files
        feed_files = [
            'ssh_attackers.txt',
            'feodo_ips.txt',
            'tor_exits.txt',
            'bruteforce_ips.txt',
            'malicious_ips.txt'
        ]

        for feed_file in feed_files:
            file_path = self.threat_feeds_dir / feed_file
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if line and not line.startswith('#'):
                                # Extract IP (handle various formats)
                                ip = line.split()[0] if ' ' in line else line
                                if self._is_valid_ip(ip):
                                    ips.add(ip)
                except Exception as e:
                    print(f"⚠️ Error reading {feed_file}: {e}")

        # If no threat feeds found, add some known malicious IPs
        if len(ips) == 0:
            print("⚠️ No threat feeds found, using sample malicious IPs")
            ips = {
                '45.142.212.61',  # Known SSH attacker
                '185.220.101.1',  # TOR exit node
                '91.240.118.168',  # Brute force source
                '103.253.145.28',  # Malicious scanner
                '194.87.139.103',  # Known attacker
                '221.181.185.159',  # Chinese attack source
                '159.89.177.88',   # Compromised server
                '178.128.141.149', # Botnet node
                '167.99.95.35',    # Scanner
                '142.93.114.137'   # Attack source
            }

        return list(ips)

    def _load_trusted_ips(self) -> List[str]:
        """Load trusted IPs from whitelist"""
        ips = set()

        # Add RFC1918 private IP ranges examples
        ips.update([
            '192.168.1.100',
            '192.168.1.101',
            '192.168.1.102',
            '192.168.10.50',
            '10.0.0.100',
            '10.0.0.101',
            '10.0.1.50',
            '172.16.0.100',
            '172.16.1.100'
        ])

        # Load from whitelist file if exists
        if self.whitelist_file.exists():
            try:
                with open(self.whitelist_file, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            if self._is_valid_ip(ip):
                                ips.add(ip)
            except Exception as e:
                print(f"⚠️ Error reading whitelist: {e}")

        return list(ips)

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_ips(self, pool_type: str, count: int = 1) -> List[str]:
        """
        Get IPs from specified pool

        Args:
            pool_type: 'malicious', 'trusted', or 'random'
            count: Number of IPs to return

        Returns:
            List of IP addresses
        """
        if pool_type == 'malicious':
            if len(self._malicious_ips) == 0:
                raise ValueError("No malicious IPs available in threat feeds")
            return random.sample(self._malicious_ips, min(count, len(self._malicious_ips)))

        elif pool_type == 'trusted':
            if len(self._trusted_ips) == 0:
                raise ValueError("No trusted IPs available")
            return random.sample(self._trusted_ips, min(count, len(self._trusted_ips)))

        elif pool_type == 'random':
            return self._generate_random_ips(count)

        else:
            raise ValueError(f"Unknown pool type: {pool_type}")

    def _generate_random_ips(self, count: int) -> List[str]:
        """Generate random public IPs"""
        ips = []
        for _ in range(count):
            # Generate random public IP (avoid RFC1918, multicast, etc.)
            while True:
                octets = [random.randint(1, 223) for _ in range(4)]
                ip = '.'.join(map(str, octets))

                # Skip private ranges
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_multicast or
                        ip_obj.is_loopback or ip_obj.is_reserved):
                    ips.append(ip)
                    break

        return ips

    def get_pool_info(self) -> Dict:
        """Get information about available IP pools"""
        return {
            'malicious': {
                'count': len(self._malicious_ips),
                'samples': self._malicious_ips[:5] if self._malicious_ips else []
            },
            'trusted': {
                'count': len(self._trusted_ips),
                'samples': self._trusted_ips[:5] if self._trusted_ips else []
            },
            'random': {
                'count': 'unlimited',
                'samples': self._generate_random_ips(5)
            }
        }

    def get_ip_with_metadata(self, pool_type: str) -> Dict:
        """Get an IP with additional metadata"""
        ip = self.get_ips(pool_type, 1)[0]

        metadata = {
            'ip': ip,
            'pool_type': pool_type,
            'is_private': ipaddress.ip_address(ip).is_private,
        }

        if pool_type == 'malicious':
            metadata['reputation'] = 'malicious'
            metadata['source'] = 'threat_feed'
        elif pool_type == 'trusted':
            metadata['reputation'] = 'trusted'
            metadata['source'] = 'whitelist'
        else:
            metadata['reputation'] = 'unknown'
            metadata['source'] = 'random_generated'

        return metadata


# Module-level instance
_pool_manager = None


def get_pool_manager() -> IPPoolManager:
    """Get singleton IPPoolManager instance"""
    global _pool_manager
    if _pool_manager is None:
        _pool_manager = IPPoolManager()
    return _pool_manager
