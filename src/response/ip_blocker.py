"""
Automated IP Blocking System with iptables Integration
Intelligent blocking with duration management and whitelisting
"""

import subprocess
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from pathlib import Path
import json
import ipaddress

logger = logging.getLogger(__name__)


class IPBlocker:
    """
    Manages IP blocking using iptables
    Features:
    - Dynamic block duration based on threat level
    - Whitelist management
    - Automatic unblocking
    - Persistent state across restarts
    """

    def __init__(self,
                 state_file: Path,
                 whitelist_file: Optional[Path] = None,
                 chain_name: str = "SSH_GUARDIAN_BLOCK"):

        self.state_file = state_file
        self.whitelist_file = whitelist_file
        self.chain_name = chain_name

        # In-memory state
        self.blocked_ips = {}  # {ip: block_info}
        self.whitelist = set()

        # Load state
        self._load_state()
        self._load_whitelist()

        # Initialize iptables chain
        self._initialize_iptables()

    def _initialize_iptables(self):
        """Create SSH Guardian iptables chain if it doesn't exist"""
        try:
            # Check if chain exists
            result = subprocess.run(
                ['iptables', '-L', self.chain_name, '-n'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                # Chain doesn't exist, create it
                logger.info(f"Creating iptables chain: {self.chain_name}")

                # Create chain
                subprocess.run(['iptables', '-N', self.chain_name], check=True)

                # Insert jump to our chain in INPUT
                subprocess.run([
                    'iptables', '-I', 'INPUT', '-p', 'tcp',
                    '--dport', '22', '-j', self.chain_name
                ], check=True)

                logger.info(f"✅ iptables chain '{self.chain_name}' created successfully")
            else:
                logger.info(f"✅ iptables chain '{self.chain_name}' already exists")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to initialize iptables chain: {e}")
            logger.error("Note: This requires root privileges")
        except FileNotFoundError:
            logger.error("iptables command not found. Is iptables installed?")

    def _load_state(self):
        """Load blocked IPs from state file"""
        if not self.state_file.exists():
            logger.info("No existing state file found")
            return

        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)

            self.blocked_ips = {}
            for ip, info in data.items():
                # Convert string timestamps back to datetime
                info['blocked_at'] = datetime.fromisoformat(info['blocked_at'])
                info['unblock_at'] = datetime.fromisoformat(info['unblock_at'])
                self.blocked_ips[ip] = info

            logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs from state")

        except Exception as e:
            logger.error(f"Failed to load state file: {e}")

    def _save_state(self):
        """Save blocked IPs to state file"""
        try:
            # Ensure directory exists
            self.state_file.parent.mkdir(parents=True, exist_ok=True)

            # Convert datetime objects to ISO format strings
            data = {}
            for ip, info in self.blocked_ips.items():
                data[ip] = {
                    **info,
                    'blocked_at': info['blocked_at'].isoformat(),
                    'unblock_at': info['unblock_at'].isoformat()
                }

            with open(self.state_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug("State saved successfully")

        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def _load_whitelist(self):
        """Load whitelisted IPs"""
        if not self.whitelist_file or not self.whitelist_file.exists():
            logger.info("No whitelist file found")
            return

        try:
            with open(self.whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.whitelist.add(line)

            logger.info(f"Loaded {len(self.whitelist)} whitelisted IPs")

        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        # Check exact match
        if ip in self.whitelist:
            return True

        # Check if private IP
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return True
        except:
            pass

        return False

    def block_ip(self,
                 ip: str,
                 reason: str,
                 threat_level: str = 'medium',
                 duration_hours: Optional[int] = None,
                 dry_run: bool = False) -> Dict:
        """
        Block an IP address

        Args:
            ip: IP address to block
            reason: Reason for blocking
            threat_level: Threat level (low/medium/high/critical)
            duration_hours: Custom duration in hours (None = auto-calculate)
            dry_run: If True, don't actually block, just return what would happen

        Returns:
            Dict with block information
        """
        # Check whitelist
        if self.is_whitelisted(ip):
            logger.warning(f"Cannot block whitelisted IP: {ip}")
            return {
                'success': False,
                'reason': 'IP is whitelisted',
                'ip': ip
            }

        # Check if already blocked
        if ip in self.blocked_ips:
            logger.info(f"IP already blocked: {ip}")
            return {
                'success': False,
                'reason': 'Already blocked',
                'ip': ip,
                'block_info': self.blocked_ips[ip]
            }

        # Calculate block duration based on threat level
        if duration_hours is None:
            duration_map = {
                'low': 1,
                'medium': 24,
                'high': 168,      # 1 week
                'critical': 720   # 30 days
            }
            duration_hours = duration_map.get(threat_level, 24)

        blocked_at = datetime.now()
        unblock_at = blocked_at + timedelta(hours=duration_hours)

        block_info = {
            'ip': ip,
            'reason': reason,
            'threat_level': threat_level,
            'blocked_at': blocked_at,
            'unblock_at': unblock_at,
            'duration_hours': duration_hours,
            'manual': False
        }

        if dry_run:
            logger.info(f"[DRY RUN] Would block {ip} for {duration_hours}h: {reason}")
            return {
                'success': True,
                'dry_run': True,
                'ip': ip,
                'block_info': {
                    **block_info,
                    'blocked_at': blocked_at.isoformat(),
                    'unblock_at': unblock_at.isoformat()
                }
            }

        # Execute iptables block
        try:
            # Add DROP rule
            subprocess.run([
                'iptables', '-A', self.chain_name,
                '-s', ip, '-j', 'DROP'
            ], check=True, capture_output=True)

            logger.info(f"✅ Blocked {ip} for {duration_hours}h (until {unblock_at}): {reason}")

            # Store in memory and save state
            self.blocked_ips[ip] = block_info
            self._save_state()

            return {
                'success': True,
                'ip': ip,
                'block_info': {
                    **block_info,
                    'blocked_at': blocked_at.isoformat(),
                    'unblock_at': unblock_at.isoformat()
                }
            }

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip}: {e}")
            logger.error(f"stderr: {e.stderr.decode() if e.stderr else 'N/A'}")
            return {
                'success': False,
                'reason': f'iptables error: {e}',
                'ip': ip
            }
        except FileNotFoundError:
            logger.error("iptables command not found")
            return {
                'success': False,
                'reason': 'iptables not available',
                'ip': ip
            }

    def unblock_ip(self, ip: str, reason: str = 'manual unblock') -> Dict:
        """
        Unblock an IP address

        Args:
            ip: IP to unblock
            reason: Reason for unblocking

        Returns:
            Dict with unblock result
        """
        if ip not in self.blocked_ips:
            logger.warning(f"IP not blocked: {ip}")
            return {
                'success': False,
                'reason': 'IP not in blocked list',
                'ip': ip
            }

        try:
            # Remove iptables rule
            subprocess.run([
                'iptables', '-D', self.chain_name,
                '-s', ip, '-j', 'DROP'
            ], check=True, capture_output=True)

            logger.info(f"✅ Unblocked {ip}: {reason}")

            # Remove from memory and save
            del self.blocked_ips[ip]
            self._save_state()

            return {
                'success': True,
                'ip': ip,
                'reason': reason
            }

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock {ip}: {e}")
            # Remove from memory anyway (rule might not exist)
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self._save_state()

            return {
                'success': False,
                'reason': f'iptables error: {e}',
                'ip': ip
            }

    def cleanup_expired_blocks(self) -> int:
        """
        Remove blocks that have expired

        Returns:
            Number of IPs unblocked
        """
        current_time = datetime.now()
        expired_ips = []

        for ip, info in self.blocked_ips.items():
            if current_time >= info['unblock_at']:
                expired_ips.append(ip)

        unblocked_count = 0
        for ip in expired_ips:
            result = self.unblock_ip(ip, reason='block expired')
            if result['success']:
                unblocked_count += 1

        if unblocked_count > 0:
            logger.info(f"Cleaned up {unblocked_count} expired blocks")

        return unblocked_count

    def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        result = []
        for ip, info in self.blocked_ips.items():
            result.append({
                'ip': ip,
                'reason': info['reason'],
                'threat_level': info['threat_level'],
                'blocked_at': info['blocked_at'].isoformat(),
                'unblock_at': info['unblock_at'].isoformat(),
                'time_remaining': str(info['unblock_at'] - datetime.now())
            })
        return result

    def get_statistics(self) -> Dict:
        """Get blocking statistics"""
        current_time = datetime.now()

        active_blocks = len(self.blocked_ips)
        expired_blocks = sum(
            1 for info in self.blocked_ips.values()
            if current_time >= info['unblock_at']
        )

        threat_distribution = {}
        for info in self.blocked_ips.values():
            level = info['threat_level']
            threat_distribution[level] = threat_distribution.get(level, 0) + 1

        return {
            'active_blocks': active_blocks,
            'expired_blocks': expired_blocks,
            'whitelisted_ips': len(self.whitelist),
            'threat_level_distribution': threat_distribution
        }


def test_ip_blocker():
    """Test the IP blocker (dry run mode)"""
    print("=" * 80)
    print("IP BLOCKER - TEST (DRY RUN MODE)")
    print("=" * 80)

    # Initialize blocker
    state_file = Path("/tmp/ssh_guardian_blocks.json")
    whitelist_file = Path("/tmp/ssh_guardian_whitelist.txt")

    # Create test whitelist
    whitelist_file.parent.mkdir(parents=True, exist_ok=True)
    with open(whitelist_file, 'w') as f:
        f.write("# SSH Guardian Whitelist\n")
        f.write("8.8.8.8\n")  # Google DNS
        f.write("1.1.1.1\n")  # Cloudflare DNS

    blocker = IPBlocker(state_file, whitelist_file)

    # Test 1: Block an IP (dry run)
    print("\n📍 Test 1: Block malicious IP (dry run)")
    result = blocker.block_ip(
        ip="185.220.101.1",
        reason="Brute force attack detected - 50 failed attempts",
        threat_level="high",
        dry_run=True
    )
    print(f"   Success: {result['success']}")
    print(f"   Duration: {result['block_info']['duration_hours']} hours")

    # Test 2: Try to block whitelisted IP
    print("\n📍 Test 2: Try to block whitelisted IP")
    result = blocker.block_ip(
        ip="8.8.8.8",
        reason="Test",
        threat_level="low",
        dry_run=True
    )
    print(f"   Success: {result['success']}")
    print(f"   Reason: {result.get('reason', 'N/A')}")

    # Test 3: Block duration by threat level
    print("\n📍 Test 3: Block duration by threat level")
    threat_levels = ['low', 'medium', 'high', 'critical']
    # Use actual public IPs for testing (known Tor exit nodes)
    test_ips = ['185.220.101.1', '185.220.101.2', '185.220.101.3', '185.220.101.4']
    for level, test_ip in zip(threat_levels, test_ips):
        result = blocker.block_ip(
            ip=test_ip,
            reason=f"Test {level} threat",
            threat_level=level,
            dry_run=True
        )
        if result['success']:
            print(f"   {level.upper():8} -> {result['block_info']['duration_hours']} hours")
        else:
            print(f"   {level.upper():8} -> Failed: {result.get('reason', 'Unknown')}")

    # Statistics
    print("\n📊 STATISTICS:")
    stats = blocker.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n" + "=" * 80)
    print("ℹ️  Note: This was a dry run. No actual iptables rules were created.")
    print("   Run with sudo/root privileges for actual blocking.")
    print("=" * 80)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_ip_blocker()
