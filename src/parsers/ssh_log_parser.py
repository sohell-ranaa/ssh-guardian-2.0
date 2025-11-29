"""
SSH Auth Log Parser
Parses real Ubuntu SSH logs from /var/log/auth.log format
Extracts structured data for ML training
"""
import re
from datetime import datetime
from typing import Dict, Optional, List
import json
import os


class SSHLogParser:
    def __init__(self):
        """Initialize parser with regex patterns for different SSH events"""
        
        # Main log line pattern (extracts timestamp, hostname, process)
        self.base_pattern = re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<process>sshd)\[(?P<pid>\d+)\]:\s+'
            r'(?P<message>.+)'
        )
        
        # Event-specific patterns
        self.event_patterns = {
            'accepted_password': re.compile(
                r'Accepted password for (?P<username>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+) (?P<protocol>\S+)'
            ),
            'failed_password': re.compile(
                r'Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+) (?P<protocol>\S+)'
            ),
            'invalid_user': re.compile(
                r'Invalid user (?P<username>\S*) from (?P<ip>[\d\.]+) port (?P<port>\d+)'
            ),
            'connection_closed_invalid': re.compile(
                r'Connection closed by invalid user (?P<username>\S*)\s*(?P<ip>[\d\.]+) port (?P<port>\d+)'
            ),
            'connection_closed': re.compile(
                r'Connection closed by (?:authenticating user )?(?P<username>\S+)?\s*(?P<ip>[\d\.]+) port (?P<port>\d+)'
            ),
            'received_disconnect': re.compile(
                r'Received disconnect from (?P<ip>[\d\.]+) port (?P<port>\d+):(?P<code>\d+): (?P<reason>.+)'
            ),
            'disconnected_from': re.compile(
                r'Disconnected from(?: user)? (?P<username>\S+)?\s*(?P<ip>[\d\.]+) port (?P<port>\d+)'
            ),
            'check_pass': re.compile(
                r'pam_unix\(sshd:auth\): check pass; user (?P<status>\w+)'
            ),
            'session_opened': re.compile(
                r'pam_unix\(sshd:session\): session opened for user (?P<username>\S+)'
            ),
            'session_closed': re.compile(
                r'pam_unix\(sshd:session\): session closed for user (?P<username>\S+)'
            ),
            'auth_failure': re.compile(
                r'pam_unix\(sshd:auth\): authentication failure.*rhost=(?P<ip>[\d\.]+)(?:.*user=(?P<username>\S+))?'
            ),
            'server_listening': re.compile(
                r'Server listening on (?P<address>[\d\.\:]+) port (?P<port>\d+)'
            ),
            'banner_exchange': re.compile(
                r'banner exchange: Connection from (?P<ip>[\d\.]+) port (?P<port>\d+): (?P<reason>.+)'
            )
        }
    
    def parse_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single SSH log line
        Returns: Dictionary with extracted fields or None if not SSH related
        """
        # First, match the base log structure
        base_match = self.base_pattern.match(line)
        if not base_match:
            return None
        
        # Extract base fields
        result = {
            'timestamp': base_match.group('timestamp'),
            'hostname': base_match.group('hostname'),
            'process': base_match.group('process'),
            'pid': int(base_match.group('pid')),
            'raw_message': base_match.group('message'),
            'event_type': 'unknown',
            'username': None,
            'source_ip': None,
            'source_port': None,
            'protocol': None,
            'is_preauth': '[preauth]' in line
        }
        
        # Try to match specific event patterns
        message = base_match.group('message')
        
        for event_type, pattern in self.event_patterns.items():
            match = pattern.search(message)
            if match:
                result['event_type'] = event_type
                # Map 'ip' to 'source_ip' and 'port' to 'source_port'
                for key, value in match.groupdict().items():
                    if key == 'ip':
                        result['source_ip'] = value
                    elif key == 'port':
                        result['source_port'] = int(value) if value else None
                    else:
                        result[key] = value
                
                # Clean username (remove uid info)
                if result.get('username'):
                    result['username'] = result['username'].split('(')[0]
                
                break
        
        # Parse timestamp to datetime object
        try:
            result['datetime'] = datetime.fromisoformat(result['timestamp'])
            result['hour'] = result['datetime'].hour
            result['day_of_week'] = result['datetime'].weekday()
            result['is_weekend'] = 1 if result['day_of_week'] >= 5 else 0
        except:
            result['datetime'] = None
        
        # Determine if this is an anomaly indicator
        result['is_suspicious'] = self._check_suspicious(result)
        
        return result
    
    def _check_suspicious(self, event: Dict) -> bool:
        """Simple heuristic to mark suspicious events"""
        suspicious_events = [
            'failed_password',
            'invalid_user',
            'auth_failure',
            'banner_exchange',
            'connection_closed_invalid',
            'check_pass'
        ]
        return event['event_type'] in suspicious_events
    
    def parse_file(self, filepath: str) -> List[Dict]:
        """
        Parse entire log file
        Returns: List of parsed events
        """
        events = []
        
        with open(filepath, 'r') as f:
            for line in f:
                parsed = self.parse_line(line)
                if parsed:
                    events.append(parsed)
        
        return events
    
    def get_statistics(self, events: List[Dict]) -> Dict:
        """Generate statistics from parsed events"""
        stats = {
            'total_events': len(events),
            'event_types': {},
            'unique_users': set(),
            'unique_ips': set(),
            'suspicious_count': 0,
            'preauth_count': 0
        }
        
        for event in events:
            # Count event types
            event_type = event['event_type']
            stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1
            
            # Track unique users and IPs
            if event.get('username'):
                stats['unique_users'].add(event['username'])
            if event.get('source_ip'):
                stats['unique_ips'].add(event['source_ip'])
            
            # Count suspicious events
            if event['is_suspicious']:
                stats['suspicious_count'] += 1
            
            if event['is_preauth']:
                stats['preauth_count'] += 1
        
        # Convert sets to counts
        stats['unique_users'] = len(stats['unique_users'])
        stats['unique_ips'] = len(stats['unique_ips'])
        
        return stats
    
    def validate_log_format(self, filepath: str) -> Dict:
        """
        Validate if log file matches expected SSH auth.log format
        Returns: Validation report
        """
        report = {
            'valid': True,
            'total_lines': 0,
            'parsed_lines': 0,
            'failed_lines': 0,
            'format_issues': []
        }
        
        with open(filepath, 'r') as f:
            for i, line in enumerate(f, 1):
                report['total_lines'] += 1
                
                parsed = self.parse_line(line)
                if parsed:
                    report['parsed_lines'] += 1
                else:
                    report['failed_lines'] += 1
                    if report['failed_lines'] <= 5:
                        report['format_issues'].append({
                            'line_number': i,
                            'content': line.strip()
                        })
        
        # Calculate parse rate
        if report['total_lines'] > 0:
            parse_rate = (report['parsed_lines'] / report['total_lines']) * 100
            report['parse_rate'] = round(parse_rate, 2)
            
            if parse_rate < 80:
                report['valid'] = False
        
        return report


def main():
    """Test the parser with command line interface"""
    import sys
    
    print("=" * 70)
    print("🔍 SSH LOG PARSER")
    print("=" * 70)
    
    # Get file path
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = input("\n📁 Enter log file path (default: /var/log/auth.log): ").strip()
        if not filepath:
            filepath = "/var/log/auth.log"
    
    print(f"\n📄 Parsing: {filepath}")
    print("-" * 70)
    
    # Initialize parser
    parser = SSHLogParser()
    
    # Parse file
    try:
        events = parser.parse_file(filepath)
        print(f"✅ Parsed {len(events)} SSH events")
        
        # Show statistics
        stats = parser.get_statistics(events)
        print("\n📊 STATISTICS:")
        print("-" * 70)
        print(f"Total Events: {stats['total_events']}")
        print(f"Suspicious Events: {stats['suspicious_count']} ({stats['suspicious_count']/stats['total_events']*100:.1f}%)")
        print(f"Unique Users: {stats['unique_users']}")
        print(f"Unique IPs: {stats['unique_ips']}")
        print(f"Preauth Events: {stats['preauth_count']}")
        
        print("\n📋 Event Type Breakdown:")
        for event_type, count in sorted(stats['event_types'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_events']) * 100
            print(f"  {event_type:.<30} {count:>6} ({percentage:>5.1f}%)")
        
        # Validate format
        print("\n" + "=" * 70)
        print("🔍 FORMAT VALIDATION:")
        print("-" * 70)
        validation = parser.validate_log_format(filepath)
        print(f"Parse Rate: {validation['parse_rate']}%")
        print(f"Status: {'✅ VALID' if validation['valid'] else '❌ INVALID'}")
        
        if validation['format_issues']:
            print(f"\n⚠️  Found {validation['failed_lines']} unparsed lines (showing first 5):")
            for issue in validation['format_issues']:
                print(f"  Line {issue['line_number']}: {issue['content'][:80]}...")
        
        # Show sample events
        print("\n" + "=" * 70)
        print("📋 SAMPLE PARSED EVENTS (first 5):")
        print("-" * 70)
        for event in events[:5]:
            print(json.dumps(event, default=str, indent=2))
            print("-" * 70)

      # Option to save parsed data
        save = input("\n💾 Save parsed data to organized JSON? (y/n): ").strip().lower()
        if save == 'y':
            if events:
                # Group events by hostname
                events_by_hostname = {}
                for event in events:
                    hostname = event.get('hostname', 'unknown_server')
                    if hostname not in events_by_hostname:
                        events_by_hostname[hostname] = []
                    events_by_hostname[hostname].append(event)
                
                # Process each hostname separately
                for server_name, server_events in events_by_hostname.items():
                    # Get date range for this server
                    dates = set()
                    for event in server_events:
                        if event.get('datetime'):
                            date_str = str(event['datetime']).split()[0]  # Get YYYY-MM-DD
                            dates.add(date_str)
                    
                    print(f"\n📁 Server: {server_name}")
                    print(f"📅 Date range: {min(dates)} to {max(dates)}")
                    
                    # Create organized directory structure
                    for date in sorted(dates):
                        output_dir = f"data/parsed_json/{server_name}/{date}"
                        os.makedirs(output_dir, exist_ok=True)
                        
                        # Filter events for this date
                        date_events = [e for e in server_events if str(e.get('datetime', '')).startswith(date)]
                        
                        # Save to file with hostname as filename
                        output_file = f"{output_dir}/{server_name}.json"
                        with open(output_file, 'w') as f:
                            json.dump(date_events, f, default=str, indent=2)
                        
                        print(f"  ✅ {date}: {len(date_events)} events → {output_file}")
                
                # Clear the source file after successful parse
                clear = input(f"\n🗑️  Clear {filepath} after parsing? (y/n): ").strip().lower()
                if clear == 'y':
                    with open(filepath, 'w') as f:
                        f.write('')  # Empty the file
                    print(f"✅ Cleared: {filepath}")
                else:
                    print("❌ No events to save")   
                
                # Clear the source file after successful parse
                clear = input(f"\n🗑️  Clear {filepath} after parsing? (y/n): ").strip().lower()
                if clear == 'y':
                    with open(filepath, 'w') as f:
                        f.write('')  # Empty the file
                    print(f"✅ Cleared: {filepath}")
            else:
                print("❌ No events to save")
        
    except FileNotFoundError:
        print(f"❌ Error: File not found - {filepath}")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()