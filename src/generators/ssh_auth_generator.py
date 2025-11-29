"""
Realistic SSH Auth Log Generator
Mimics real /var/log/auth.log format with various SSH events
"""
import random
from datetime import datetime, timedelta
import os

class SSHAuthLogGenerator:
    
    def __init__(self):
        self.hostname = "server1"
        
        # Realistic usernames
        self.legitimate_users = ['root', 'admin', 'deploy', 'developer', 'jenkins', 'git']
        self.attack_users = ['oracle', 'postgres', 'test', 'user', 'admin123', 'mysql', 'ftp']
        
        # Realistic IPs - Mix of private and public in both categories
        self.legitimate_ips = [
            # Private IPs (office, VPN, internal)
            '192.168.1.10', '192.168.1.15', '10.0.0.5', '172.16.0.20',
            # Public IPs (cloud servers, remote workers)
            '52.23.185.42', '34.201.12.88', '18.220.45.99', '13.58.127.33'
        ]
        
        self.attack_ips = [
            # Public IPs (typical attack sources)
            '185.220.101.5', '45.142.120.10', '103.99.0.122', '176.123.5.89',
            '91.240.118.55', '218.92.0.107', '139.59.125.77', '159.65.88.44',
            # Private IPs (internal threats, compromised machines)
            '192.168.1.250', '10.0.0.99', '172.16.0.150', '192.168.100.55'
        ]
        
        # Session tracking
        self.active_sessions = {}
        self.session_counter = 2000
        
    def random_timestamp(self, start_date, end_date):
        """Generate random timestamp in auth.log format"""
        time_delta = end_date - start_date
        random_seconds = random.randint(0, int(time_delta.total_seconds()))
        timestamp = start_date + timedelta(seconds=random_seconds)
        # Format: 2025-11-28T08:15:22.123456-05:00
        return timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '-05:00'
    
    def generate_server_start(self, timestamp):
        """SSH server startup logs"""
        return [
            f"{timestamp} {self.hostname} sshd[{random.randint(1000,2000)}]: Server listening on 0.0.0.0 port 22.",
            f"{timestamp} {self.hostname} sshd[{random.randint(1000,2000)}]: Server listening on :: port 22."
        ]
    
    def generate_successful_login(self, timestamp, username, ip):
        """Successful SSH login sequence"""
        pid = self.session_counter
        self.session_counter += 1
        port = random.randint(40000, 65000)
        
        logs = [
            f"{timestamp} {self.hostname} sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
            f"{timestamp} {self.hostname} sshd[{pid}]: pam_unix(sshd:session): session opened for user {username}(uid=0) by {username}(uid=0)"
        ]
        
        # Track session for later closure
        self.active_sessions[pid] = {'username': username, 'timestamp': timestamp}
        
        return logs
    
    def generate_failed_login(self, timestamp, username, ip):
        """Failed password attempt"""
        pid = random.randint(3000, 9000)
        port = random.randint(40000, 65000)
        
        return [
            f"{timestamp} {self.hostname} sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2"
        ]
    
    def generate_invalid_user(self, timestamp, username, ip):
        """Invalid user attempt (user doesn't exist)"""
        pid = random.randint(3000, 9000)
        port = random.randint(40000, 65000)
        
        return [
            f"{timestamp} {self.hostname} sshd[{pid}]: Invalid user {username} from {ip} port {port}",
            f"{timestamp} {self.hostname} sshd[{pid}]: Connection closed by invalid user {username} {ip} port {port} [preauth]"
        ]
    
    def generate_connection_closed(self, timestamp, username, ip):
        """Connection closed by client"""
        pid = random.randint(3000, 9000)
        port = random.randint(40000, 65000)
        
        return [
            f"{timestamp} {self.hostname} sshd[{pid}]: Connection closed by authenticating user {username} {ip} port {port} [preauth]"
        ]
    
    def generate_session_close(self, timestamp, pid):
        """Close an active session"""
        if pid in self.active_sessions:
            username = self.active_sessions[pid]['username']
            del self.active_sessions[pid]
            return [
                f"{timestamp} {self.hostname} sshd[{pid}]: pam_unix(sshd:session): session closed for user {username}"
            ]
        return []
    
    def generate_brute_force_attack(self, timestamp, ip):
        """Simulate brute force attack pattern"""
        logs = []
        attempts = random.randint(5, 20)
        
        for i in range(attempts):
            username = random.choice(self.attack_users)
            # Spread attempts over 1-5 seconds
            attack_time = datetime.fromisoformat(timestamp.split('.')[0]) + timedelta(seconds=i)
            attack_timestamp = attack_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '-05:00'
            
            if random.random() < 0.3:
                logs.extend(self.generate_invalid_user(attack_timestamp, username, ip))
            else:
                logs.extend(self.generate_failed_login(attack_timestamp, username, ip))
        
        return logs
    
    def generate_logs(self, num_events, start_date, end_date):
        """Generate mixed SSH auth logs"""
        logs = []
        
        # Add server start
        logs.extend(self.generate_server_start(
            self.random_timestamp(start_date, start_date + timedelta(minutes=1))
        ))
        
        event_count = 0
        brute_force_count = 0
        
        while event_count < num_events:
            timestamp = self.random_timestamp(start_date, end_date)
            
            # Event distribution
            event_type = random.choices(
                ['legitimate_login', 'failed_login', 'invalid_user', 'brute_force', 'session_close', 'connection_closed'],
                weights=[40, 20, 10, 5, 20, 5]
            )[0]
            
            if event_type == 'legitimate_login':
                username = random.choice(self.legitimate_users)
                ip = random.choice(self.legitimate_ips)
                logs.extend(self.generate_successful_login(timestamp, username, ip))
                event_count += 1
                
            elif event_type == 'failed_login':
                username = random.choice(self.legitimate_users + self.attack_users)
                ip = random.choice(self.legitimate_ips + self.attack_ips)
                logs.extend(self.generate_failed_login(timestamp, username, ip))
                event_count += 1
                
            elif event_type == 'invalid_user':
                username = random.choice(self.attack_users)
                ip = random.choice(self.attack_ips)
                logs.extend(self.generate_invalid_user(timestamp, username, ip))
                event_count += 1
                
            elif event_type == 'brute_force' and brute_force_count < 3:
                ip = random.choice(self.attack_ips)
                attack_logs = self.generate_brute_force_attack(timestamp, ip)
                logs.extend(attack_logs)
                brute_force_count += 1
                event_count += len(attack_logs)
                
            elif event_type == 'session_close' and self.active_sessions:
                pid = random.choice(list(self.active_sessions.keys()))
                logs.extend(self.generate_session_close(timestamp, pid))
                event_count += 1
                
            elif event_type == 'connection_closed':
                username = random.choice(self.legitimate_users)
                ip = random.choice(self.legitimate_ips + self.attack_ips)
                logs.extend(self.generate_connection_closed(timestamp, username, ip))
                event_count += 1
        
        # Close remaining sessions
        for pid in list(self.active_sessions.keys()):
            close_time = self.random_timestamp(end_date - timedelta(hours=1), end_date)
            logs.extend(self.generate_session_close(close_time, pid))
        
        # Sort by timestamp
        logs.sort(key=lambda x: x.split()[0])
        
        return logs


def main():
    print("=" * 70)
    print("🔐 SSH AUTH LOG GENERATOR")
    print("=" * 70)
    print()
    
    # Get user input
    num_events = int(input("📊 How many SSH events to generate? (e.g., 1000): "))
    days_span = int(input("📅 Time span in days? (e.g., 7): "))
    
    # Date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days_span)
    
    print(f"\n⏳ Generating {num_events} events from {start_date.date()} to {end_date.date()}...")
    
    # Generate logs
    generator = SSHAuthLogGenerator()
    logs = generator.generate_logs(num_events, start_date, end_date)
    
    # Create output directory
    output_dir = "data/ssh_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save to file
    output_file = f"{output_dir}/server1.auth"
    with open(output_file, 'w') as f:
        f.write('\n'.join(logs))
    
    print(f"\n✅ Generated {len(logs)} log lines")
    print(f"📁 Saved to: {output_file}")
    print(f"📏 File size: {os.path.getsize(output_file) / 1024:.2f} KB")
    print("\n" + "=" * 70)
    
    # Show sample
    print("\n📋 Sample logs (first 10 lines):")
    print("-" * 70)
    for log in logs[:10]:
        print(log)
    print("=" * 70)


if __name__ == "__main__":
    main()