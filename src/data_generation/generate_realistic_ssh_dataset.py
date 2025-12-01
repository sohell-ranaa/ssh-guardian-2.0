import random
import json
from datetime import datetime, timedelta
import ipaddress
import os

class RealisticSSHDatasetGenerator:
    def __init__(self):
        # More overlapping patterns between normal and attack
        self.users = ['admin', 'root', 'user', 'ubuntu', 'devops', 'test', 'guest']  # Shared users
        self.countries = ['United States', 'Canada', 'Germany', 'China', 'Russia', 'Unknown']  # Mixed
        self.servers = ['web-server', 'db-server', 'api-server']
        
    def generate_ip_address(self):
        """Generate IPs that could be normal OR attack"""
        ranges = [
            '192.168.1.0/24',  # Normal office
            '10.0.0.0/24',     # Normal VPN  
            '203.0.113.0/24',  # Mixed traffic
            '198.51.100.0/24', # Could be attacks or normal
        ]
        network = ipaddress.IPv4Network(random.choice(ranges))
        return str(random.choice(list(network.hosts())))
    
    def generate_realistic_event(self):
        """Generate events with overlapping normal/attack patterns"""
        timestamp = datetime.now() - timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        # Create ambiguous scenarios
        scenario = random.choice([
            'normal_activity',
            'failed_but_legitimate',    # Failed logins from real users
            'successful_but_suspicious', # Success from unusual location
            'clear_attack',
            'borderline_suspicious'
        ])
        
        if scenario == 'normal_activity':
            return {
                'timestamp': timestamp.isoformat(),
                'hostname': random.choice(self.servers),
                'process': 'sshd',
                'pid': random.randint(1000, 9999),
                'event_type': 'accepted_password',
                'username': random.choice(self.users[:5]),  # Normal users
                'source_ip': self.generate_ip_address(),
                'port': 22,
                'protocol': 'ssh2',
                'location_country': random.choice(['United States', 'Canada', 'Germany']),
                'is_suspicious': False
            }
            
        elif scenario == 'failed_but_legitimate':
            # Real user typed wrong password - NOT an attack
            return {
                'timestamp': timestamp.isoformat(),
                'hostname': random.choice(self.servers),
                'process': 'sshd',
                'pid': random.randint(1000, 9999),
                'event_type': 'failed_password',
                'username': random.choice(self.users[:5]),  # Valid users
                'source_ip': self.generate_ip_address(),
                'port': 22,
                'protocol': 'ssh2',
                'location_country': random.choice(['United States', 'Canada']),
                'is_suspicious': False  # NOT suspicious - human error
            }
            
        elif scenario == 'successful_but_suspicious':
            # Real login but from unusual place - mildly suspicious
            return {
                'timestamp': timestamp.isoformat(),
                'hostname': random.choice(self.servers),
                'process': 'sshd',  
                'pid': random.randint(1000, 9999),
                'event_type': 'accepted_password',
                'username': random.choice(self.users[:4]),
                'source_ip': self.generate_ip_address(),
                'port': 22,
                'protocol': 'ssh2',
                'location_country': random.choice(['China', 'Russia']),
                'is_suspicious': True  # Suspicious due to location
            }
            
        elif scenario == 'clear_attack':
            # Clear attack pattern
            return {
                'timestamp': timestamp.isoformat(),
                'hostname': random.choice(self.servers),
                'process': 'sshd',
                'pid': random.randint(1000, 9999),
                'event_type': random.choice(['failed_password', 'invalid_user']),
                'username': random.choice(['hacker', 'bot', 'admin123'] + self.users),
                'source_ip': self.generate_ip_address(),
                'port': 22,
                'protocol': 'ssh2',
                'location_country': random.choice(['China', 'Russia', 'Unknown']),
                'is_suspicious': True
            }
            
        elif scenario == 'borderline_suspicious':
            # Hard to classify - could go either way
            return {
                'timestamp': timestamp.isoformat(),
                'hostname': random.choice(self.servers),
                'process': 'sshd',
                'pid': random.randint(1000, 9999),
                'event_type': 'failed_password',
                'username': random.choice(self.users),  # Valid user
                'source_ip': self.generate_ip_address(),
                'port': random.choice([22, 2222]),
                'protocol': 'ssh2',
                'location_country': random.choice(self.countries),
                'is_suspicious': random.choice([True, False])  # Randomly labeled!
            }
    
    def generate_realistic_dataset(self, num_samples=20000):
        """Generate realistic, challenging dataset"""
        print(f"🔄 Generating {num_samples:,} REALISTIC SSH events...")
        
        events = []
        for i in range(num_samples):
            event = self.generate_realistic_event()
            events.append(event)
            
            if i % 2000 == 0:
                print(f"   Generated: {i:,} / {num_samples:,}")
        
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'])
        
        # Statistics
        normal_count = sum(1 for e in events if not e['is_suspicious'])
        attack_count = sum(1 for e in events if e['is_suspicious'])
        
        print(f"✅ Generated {len(events):,} realistic events")
        print(f"   📊 Normal: {normal_count:,} ({normal_count/len(events)*100:.1f}%)")
        print(f"   ⚠️  Suspicious: {attack_count:,} ({attack_count/len(events)*100:.1f}%)")
        
        return events
    
    def save_dataset(self, events, filename="realistic_ssh_dataset.json"):
        """Save realistic dataset"""
        output_path = f"data/training_datasets/{filename}"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(events, f, indent=2)
        
        print(f"💾 Realistic dataset saved: {output_path}")
        return output_path

if __name__ == "__main__":
    generator = RealisticSSHDatasetGenerator()
    
    # Generate 20K more challenging samples
    events = generator.generate_realistic_dataset(20000)
    
    # Save dataset
    generator.save_dataset(events, "realistic_ssh_20k.json")
    
    print("\n🎯 Realistic dataset created!")
    print("This should give 85-92% accuracy (not 100%)")