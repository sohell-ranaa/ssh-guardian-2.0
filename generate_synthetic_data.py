#!/usr/bin/env python3
"""
Synthetic SSH Access Data Generator
Generates 10,000 realistic SSH events with mixed legitimate and malicious patterns
"""

import random
import pymysql
from datetime import datetime, timedelta
from typing import List, Dict
import sys
import os

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'sshguardian'),
    'password': os.getenv('DB_PASSWORD', 'guardian123'),
    'database': os.getenv('DB_NAME', 'ssh_guardian_dev'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# Realistic data pools
LEGITIMATE_IPS = [
    # Office networks
    '192.168.1.10', '192.168.1.15', '192.168.1.20', '192.168.1.25',
    '10.0.0.10', '10.0.0.15', '10.0.0.20', '10.0.0.25',
    # VPN endpoints
    '203.0.113.10', '203.0.113.15', '198.51.100.20', '198.51.100.25',
    # Cloud providers
    '52.86.108.12', '54.210.45.67', '18.208.126.82',  # AWS
    '104.198.14.52', '35.184.219.87', '35.188.123.45',  # GCP
]

MALICIOUS_IPS = [
    # Known attack sources
    '185.220.101.50', '185.220.101.51', '185.220.101.52',  # Tor exits
    '222.186.42.34', '222.186.42.35', '222.186.42.36',  # China attackers
    '45.142.120.10', '45.142.120.15', '45.142.120.20',  # Eastern Europe
    '94.232.47.190', '94.232.47.191', '94.232.47.192',  # Russia
    '103.253.145.21', '103.253.145.22', '103.253.145.23',  # Asia
    '157.245.100.45', '157.245.100.46', '157.245.100.47',  # Compromised VPS
    '159.65.123.89', '159.65.123.90', '159.65.123.91',  # Botnets
]

LEGITIMATE_USERNAMES = [
    'admin', 'ubuntu', 'developer', 'devops', 'sysadmin',
    'jenkins', 'deploy', 'gitlab', 'circleci', 'ansible',
    'john', 'sarah', 'mike', 'alice', 'bob'
]

MALICIOUS_USERNAMES = [
    'root', 'test', 'guest', 'oracle', 'postgres',
    'admin123', 'Administrator', 'user', 'mysql', 'ftpuser',
    'tomcat', 'webadmin', 'support', 'default', 'pi',
    'apache', 'nginx', 'www-data', 'nobody', 'ftp'
]

SERVERS = [
    'web-server-01', 'web-server-02', 'db-server-01',
    'app-server-01', 'app-server-02', 'api-gateway',
    'staging-server', 'production-01', 'production-02'
]

COUNTRIES_LEGITIMATE = [
    ('US', 'New York'), ('US', 'San Francisco'), ('US', 'Seattle'),
    ('GB', 'London'), ('DE', 'Frankfurt'), ('FR', 'Paris'),
    ('CA', 'Toronto'), ('AU', 'Sydney'), ('JP', 'Tokyo')
]

COUNTRIES_MALICIOUS = [
    ('CN', 'Beijing'), ('RU', 'Moscow'), ('KP', 'Pyongyang'),
    ('IR', 'Tehran'), ('VN', 'Hanoi'), ('UA', 'Kiev'),
    ('BR', 'Sao Paulo'), ('IN', 'Mumbai'), ('Unknown', 'Unknown')
]

class SyntheticDataGenerator:
    def __init__(self):
        self.connection = None
        self.start_time = datetime.now() - timedelta(days=30)  # 30 days of data

    def connect_db(self):
        """Connect to MySQL database"""
        try:
            self.connection = pymysql.connect(**DB_CONFIG)
            print(f"✅ Connected to database: {DB_CONFIG['database']}")
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False

    def create_schema(self):
        """Create database schema for SSH events"""
        schema = """
        CREATE TABLE IF NOT EXISTS ssh_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            event_type VARCHAR(50) NOT NULL,
            source_ip VARCHAR(45) NOT NULL,
            username VARCHAR(100) NOT NULL,
            server_name VARCHAR(100) NOT NULL,
            port INT DEFAULT 22,
            country VARCHAR(10),
            city VARCHAR(100),
            is_legitimate BOOLEAN DEFAULT FALSE,
            is_threat BOOLEAN DEFAULT FALSE,
            risk_score INT DEFAULT 0,
            threat_level VARCHAR(20),
            session_duration INT,
            bytes_transferred BIGINT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_timestamp (timestamp),
            INDEX idx_source_ip (source_ip),
            INDEX idx_event_type (event_type),
            INDEX idx_is_threat (is_threat),
            INDEX idx_risk_score (risk_score)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

        CREATE TABLE IF NOT EXISTS attack_patterns (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            source_ip VARCHAR(45) NOT NULL,
            pattern_type VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            failed_attempts INT DEFAULT 0,
            time_window_minutes INT DEFAULT 0,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            is_blocked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_source_ip (source_ip),
            INDEX idx_pattern_type (pattern_type),
            INDEX idx_severity (severity)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            reason TEXT,
            risk_score INT NOT NULL,
            block_duration_hours INT NOT NULL,
            blocked_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            unblocked_at DATETIME,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip_address (ip_address),
            INDEX idx_is_active (is_active),
            INDEX idx_expires_at (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        try:
            with self.connection.cursor() as cursor:
                for statement in schema.split(';'):
                    if statement.strip():
                        cursor.execute(statement)
                self.connection.commit()
                print("✅ Database schema created successfully")
                return True
        except Exception as e:
            print(f"❌ Schema creation failed: {e}")
            return False

    def generate_legitimate_event(self, timestamp: datetime) -> Dict:
        """Generate a legitimate SSH event"""
        ip = random.choice(LEGITIMATE_IPS)
        username = random.choice(LEGITIMATE_USERNAMES)
        server = random.choice(SERVERS)
        country, city = random.choice(COUNTRIES_LEGITIMATE)

        # Mostly successful logins for legitimate users
        event_type = random.choices(
            ['accepted_password', 'accepted_publickey', 'failed_password'],
            weights=[0.7, 0.2, 0.1]  # 70% password, 20% key, 10% failed
        )[0]

        return {
            'timestamp': timestamp,
            'event_type': event_type,
            'source_ip': ip,
            'username': username,
            'server_name': server,
            'port': 22,
            'country': country,
            'city': city,
            'is_legitimate': True,
            'is_threat': False,
            'risk_score': random.randint(0, 25),
            'threat_level': 'clean',
            'session_duration': random.randint(300, 7200) if 'accepted' in event_type else None,
            'bytes_transferred': random.randint(10000, 50000000) if 'accepted' in event_type else None
        }

    def generate_brute_force_attack(self, timestamp: datetime, ip: str) -> List[Dict]:
        """Generate a brute force attack pattern"""
        events = []
        attempts = random.randint(10, 50)
        username = random.choice(MALICIOUS_USERNAMES)
        server = random.choice(SERVERS)
        country, city = random.choice(COUNTRIES_MALICIOUS)

        for i in range(attempts):
            # Vary username for credential stuffing
            if random.random() < 0.3:
                username = random.choice(MALICIOUS_USERNAMES)

            event_time = timestamp + timedelta(seconds=i * random.randint(1, 10))
            risk_score = min(100, 50 + (i * 2))  # Escalating risk

            events.append({
                'timestamp': event_time,
                'event_type': 'failed_password',
                'source_ip': ip,
                'username': username,
                'server_name': server,
                'port': 22,
                'country': country,
                'city': city,
                'is_legitimate': False,
                'is_threat': True,
                'risk_score': risk_score,
                'threat_level': 'high' if risk_score > 70 else 'medium',
                'session_duration': None,
                'bytes_transferred': None
            })

        return events

    def generate_distributed_attack(self, timestamp: datetime) -> List[Dict]:
        """Generate a distributed attack from multiple IPs"""
        events = []
        num_ips = random.randint(5, 15)
        target_server = random.choice(SERVERS)
        target_username = random.choice(['root', 'admin', 'administrator'])

        for _ in range(num_ips):
            ip = random.choice(MALICIOUS_IPS)
            country, city = random.choice(COUNTRIES_MALICIOUS)
            attempts = random.randint(3, 8)

            for i in range(attempts):
                event_time = timestamp + timedelta(minutes=random.randint(0, 30))

                events.append({
                    'timestamp': event_time,
                    'event_type': 'failed_password',
                    'source_ip': ip,
                    'username': target_username,
                    'server_name': target_server,
                    'port': 22,
                    'country': country,
                    'city': city,
                    'is_legitimate': False,
                    'is_threat': True,
                    'risk_score': random.randint(60, 85),
                    'threat_level': 'high',
                    'session_duration': None,
                    'bytes_transferred': None
                })

        return events

    def generate_successful_breach(self, timestamp: datetime, ip: str) -> List[Dict]:
        """Generate a successful breach after multiple attempts"""
        events = []
        server = random.choice(SERVERS)
        username = random.choice(MALICIOUS_USERNAMES)
        country, city = random.choice(COUNTRIES_MALICIOUS)

        # Failed attempts
        for i in range(random.randint(5, 15)):
            events.append({
                'timestamp': timestamp + timedelta(seconds=i * 5),
                'event_type': 'failed_password',
                'source_ip': ip,
                'username': username,
                'server_name': server,
                'port': 22,
                'country': country,
                'city': city,
                'is_legitimate': False,
                'is_threat': True,
                'risk_score': random.randint(50, 80),
                'threat_level': 'high',
                'session_duration': None,
                'bytes_transferred': None
            })

        # Successful breach
        breach_time = timestamp + timedelta(seconds=len(events) * 5 + 10)
        events.append({
            'timestamp': breach_time,
            'event_type': 'accepted_password',
            'source_ip': ip,
            'username': username,
            'server_name': server,
            'port': 22,
            'country': country,
            'city': city,
            'is_legitimate': False,
            'is_threat': True,
            'risk_score': 95,
            'threat_level': 'critical',
            'session_duration': random.randint(3600, 14400),  # Long session
            'bytes_transferred': random.randint(100000000, 1000000000)  # Large data transfer
        })

        return events

    def generate_events(self, total: int = 10000) -> List[Dict]:
        """Generate mixed synthetic events"""
        events = []
        current_time = self.start_time

        print(f"\n🔄 Generating {total} synthetic SSH events...")
        print(f"📅 Date range: {self.start_time.date()} to {datetime.now().date()}")

        # Distribution strategy
        legitimate_ratio = 0.60  # 60% legitimate
        brute_force_ratio = 0.25  # 25% brute force
        distributed_ratio = 0.10  # 10% distributed attacks
        breach_ratio = 0.05  # 5% successful breaches

        legitimate_count = int(total * legitimate_ratio)
        remaining = total - legitimate_count

        # Generate legitimate events
        print(f"✅ Generating {legitimate_count} legitimate events...")
        for i in range(legitimate_count):
            current_time += timedelta(minutes=random.randint(1, 30))
            events.append(self.generate_legitimate_event(current_time))

            if (i + 1) % 1000 == 0:
                print(f"   Progress: {i + 1}/{legitimate_count}")

        # Generate brute force attacks
        brute_force_count = int(remaining * (brute_force_ratio / (1 - legitimate_ratio)))
        print(f"\n⚔️  Generating ~{brute_force_count} brute force attacks...")
        attack_count = 0
        while len(events) < legitimate_count + brute_force_count and attack_count < 100:
            current_time += timedelta(hours=random.randint(1, 6))
            ip = random.choice(MALICIOUS_IPS)
            attack_events = self.generate_brute_force_attack(current_time, ip)
            events.extend(attack_events)
            attack_count += 1

            if attack_count % 10 == 0:
                print(f"   Attacks generated: {attack_count}")

        # Generate distributed attacks
        distributed_count = int(remaining * (distributed_ratio / (1 - legitimate_ratio)))
        print(f"\n🌐 Generating ~{distributed_count} distributed attack events...")
        dist_attack_count = 0
        while len(events) < legitimate_count + brute_force_count + distributed_count and dist_attack_count < 20:
            current_time += timedelta(hours=random.randint(2, 12))
            dist_events = self.generate_distributed_attack(current_time)
            events.extend(dist_events)
            dist_attack_count += 1

        # Generate successful breaches
        breach_count = int(remaining * (breach_ratio / (1 - legitimate_ratio)))
        print(f"\n🚨 Generating ~{breach_count} successful breach events...")
        breach_attack_count = 0
        while len(events) < total and breach_attack_count < 10:
            current_time += timedelta(hours=random.randint(12, 48))
            ip = random.choice(MALICIOUS_IPS)
            breach_events = self.generate_successful_breach(current_time, ip)
            events.extend(breach_events)
            breach_attack_count += 1

        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'])

        # Trim to exact count
        events = events[:total]

        print(f"\n✅ Generated {len(events)} total events")
        return events

    def save_events(self, events: List[Dict]):
        """Save events to database in batches"""
        print(f"\n💾 Saving {len(events)} events to database...")

        insert_query = """
        INSERT INTO ssh_events
        (timestamp, event_type, source_ip, username, server_name, port,
         country, city, is_legitimate, is_threat, risk_score, threat_level,
         session_duration, bytes_transferred)
        VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        batch_size = 1000
        total_saved = 0

        try:
            with self.connection.cursor() as cursor:
                for i in range(0, len(events), batch_size):
                    batch = events[i:i + batch_size]
                    values = [
                        (
                            e['timestamp'], e['event_type'], e['source_ip'],
                            e['username'], e['server_name'], e['port'],
                            e['country'], e['city'], e['is_legitimate'],
                            e['is_threat'], e['risk_score'], e['threat_level'],
                            e['session_duration'], e['bytes_transferred']
                        )
                        for e in batch
                    ]

                    cursor.executemany(insert_query, values)
                    self.connection.commit()
                    total_saved += len(batch)
                    print(f"   Saved: {total_saved}/{len(events)}")

                print(f"✅ All {total_saved} events saved successfully")
                return True

        except Exception as e:
            print(f"❌ Error saving events: {e}")
            self.connection.rollback()
            return False

    def generate_attack_patterns(self, events: List[Dict]):
        """Analyze and save attack patterns"""
        print(f"\n🔍 Analyzing attack patterns...")

        patterns = {}
        for event in events:
            if event['is_threat']:
                ip = event['source_ip']
                if ip not in patterns:
                    patterns[ip] = {
                        'source_ip': ip,
                        'failed_attempts': 0,
                        'first_seen': event['timestamp'],
                        'last_seen': event['timestamp']
                    }

                patterns[ip]['failed_attempts'] += 1
                patterns[ip]['last_seen'] = event['timestamp']

        # Classify patterns
        pattern_records = []
        for ip, data in patterns.items():
            time_window = (data['last_seen'] - data['first_seen']).total_seconds() / 60

            if data['failed_attempts'] >= 20:
                pattern_type = 'brute_force_high'
                severity = 'critical'
            elif data['failed_attempts'] >= 10:
                pattern_type = 'brute_force_medium'
                severity = 'high'
            else:
                pattern_type = 'reconnaissance'
                severity = 'medium'

            pattern_records.append({
                'source_ip': ip,
                'pattern_type': pattern_type,
                'severity': severity,
                'failed_attempts': data['failed_attempts'],
                'time_window_minutes': int(time_window),
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'is_blocked': severity in ['critical', 'high']
            })

        # Save patterns
        insert_query = """
        INSERT INTO attack_patterns
        (source_ip, pattern_type, severity, failed_attempts, time_window_minutes,
         first_seen, last_seen, is_blocked)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

        try:
            with self.connection.cursor() as cursor:
                values = [
                    (p['source_ip'], p['pattern_type'], p['severity'],
                     p['failed_attempts'], p['time_window_minutes'],
                     p['first_seen'], p['last_seen'], p['is_blocked'])
                    for p in pattern_records
                ]
                cursor.executemany(insert_query, values)
                self.connection.commit()
                print(f"✅ Saved {len(pattern_records)} attack patterns")
                return True
        except Exception as e:
            print(f"❌ Error saving patterns: {e}")
            return False

    def generate_blocked_ips(self, events: List[Dict]):
        """Generate blocked IP records for high-risk threats"""
        print(f"\n🚫 Generating blocked IP records...")

        high_risk_ips = {}
        for event in events:
            if event['risk_score'] >= 85:  # Auto-block threshold
                ip = event['source_ip']
                if ip not in high_risk_ips:
                    high_risk_ips[ip] = {
                        'ip_address': ip,
                        'risk_score': event['risk_score'],
                        'blocked_at': event['timestamp'],
                        'reason': f"High risk detected: {event['threat_level']} - {event['event_type']}"
                    }

        blocked_records = []
        for ip, data in high_risk_ips.items():
            duration = 7 * 24 if data['risk_score'] >= 90 else 24  # 7 days for critical, 1 day for high
            blocked_records.append({
                'ip_address': ip,
                'reason': data['reason'],
                'risk_score': data['risk_score'],
                'block_duration_hours': duration,
                'blocked_at': data['blocked_at'],
                'expires_at': data['blocked_at'] + timedelta(hours=duration),
                'is_active': True
            })

        if not blocked_records:
            print("   No IPs met auto-block threshold")
            return True

        insert_query = """
        INSERT INTO blocked_ips
        (ip_address, reason, risk_score, block_duration_hours, blocked_at, expires_at, is_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        risk_score = VALUES(risk_score),
        expires_at = VALUES(expires_at)
        """

        try:
            with self.connection.cursor() as cursor:
                values = [
                    (b['ip_address'], b['reason'], b['risk_score'],
                     b['block_duration_hours'], b['blocked_at'],
                     b['expires_at'], b['is_active'])
                    for b in blocked_records
                ]
                cursor.executemany(insert_query, values)
                self.connection.commit()
                print(f"✅ Saved {len(blocked_records)} blocked IP records")
                return True
        except Exception as e:
            print(f"❌ Error saving blocked IPs: {e}")
            return False

    def print_statistics(self):
        """Print database statistics"""
        print(f"\n" + "="*80)
        print("📊 DATABASE STATISTICS")
        print("="*80)

        try:
            with self.connection.cursor() as cursor:
                # Total events
                cursor.execute("SELECT COUNT(*) as total FROM ssh_events")
                total = cursor.fetchone()['total']
                print(f"\n📝 Total Events: {total:,}")

                # Events by type
                cursor.execute("""
                    SELECT event_type, COUNT(*) as count
                    FROM ssh_events
                    GROUP BY event_type
                    ORDER BY count DESC
                """)
                print(f"\n📋 Events by Type:")
                for row in cursor.fetchall():
                    print(f"   {row['event_type']:<25} {row['count']:>6,}")

                # Threat statistics
                cursor.execute("""
                    SELECT
                        SUM(is_legitimate) as legitimate,
                        SUM(is_threat) as threats,
                        COUNT(*) as total
                    FROM ssh_events
                """)
                stats = cursor.fetchone()
                print(f"\n🛡️  Security Statistics:")
                print(f"   Legitimate Events:        {stats['legitimate']:>6,} ({stats['legitimate']/stats['total']*100:.1f}%)")
                print(f"   Threat Events:            {stats['threats']:>6,} ({stats['threats']/stats['total']*100:.1f}%)")

                # Risk level distribution
                cursor.execute("""
                    SELECT threat_level, COUNT(*) as count
                    FROM ssh_events
                    GROUP BY threat_level
                    ORDER BY FIELD(threat_level, 'clean', 'low', 'medium', 'high', 'critical')
                """)
                print(f"\n⚠️  Risk Level Distribution:")
                for row in cursor.fetchall():
                    print(f"   {row['threat_level']:<15} {row['count']:>6,}")

                # Top attacking IPs
                cursor.execute("""
                    SELECT source_ip, country, COUNT(*) as attempts
                    FROM ssh_events
                    WHERE is_threat = TRUE
                    GROUP BY source_ip, country
                    ORDER BY attempts DESC
                    LIMIT 10
                """)
                print(f"\n🎯 Top 10 Attacking IPs:")
                for i, row in enumerate(cursor.fetchall(), 1):
                    print(f"   {i:>2}. {row['source_ip']:<18} ({row['country']:<3}) - {row['attempts']:>4} attempts")

                # Attack patterns
                cursor.execute("SELECT COUNT(*) as total FROM attack_patterns")
                patterns = cursor.fetchone()['total']
                print(f"\n🔍 Attack Patterns Identified: {patterns}")

                # Blocked IPs
                cursor.execute("SELECT COUNT(*) as total FROM blocked_ips WHERE is_active = TRUE")
                blocked = cursor.fetchone()['total']
                print(f"🚫 Active IP Blocks: {blocked}")

                print(f"\n" + "="*80)

        except Exception as e:
            print(f"❌ Error fetching statistics: {e}")

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("\n✅ Database connection closed")

def main():
    """Main execution"""
    print("="*80)
    print("🛡️  SSH GUARDIAN 2.0 - SYNTHETIC DATA GENERATOR")
    print("="*80)

    generator = SyntheticDataGenerator()

    # Connect to database
    if not generator.connect_db():
        print("\n❌ Failed to connect to database. Please check your .env configuration.")
        sys.exit(1)

    # Create schema
    if not generator.create_schema():
        print("\n❌ Failed to create database schema.")
        sys.exit(1)

    # Generate events
    events = generator.generate_events(10000)

    # Save events
    if not generator.save_events(events):
        print("\n❌ Failed to save events to database.")
        sys.exit(1)

    # Generate attack patterns
    generator.generate_attack_patterns(events)

    # Generate blocked IPs
    generator.generate_blocked_ips(events)

    # Print statistics
    generator.print_statistics()

    # Close connection
    generator.close()

    print("\n✅ Synthetic data generation complete!")
    print(f"📊 Database: {DB_CONFIG['database']}")
    print(f"🔗 Tables: ssh_events, attack_patterns, blocked_ips")

if __name__ == "__main__":
    main()
