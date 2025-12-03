#!/usr/bin/env python3
"""
Synthetic SSH Access Data Generator for SSH Guardian 2.0
Generates 10,000 realistic SSH events using existing database schema
"""

import random
import pymysql
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import sys
import os
import json

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', '123123'),
    'database': os.getenv('DB_NAME', 'ssh_guardian_20'),
    'charset': 'utf8mb4'
}

# Realistic data pools
LEGITIMATE_IPS = [
    # Office networks
    '192.168.1.10', '192.168.1.15', '192.168.1.20', '192.168.1.25', '192.168.1.30',
    '10.0.0.10', '10.0.0.15', '10.0.0.20', '10.0.0.25', '10.0.0.30',
    # VPN endpoints
    '203.0.113.10', '203.0.113.15', '198.51.100.20', '198.51.100.25',
    # Cloud providers
    '52.86.108.12', '54.210.45.67', '18.208.126.82',  # AWS
    '104.198.14.52', '35.184.219.87', '35.188.123.45',  # GCP
    '13.71.172.90', '40.112.72.205', '20.42.73.145',  # Azure
]

MALICIOUS_IPS = [
    # Known attack sources
    '185.220.101.50', '185.220.101.51', '185.220.101.52', '185.220.101.53',  # Tor
    '222.186.42.34', '222.186.42.35', '222.186.42.36', '222.186.42.37',  # China
    '45.142.120.10', '45.142.120.15', '45.142.120.20', '45.142.120.25',  # Eastern Europe
    '94.232.47.190', '94.232.47.191', '94.232.47.192', '94.232.47.193',  # Russia
    '103.253.145.21', '103.253.145.22', '103.253.145.23', '103.253.145.24',  # Asia
    '157.245.100.45', '157.245.100.46', '157.245.100.47', '157.245.100.48',  # VPS
    '159.65.123.89', '159.65.123.90', '159.65.123.91', '159.65.123.92',  # Botnets
    '178.128.45.12', '178.128.45.13', '178.128.45.14', '178.128.45.15',  # Compromised
]

LEGITIMATE_USERNAMES = [
    'admin', 'ubuntu', 'developer', 'devops', 'sysadmin',
    'jenkins', 'deploy', 'gitlab', 'circleci', 'ansible',
    'john', 'sarah', 'mike', 'alice', 'bob', 'charlie',
    'david', 'emily', 'frank', 'grace'
]

MALICIOUS_USERNAMES = [
    'root', 'test', 'guest', 'oracle', 'postgres',
    'admin123', 'Administrator', 'user', 'mysql', 'ftpuser',
    'tomcat', 'webadmin', 'support', 'default', 'pi',
    'apache', 'nginx', 'www-data', 'nobody', 'ftp',
    'nagios', 'zabbix', 'minecraft', 'steam', 'teamspeak'
]

SERVERS = [
    'web-server-01', 'web-server-02', 'web-server-03',
    'db-server-01', 'db-server-02',
    'app-server-01', 'app-server-02', 'app-server-03',
    'api-gateway-01', 'api-gateway-02',
    'staging-server', 'production-01', 'production-02', 'production-03'
]

# GeoIP data for legitimate sources
LEGIT_LOCATIONS = [
    ('US', 'New York', 40.7128, -74.0060, 'America/New_York'),
    ('US', 'San Francisco', 37.7749, -122.4194, 'America/Los_Angeles'),
    ('US', 'Seattle', 47.6062, -122.3321, 'America/Los_Angeles'),
    ('GB', 'London', 51.5074, -0.1278, 'Europe/London'),
    ('DE', 'Frankfurt', 50.1109, 8.6821, 'Europe/Berlin'),
    ('FR', 'Paris', 48.8566, 2.3522, 'Europe/Paris'),
    ('CA', 'Toronto', 43.6532, -79.3832, 'America/Toronto'),
    ('AU', 'Sydney', -33.8688, 151.2093, 'Australia/Sydney'),
    ('JP', 'Tokyo', 35.6762, 139.6503, 'Asia/Tokyo'),
]

# GeoIP data for malicious sources
MALICIOUS_LOCATIONS = [
    ('CN', 'Beijing', 39.9042, 116.4074, 'Asia/Shanghai'),
    ('CN', 'Shanghai', 31.2304, 121.4737, 'Asia/Shanghai'),
    ('RU', 'Moscow', 55.7558, 37.6173, 'Europe/Moscow'),
    ('RU', 'St Petersburg', 59.9343, 30.3351, 'Europe/Moscow'),
    ('KP', 'Pyongyang', 39.0392, 125.7625, 'Asia/Pyongyang'),
    ('IR', 'Tehran', 35.6892, 51.3890, 'Asia/Tehran'),
    ('VN', 'Hanoi', 21.0285, 105.8542, 'Asia/Ho_Chi_Minh'),
    ('UA', 'Kiev', 50.4501, 30.5234, 'Europe/Kiev'),
    ('BR', 'Sao Paulo', -23.5505, -46.6333, 'America/Sao_Paulo'),
    ('IN', 'Mumbai', 19.0760, 72.8777, 'Asia/Kolkata'),
    ('Unknown', 'Unknown', None, None, None),
]

class SyntheticSSHDataGenerator:
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

    def get_geo_data(self, is_malicious: bool) -> Tuple:
        """Get randomized geo location data"""
        if is_malicious:
            return random.choice(MALICIOUS_LOCATIONS)
        return random.choice(LEGIT_LOCATIONS)

    def generate_successful_login(self, timestamp: datetime, is_malicious: bool = False) -> Dict:
        """Generate a successful SSH login event"""
        if is_malicious:
            ip = random.choice(MALICIOUS_IPS)
            username = random.choice(MALICIOUS_USERNAMES)
            session_duration = random.randint(3600, 14400)  # Long suspicious sessions
            ip_risk_score = random.randint(70, 95)
            ip_reputation = random.choice(['suspicious', 'malicious'])
        else:
            ip = random.choice(LEGITIMATE_IPS)
            username = random.choice(LEGITIMATE_USERNAMES)
            session_duration = random.randint(300, 7200)  # Normal sessions
            ip_risk_score = random.randint(0, 25)
            ip_reputation = 'clean'

        server = random.choice(SERVERS)
        country, city, lat, lon, tz = self.get_geo_data(is_malicious)

        event_data = {
            'event_type': 'successful_login',
            'authentication_method': random.choice(['password', 'publickey', 'keyboard-interactive']),
            'client_version': f'SSH-2.0-OpenSSH_{random.choice(["7.4", "8.0", "8.2", "9.0"])}'
        }

        return {
            'timestamp': timestamp,
            'server_hostname': server,
            'source_ip': ip,
            'username': username,
            'port': 22,
            'session_duration': session_duration,
            'raw_event_data': json.dumps(event_data),
            'country': country,
            'city': city,
            'latitude': lat,
            'longitude': lon,
            'timezone': tz,
            'geoip_processed': 1,
            'ip_risk_score': ip_risk_score,
            'ip_reputation': ip_reputation,
            'ip_health_processed': 1,
            'ml_risk_score': ip_risk_score + random.randint(-10, 10),
            'ml_threat_type': 'intrusion' if is_malicious else 'normal',
            'ml_confidence': round(random.uniform(0.75, 0.99), 3),
            'is_anomaly': 1 if is_malicious else 0,
            'ml_processed': 1,
            'pipeline_completed': 1
        }

    def generate_failed_login(self, timestamp: datetime, is_attack: bool = False) -> Dict:
        """Generate a failed SSH login event"""
        if is_attack:
            ip = random.choice(MALICIOUS_IPS)
            username = random.choice(MALICIOUS_USERNAMES)
            failure_reason = random.choice(['invalid_password', 'invalid_user'])
            ip_risk_score = random.randint(60, 90)
            ip_reputation = random.choice(['suspicious', 'malicious'])
        else:
            # Legitimate typo/mistake
            ip = random.choice(LEGITIMATE_IPS)
            username = random.choice(LEGITIMATE_USERNAMES)
            failure_reason = 'invalid_password'
            ip_risk_score = random.randint(0, 30)
            ip_reputation = 'clean'

        server = random.choice(SERVERS)
        country, city, lat, lon, tz = self.get_geo_data(is_attack)

        event_data = {
            'event_type': 'failed_login',
            'authentication_method': 'password',
            'client_version': f'SSH-2.0-libssh_{random.choice(["0.8", "0.9", "1.0"])}'
        }

        return {
            'timestamp': timestamp,
            'server_hostname': server,
            'source_ip': ip,
            'username': username,
            'port': 22,
            'failure_reason': failure_reason,
            'raw_event_data': json.dumps(event_data),
            'country': country,
            'city': city,
            'latitude': lat,
            'longitude': lon,
            'timezone': tz,
            'geoip_processed': 1,
            'ip_risk_score': ip_risk_score,
            'ip_reputation': ip_reputation,
            'ip_health_processed': 1,
            'ml_risk_score': ip_risk_score + random.randint(-5, 15),
            'ml_threat_type': 'brute_force' if is_attack else 'failed_auth',
            'ml_confidence': round(random.uniform(0.70, 0.95), 3),
            'is_anomaly': 1 if is_attack else 0,
            'ml_processed': 1,
            'pipeline_completed': 1
        }

    def generate_brute_force_attack(self, timestamp: datetime) -> List[Dict]:
        """Generate a brute force attack pattern (multiple failed attempts)"""
        events = []
        attacker_ip = random.choice(MALICIOUS_IPS)
        target_server = random.choice(SERVERS)
        attempts = random.randint(15, 50)

        base_risk = 50
        for i in range(attempts):
            # Escalating risk score
            risk_score = min(95, base_risk + (i * 2))

            # Vary usernames (credential stuffing pattern)
            if random.random() < 0.4:
                username = random.choice(MALICIOUS_USERNAMES)
            else:
                username = f"user{random.randint(1, 100)}"

            event_time = timestamp + timedelta(seconds=i * random.randint(2, 15))
            country, city, lat, lon, tz = self.get_geo_data(True)

            event_data = {
                'event_type': 'brute_force_attempt',
                'attack_pattern': 'credential_stuffing',
                'attempt_number': i + 1
            }

            events.append({
                'timestamp': event_time,
                'server_hostname': target_server,
                'source_ip': attacker_ip,
                'username': username,
                'port': 22,
                'failure_reason': random.choice(['invalid_password', 'invalid_user']),
                'raw_event_data': json.dumps(event_data),
                'country': country,
                'city': city,
                'latitude': lat,
                'longitude': lon,
                'timezone': tz,
                'geoip_processed': 1,
                'ip_risk_score': risk_score,
                'ip_reputation': 'malicious',
                'ip_health_processed': 1,
                'ml_risk_score': risk_score + random.randint(0, 10),
                'ml_threat_type': 'brute_force',
                'ml_confidence': round(random.uniform(0.85, 0.99), 3),
                'is_anomaly': 1,
                'ml_processed': 1,
                'pipeline_completed': 1
            })

        return events

    def generate_distributed_attack(self, timestamp: datetime) -> List[Dict]:
        """Generate distributed attack from multiple IPs targeting same server/user"""
        events = []
        target_server = random.choice(SERVERS)
        target_user = random.choice(['root', 'admin', 'administrator'])
        num_attackers = random.randint(5, 15)

        for _ in range(num_attackers):
            attacker_ip = random.choice(MALICIOUS_IPS)
            attempts = random.randint(3, 10)

            for i in range(attempts):
                event_time = timestamp + timedelta(minutes=random.randint(0, 60))
                country, city, lat, lon, tz = self.get_geo_data(True)

                event_data = {
                    'event_type': 'distributed_attack',
                    'attack_pattern': 'coordinated',
                    'target_user': target_user
                }

                events.append({
                    'timestamp': event_time,
                    'server_hostname': target_server,
                    'source_ip': attacker_ip,
                    'username': target_user,
                    'port': 22,
                    'failure_reason': 'invalid_password',
                    'raw_event_data': json.dumps(event_data),
                    'country': country,
                    'city': city,
                    'latitude': lat,
                    'longitude': lon,
                    'timezone': tz,
                    'geoip_processed': 1,
                    'ip_risk_score': random.randint(75, 90),
                    'ip_reputation': 'malicious',
                    'ip_health_processed': 1,
                    'ml_risk_score': random.randint(80, 95),
                    'ml_threat_type': 'distributed_attack',
                    'ml_confidence': round(random.uniform(0.80, 0.95), 3),
                    'is_anomaly': 1,
                    'ml_processed': 1,
                    'pipeline_completed': 1
                })

        return events

    def generate_events(self, total: int = 10000) -> Tuple[List[Dict], List[Dict]]:
        """Generate mixed synthetic events"""
        successful_events = []
        failed_events = []
        current_time = self.start_time

        print(f"\n🔄 Generating {total} synthetic SSH events...")
        print(f"📅 Date range: {self.start_time.date()} to {datetime.now().date()}")

        # Distribution strategy
        successful_legit_ratio = 0.35  # 35% successful legitimate
        successful_breach_ratio = 0.03  # 3% successful breaches
        failed_legit_ratio = 0.07  # 7% failed legitimate (typos)
        failed_attack_ratio = 0.15  # 15% simple failed attacks
        brute_force_ratio = 0.30  # 30% brute force attacks
        distributed_ratio = 0.10  # 10% distributed attacks

        counts = {
            'successful_legit': int(total * successful_legit_ratio),
            'successful_breach': int(total * successful_breach_ratio),
            'failed_legit': int(total * failed_legit_ratio),
            'failed_attack': int(total * failed_attack_ratio),
        }

        # Generate successful legitimate logins
        print(f"\n✅ Generating {counts['successful_legit']} successful legitimate logins...")
        for i in range(counts['successful_legit']):
            current_time += timedelta(minutes=random.randint(5, 30))
            successful_events.append(self.generate_successful_login(current_time, False))
            if (i + 1) % 500 == 0:
                print(f"   Progress: {i + 1}/{counts['successful_legit']}")

        # Generate successful breaches
        print(f"\n🚨 Generating {counts['successful_breach']} successful breach attempts...")
        for i in range(counts['successful_breach']):
            current_time += timedelta(hours=random.randint(12, 48))
            successful_events.append(self.generate_successful_login(current_time, True))

        # Generate failed legitimate attempts
        print(f"\n❌ Generating {counts['failed_legit']} failed legitimate attempts...")
        for i in range(counts['failed_legit']):
            current_time += timedelta(minutes=random.randint(10, 60))
            failed_events.append(self.generate_failed_login(current_time, False))

        # Generate simple failed attacks
        print(f"\n⚔️  Generating {counts['failed_attack']} simple failed attacks...")
        for i in range(counts['failed_attack']):
            current_time += timedelta(minutes=random.randint(5, 30))
            failed_events.append(self.generate_failed_login(current_time, True))
            if (i + 1) % 500 == 0:
                print(f"   Progress: {i + 1}/{counts['failed_attack']}")

        # Generate brute force attacks
        brute_force_attacks = int((total * brute_force_ratio) / 25)  # ~25 attempts per attack
        print(f"\n💥 Generating ~{brute_force_attacks} brute force attacks...")
        for i in range(brute_force_attacks):
            current_time += timedelta(hours=random.randint(1, 8))
            failed_events.extend(self.generate_brute_force_attack(current_time))
            if (i + 1) % 10 == 0:
                print(f"   Attacks generated: {i + 1}/{brute_force_attacks}")

        # Generate distributed attacks
        distributed_attacks = int((total * distributed_ratio) / 50)  # ~50 attempts per attack
        print(f"\n🌐 Generating ~{distributed_attacks} distributed attacks...")
        for i in range(distributed_attacks):
            current_time += timedelta(hours=random.randint(6, 24))
            failed_events.extend(self.generate_distributed_attack(current_time))

        # Sort by timestamp
        successful_events.sort(key=lambda x: x['timestamp'])
        failed_events.sort(key=lambda x: x['timestamp'])

        print(f"\n✅ Generated:")
        print(f"   Successful logins: {len(successful_events)}")
        print(f"   Failed logins: {len(failed_events)}")
        print(f"   Total: {len(successful_events) + len(failed_events)}")

        return successful_events, failed_events

    def save_successful_logins(self, events: List[Dict]) -> bool:
        """Save successful login events to database"""
        print(f"\n💾 Saving {len(events)} successful logins...")

        insert_query = """
        INSERT INTO successful_logins
        (timestamp, server_hostname, source_ip, username, port, session_duration,
         raw_event_data, country, city, latitude, longitude, timezone,
         geoip_processed, ip_risk_score, ip_reputation, ip_health_processed,
         ml_risk_score, ml_threat_type, ml_confidence, is_anomaly,
         ml_processed, pipeline_completed)
        VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        batch_size = 1000
        total_saved = 0

        try:
            with self.connection.cursor() as cursor:
                for i in range(0, len(events), batch_size):
                    batch = events[i:i + batch_size]
                    values = [
                        (
                            e['timestamp'], e['server_hostname'], e['source_ip'],
                            e['username'], e['port'], e['session_duration'],
                            e['raw_event_data'], e['country'], e['city'],
                            e['latitude'], e['longitude'], e['timezone'],
                            e['geoip_processed'], e['ip_risk_score'],
                            e['ip_reputation'], e['ip_health_processed'],
                            e['ml_risk_score'], e['ml_threat_type'],
                            e['ml_confidence'], e['is_anomaly'],
                            e['ml_processed'], e['pipeline_completed']
                        )
                        for e in batch
                    ]

                    cursor.executemany(insert_query, values)
                    self.connection.commit()
                    total_saved += len(batch)
                    print(f"   Saved: {total_saved}/{len(events)}")

            print(f"✅ All successful logins saved")
            return True
        except Exception as e:
            print(f"❌ Error saving successful logins: {e}")
            self.connection.rollback()
            return False

    def save_failed_logins(self, events: List[Dict]) -> bool:
        """Save failed login events to database"""
        print(f"\n💾 Saving {len(events)} failed logins...")

        insert_query = """
        INSERT INTO failed_logins
        (timestamp, server_hostname, source_ip, username, port, failure_reason,
         raw_event_data, country, city, latitude, longitude, timezone,
         geoip_processed, ip_risk_score, ip_reputation, ip_health_processed,
         ml_risk_score, ml_threat_type, ml_confidence, is_anomaly,
         ml_processed, pipeline_completed)
        VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        batch_size = 1000
        total_saved = 0

        try:
            with self.connection.cursor() as cursor:
                for i in range(0, len(events), batch_size):
                    batch = events[i:i + batch_size]
                    values = [
                        (
                            e['timestamp'], e['server_hostname'], e['source_ip'],
                            e['username'], e['port'], e['failure_reason'],
                            e['raw_event_data'], e['country'], e['city'],
                            e['latitude'], e['longitude'], e['timezone'],
                            e['geoip_processed'], e['ip_risk_score'],
                            e['ip_reputation'], e['ip_health_processed'],
                            e['ml_risk_score'], e['ml_threat_type'],
                            e['ml_confidence'], e['is_anomaly'],
                            e['ml_processed'], e['pipeline_completed']
                        )
                        for e in batch
                    ]

                    cursor.executemany(insert_query, values)
                    self.connection.commit()
                    total_saved += len(batch)
                    print(f"   Saved: {total_saved}/{len(events)}")

            print(f"✅ All failed logins saved")
            return True
        except Exception as e:
            print(f"❌ Error saving failed logins: {e}")
            self.connection.rollback()
            return False

    def generate_ip_blocks(self) -> bool:
        """Generate IP block records for high-risk IPs"""
        print(f"\n🚫 Generating IP block records...")

        # Get high-risk IPs from failed logins
        query = """
        SELECT DISTINCT source_ip, ml_risk_score, ml_threat_type
        FROM failed_logins
        WHERE ml_risk_score >= 85
        ORDER BY ml_risk_score DESC
        LIMIT 50
        """

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query)
                high_risk_ips = cursor.fetchall()

                if not high_risk_ips:
                    print("   No high-risk IPs found")
                    return True

                insert_query = """
                INSERT INTO ip_blocks
                (ip_address, block_reason, block_source, unblock_at, is_active)
                VALUES (%s, %s, %s, %s, %s)
                """

                values = []
                for ip_data in high_risk_ips:
                    ip = ip_data[0]
                    risk_score = ip_data[1]
                    threat_type = ip_data[2]

                    # Determine block duration based on risk
                    if risk_score >= 90:
                        duration_hours = 7 * 24  # 7 days
                    else:
                        duration_hours = 24  # 1 day

                    blocked_at = datetime.now() - timedelta(hours=random.randint(1, 48))
                    unblock_at = blocked_at + timedelta(hours=duration_hours)

                    reason = f"ML detected {threat_type} (risk: {risk_score}/100)"

                    values.append((
                        ip, reason, 'ml_analysis', unblock_at, 1
                    ))

                cursor.executemany(insert_query, values)
                self.connection.commit()
                print(f"✅ Saved {len(values)} IP block records")
                return True

        except Exception as e:
            print(f"❌ Error generating IP blocks: {e}")
            return False

    def print_statistics(self):
        """Print database statistics"""
        print(f"\n" + "="*80)
        print("📊 DATABASE STATISTICS")
        print("="*80)

        try:
            with self.connection.cursor() as cursor:
                # Successful logins
                cursor.execute("SELECT COUNT(*) as total FROM successful_logins")
                success_total = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT COUNT(*) as malicious
                    FROM successful_logins
                    WHERE is_anomaly = 1
                """)
                success_malicious = cursor.fetchone()[0]

                print(f"\n✅ Successful Logins: {success_total:,}")
                print(f"   Legitimate: {success_total - success_malicious:,}")
                print(f"   Breaches: {success_malicious:,}")

                # Failed logins
                cursor.execute("SELECT COUNT(*) as total FROM failed_logins")
                failed_total = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT COUNT(*) as attacks
                    FROM failed_logins
                    WHERE is_anomaly = 1
                """)
                failed_attacks = cursor.fetchone()[0]

                print(f"\n❌ Failed Logins: {failed_total:,}")
                print(f"   Legitimate failures: {failed_total - failed_attacks:,}")
                print(f"   Attack attempts: {failed_attacks:,}")

                # Threat types
                cursor.execute("""
                    SELECT ml_threat_type, COUNT(*) as count
                    FROM failed_logins
                    WHERE is_anomaly = 1
                    GROUP BY ml_threat_type
                    ORDER BY count DESC
                """)
                print(f"\n🎯 Attack Types:")
                for row in cursor.fetchall():
                    print(f"   {row[0]:<25} {row[1]:>6,}")

                # Top attacking IPs
                cursor.execute("""
                    SELECT source_ip, country, COUNT(*) as attempts
                    FROM failed_logins
                    WHERE is_anomaly = 1
                    GROUP BY source_ip, country
                    ORDER BY attempts DESC
                    LIMIT 10
                """)
                print(f"\n🔝 Top 10 Attacking IPs:")
                for i, row in enumerate(cursor.fetchall(), 1):
                    print(f"   {i:>2}. {row[0]:<18} ({row[1]:<10}) - {row[2]:>4} attempts")

                # IP blocks
                cursor.execute("SELECT COUNT(*) as total FROM ip_blocks WHERE is_active = 1")
                blocks = cursor.fetchone()[0]
                print(f"\n🚫 Active IP Blocks: {blocks}")

                # Total events
                total_events = success_total + failed_total
                print(f"\n📊 Total Events: {total_events:,}")

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

    generator = SyntheticSSHDataGenerator()

    # Connect to database
    if not generator.connect_db():
        print("\n❌ Failed to connect to database.")
        sys.exit(1)

    # Generate events
    successful_events, failed_events = generator.generate_events(10000)

    # Save events
    if not generator.save_successful_logins(successful_events):
        print("\n❌ Failed to save successful logins.")
        sys.exit(1)

    if not generator.save_failed_logins(failed_events):
        print("\n❌ Failed to save failed logins.")
        sys.exit(1)

    # Generate IP blocks
    generator.generate_ip_blocks()

    # Print statistics
    generator.print_statistics()

    # Close connection
    generator.close()

    print("\n✅ Synthetic data generation complete!")
    print(f"📊 Database: {DB_CONFIG['database']}")
    print(f"🔗 Tables: successful_logins, failed_logins, ip_blocks")

if __name__ == "__main__":
    main()
