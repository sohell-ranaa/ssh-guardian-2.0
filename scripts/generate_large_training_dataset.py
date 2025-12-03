#!/usr/bin/env python3
"""
Large-Scale Training Dataset Generator for SSH Guardian 2.0
Generates 50,000+ realistic SSH events for ML model training
"""

import random
import pymysql
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import sys
import os
import json
from collections import defaultdict

from dotenv import load_dotenv
load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', '123123'),
    'database': os.getenv('DB_NAME', 'ssh_guardian_20'),
    'charset': 'utf8mb4'
}

# Expanded IP pools for diversity
LEGITIMATE_IP_RANGES = {
    'office_networks': [f'192.168.{subnet}.{host}' for subnet in range(1, 5) for host in range(10, 50, 5)],
    'vpn_endpoints': [f'10.{subnet}.0.{host}' for subnet in range(10, 20) for host in range(10, 30, 5)],
    'cloud_aws': [f'52.{subnet}.{block}.{host}' for subnet in range(80, 90) for block in range(100, 120, 10) for host in range(10, 30, 10)],
    'cloud_gcp': [f'35.{subnet}.{block}.{host}' for subnet in range(180, 190) for block in range(1, 30, 10) for host in range(1, 20, 5)],
    'cloud_azure': [f'20.{subnet}.{block}.{host}' for subnet in range(40, 50) for block in range(70, 90, 10) for host in range(1, 20, 5)],
}

MALICIOUS_IP_RANGES = {
    'tor_exits': [f'185.220.{subnet}.{host}' for subnet in range(100, 110) for host in range(50, 70)],
    'china_attackers': [f'222.186.{subnet}.{host}' for subnet in range(40, 50) for host in range(30, 50)],
    'russia_attackers': [f'94.232.{subnet}.{host}' for subnet in range(45, 55) for host in range(190, 200)],
    'eastern_europe': [f'45.142.{subnet}.{host}' for subnet in range(120, 130) for host in range(10, 30)],
    'asia_botnets': [f'103.253.{subnet}.{host}' for subnet in range(140, 150) for host in range(20, 40)],
    'compromised_vps': [f'157.245.{subnet}.{host}' for subnet in range(100, 110) for host in range(45, 65)],
    'botnets': [f'159.65.{subnet}.{host}' for subnet in range(120, 130) for host in range(85, 95)],
}

LEGITIMATE_IPS = [ip for ips in LEGITIMATE_IP_RANGES.values() for ip in ips]
MALICIOUS_IPS = [ip for ips in MALICIOUS_IP_RANGES.values() for ip in ips]

LEGITIMATE_USERNAMES = [
    'admin', 'ubuntu', 'developer', 'devops', 'sysadmin', 'engineer',
    'jenkins', 'deploy', 'gitlab', 'circleci', 'ansible', 'terraform',
    'john', 'sarah', 'mike', 'alice', 'bob', 'charlie', 'david', 'emily',
    'frank', 'grace', 'henry', 'isabella', 'jack', 'kate', 'liam', 'maria',
    'appuser', 'webmaster', 'ops', 'monitoring', 'backup', 'service'
]

MALICIOUS_USERNAMES = [
    'root', 'test', 'guest', 'oracle', 'postgres', 'mysql', 'mongodb',
    'admin123', 'Administrator', 'user', 'ftpuser', 'user1', 'user123',
    'tomcat', 'webadmin', 'support', 'default', 'pi', 'raspberry',
    'apache', 'nginx', 'www-data', 'nobody', 'ftp', 'anonymous',
    'nagios', 'zabbix', 'minecraft', 'steam', 'teamspeak', 'ts3',
    'ubnt', 'admin1', 'admin2', 'admins', 'administrators',
    'test1', 'test123', 'testuser', 'demo', 'temp', 'temporary'
]

SERVERS = [
    'web-01', 'web-02', 'web-03', 'web-04', 'web-05',
    'db-01', 'db-02', 'db-03',
    'app-01', 'app-02', 'app-03', 'app-04',
    'api-gateway-01', 'api-gateway-02',
    'staging-01', 'staging-02',
    'prod-01', 'prod-02', 'prod-03', 'prod-04', 'prod-05',
    'cache-01', 'cache-02', 'queue-01', 'queue-02'
]

LEGIT_LOCATIONS = [
    ('US', 'New York', 40.7128, -74.0060, 'America/New_York'),
    ('US', 'San Francisco', 37.7749, -122.4194, 'America/Los_Angeles'),
    ('US', 'Seattle', 47.6062, -122.3321, 'America/Los_Angeles'),
    ('US', 'Chicago', 41.8781, -87.6298, 'America/Chicago'),
    ('US', 'Austin', 30.2672, -97.7431, 'America/Chicago'),
    ('GB', 'London', 51.5074, -0.1278, 'Europe/London'),
    ('GB', 'Manchester', 53.4808, -2.2426, 'Europe/London'),
    ('DE', 'Frankfurt', 50.1109, 8.6821, 'Europe/Berlin'),
    ('DE', 'Berlin', 52.5200, 13.4050, 'Europe/Berlin'),
    ('FR', 'Paris', 48.8566, 2.3522, 'Europe/Paris'),
    ('CA', 'Toronto', 43.6532, -79.3832, 'America/Toronto'),
    ('CA', 'Vancouver', 49.2827, -123.1207, 'America/Vancouver'),
    ('AU', 'Sydney', -33.8688, 151.2093, 'Australia/Sydney'),
    ('AU', 'Melbourne', -37.8136, 144.9631, 'Australia/Melbourne'),
    ('JP', 'Tokyo', 35.6762, 139.6503, 'Asia/Tokyo'),
    ('SG', 'Singapore', 1.3521, 103.8198, 'Asia/Singapore'),
    ('NL', 'Amsterdam', 52.3676, 4.9041, 'Europe/Amsterdam'),
]

MALICIOUS_LOCATIONS = [
    ('CN', 'Beijing', 39.9042, 116.4074, 'Asia/Shanghai'),
    ('CN', 'Shanghai', 31.2304, 121.4737, 'Asia/Shanghai'),
    ('CN', 'Shenzhen', 22.5431, 114.0579, 'Asia/Shanghai'),
    ('RU', 'Moscow', 55.7558, 37.6173, 'Europe/Moscow'),
    ('RU', 'St Petersburg', 59.9343, 30.3351, 'Europe/Moscow'),
    ('RU', 'Novosibirsk', 55.0084, 82.9357, 'Asia/Novosibirsk'),
    ('KP', 'Pyongyang', 39.0392, 125.7625, 'Asia/Pyongyang'),
    ('IR', 'Tehran', 35.6892, 51.3890, 'Asia/Tehran'),
    ('VN', 'Hanoi', 21.0285, 105.8542, 'Asia/Ho_Chi_Minh'),
    ('VN', 'Ho Chi Minh', 10.8231, 106.6297, 'Asia/Ho_Chi_Minh'),
    ('UA', 'Kiev', 50.4501, 30.5234, 'Europe/Kiev'),
    ('BR', 'Sao Paulo', -23.5505, -46.6333, 'America/Sao_Paulo'),
    ('IN', 'Mumbai', 19.0760, 72.8777, 'Asia/Kolkata'),
    ('IN', 'Bangalore', 12.9716, 77.5946, 'Asia/Kolkata'),
    ('PK', 'Karachi', 24.8607, 67.0011, 'Asia/Karachi'),
    ('Unknown', 'Unknown', None, None, None),
]

class LargeScaleDataGenerator:
    def __init__(self):
        self.connection = None
        self.start_time = datetime.now() - timedelta(days=90)  # 90 days
        self.attack_campaigns = []

    def connect_db(self):
        try:
            self.connection = pymysql.connect(**DB_CONFIG)
            print(f"✅ Connected to database: {DB_CONFIG['database']}")
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False

    def get_geo_data(self, is_malicious: bool) -> Tuple:
        if is_malicious:
            return random.choice(MALICIOUS_LOCATIONS)
        return random.choice(LEGIT_LOCATIONS)

    def generate_normal_behavior(self, timestamp: datetime, num_events: int) -> List[Dict]:
        """Generate normal user behavior patterns"""
        events = []
        user_sessions = defaultdict(list)

        # Simulate realistic user sessions
        for _ in range(num_events):
            ip = random.choice(LEGITIMATE_IPS)
            username = random.choice(LEGITIMATE_USERNAMES)
            server = random.choice(SERVERS)

            # 90% successful, 10% failed (typos)
            is_success = random.random() < 0.9

            session_time = timestamp + timedelta(
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )

            country, city, lat, lon, tz = self.get_geo_data(False)

            if is_success:
                event = {
                    'table': 'successful_logins',
                    'timestamp': session_time,
                    'server_hostname': server,
                    'source_ip': ip,
                    'username': username,
                    'port': 22,
                    'session_duration': random.randint(300, 7200),
                    'raw_event_data': json.dumps({
                        'event_type': 'successful_login',
                        'auth_method': random.choice(['password', 'publickey']),
                    }),
                    'country': country,
                    'city': city,
                    'latitude': lat,
                    'longitude': lon,
                    'timezone': tz,
                    'geoip_processed': 1,
                    'ip_risk_score': random.randint(0, 20),
                    'ip_reputation': 'clean',
                    'ip_health_processed': 1,
                    'ml_risk_score': random.randint(0, 25),
                    'ml_threat_type': 'normal',
                    'ml_confidence': round(random.uniform(0.85, 0.99), 3),
                    'is_anomaly': 0,
                    'ml_processed': 1,
                    'pipeline_completed': 1
                }
            else:
                event = {
                    'table': 'failed_logins',
                    'timestamp': session_time,
                    'server_hostname': server,
                    'source_ip': ip,
                    'username': username,
                    'port': 22,
                    'failure_reason': 'invalid_password',
                    'raw_event_data': json.dumps({
                        'event_type': 'failed_login',
                        'reason': 'typo',
                    }),
                    'country': country,
                    'city': city,
                    'latitude': lat,
                    'longitude': lon,
                    'timezone': tz,
                    'geoip_processed': 1,
                    'ip_risk_score': random.randint(0, 25),
                    'ip_reputation': 'clean',
                    'ip_health_processed': 1,
                    'ml_risk_score': random.randint(0, 30),
                    'ml_threat_type': 'failed_auth',
                    'ml_confidence': round(random.uniform(0.75, 0.95), 3),
                    'is_anomaly': 0,
                    'ml_processed': 1,
                    'pipeline_completed': 1
                }

            events.append(event)

        return events

    def generate_slow_scan(self, timestamp: datetime) -> List[Dict]:
        """Generate slow port scan/reconnaissance"""
        events = []
        attacker_ip = random.choice(MALICIOUS_IPS)
        attempts = random.randint(5, 15)

        for i in range(attempts):
            event_time = timestamp + timedelta(hours=random.randint(1, 24))
            server = random.choice(SERVERS)
            username = random.choice(MALICIOUS_USERNAMES)
            country, city, lat, lon, tz = self.get_geo_data(True)

            events.append({
                'table': 'failed_logins',
                'timestamp': event_time,
                'server_hostname': server,
                'source_ip': attacker_ip,
                'username': username,
                'port': 22,
                'failure_reason': random.choice(['invalid_password', 'invalid_user']),
                'raw_event_data': json.dumps({
                    'event_type': 'slow_scan',
                    'pattern': 'reconnaissance',
                }),
                'country': country,
                'city': city,
                'latitude': lat,
                'longitude': lon,
                'timezone': tz,
                'geoip_processed': 1,
                'ip_risk_score': random.randint(40, 60),
                'ip_reputation': 'suspicious',
                'ip_health_processed': 1,
                'ml_risk_score': random.randint(45, 65),
                'ml_threat_type': 'reconnaissance',
                'ml_confidence': round(random.uniform(0.70, 0.85), 3),
                'is_anomaly': 1,
                'ml_processed': 1,
                'pipeline_completed': 1
            })

        return events

    def generate_brute_force(self, timestamp: datetime, severity: str = 'medium') -> List[Dict]:
        """Generate brute force attack with varying severity"""
        events = []
        attacker_ip = random.choice(MALICIOUS_IPS)
        target_server = random.choice(SERVERS)

        if severity == 'low':
            attempts = random.randint(10, 20)
            time_window_minutes = random.randint(30, 60)
            base_risk = 50
        elif severity == 'medium':
            attempts = random.randint(20, 50)
            time_window_minutes = random.randint(10, 30)
            base_risk = 65
        else:  # high
            attempts = random.randint(50, 100)
            time_window_minutes = random.randint(5, 15)
            base_risk = 80

        for i in range(attempts):
            # Vary username for credential stuffing
            if random.random() < 0.4:
                username = random.choice(MALICIOUS_USERNAMES)
            else:
                username = f"user{random.randint(1, 1000)}"

            event_time = timestamp + timedelta(
                minutes=random.randint(0, time_window_minutes),
                seconds=random.randint(0, 59)
            )

            risk_score = min(100, base_risk + (i * (40 / attempts)))
            country, city, lat, lon, tz = self.get_geo_data(True)

            events.append({
                'table': 'failed_logins',
                'timestamp': event_time,
                'server_hostname': target_server,
                'source_ip': attacker_ip,
                'username': username,
                'port': 22,
                'failure_reason': random.choice(['invalid_password', 'invalid_user']),
                'raw_event_data': json.dumps({
                    'event_type': 'brute_force',
                    'severity': severity,
                    'attempt': i + 1,
                }),
                'country': country,
                'city': city,
                'latitude': lat,
                'longitude': lon,
                'timezone': tz,
                'geoip_processed': 1,
                'ip_risk_score': int(risk_score),
                'ip_reputation': 'malicious',
                'ip_health_processed': 1,
                'ml_risk_score': int(risk_score + random.randint(-5, 10)),
                'ml_threat_type': 'brute_force',
                'ml_confidence': round(random.uniform(0.85, 0.99), 3),
                'is_anomaly': 1,
                'ml_processed': 1,
                'pipeline_completed': 1
            })

        return events

    def generate_distributed_attack(self, timestamp: datetime) -> List[Dict]:
        """Generate coordinated distributed attack"""
        events = []
        target_server = random.choice(SERVERS)
        target_user = random.choice(['root', 'admin', 'administrator'])
        num_attackers = random.randint(10, 30)

        for _ in range(num_attackers):
            attacker_ip = random.choice(MALICIOUS_IPS)
            attempts = random.randint(5, 15)

            for i in range(attempts):
                event_time = timestamp + timedelta(
                    minutes=random.randint(0, 120)
                )

                country, city, lat, lon, tz = self.get_geo_data(True)

                events.append({
                    'table': 'failed_logins',
                    'timestamp': event_time,
                    'server_hostname': target_server,
                    'source_ip': attacker_ip,
                    'username': target_user,
                    'port': 22,
                    'failure_reason': 'invalid_password',
                    'raw_event_data': json.dumps({
                        'event_type': 'distributed_attack',
                        'pattern': 'coordinated',
                    }),
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
                    'ml_confidence': round(random.uniform(0.85, 0.98), 3),
                    'is_anomaly': 1,
                    'ml_processed': 1,
                    'pipeline_completed': 1
                })

        return events

    def generate_successful_breach(self, timestamp: datetime) -> List[Dict]:
        """Generate successful breach after attempts"""
        events = []
        attacker_ip = random.choice(MALICIOUS_IPS)
        server = random.choice(SERVERS)
        username = random.choice(MALICIOUS_USERNAMES)

        # Failed attempts first
        attempts = random.randint(10, 30)
        for i in range(attempts):
            event_time = timestamp + timedelta(seconds=i * random.randint(5, 20))
            country, city, lat, lon, tz = self.get_geo_data(True)

            events.append({
                'table': 'failed_logins',
                'timestamp': event_time,
                'server_hostname': server,
                'source_ip': attacker_ip,
                'username': username,
                'port': 22,
                'failure_reason': 'invalid_password',
                'raw_event_data': json.dumps({
                    'event_type': 'breach_attempt',
                    'phase': 'attempting',
                }),
                'country': country,
                'city': city,
                'latitude': lat,
                'longitude': lon,
                'timezone': tz,
                'geoip_processed': 1,
                'ip_risk_score': random.randint(70, 85),
                'ip_reputation': 'malicious',
                'ip_health_processed': 1,
                'ml_risk_score': random.randint(75, 90),
                'ml_threat_type': 'brute_force',
                'ml_confidence': round(random.uniform(0.85, 0.95), 3),
                'is_anomaly': 1,
                'ml_processed': 1,
                'pipeline_completed': 1
            })

        # Successful breach
        breach_time = timestamp + timedelta(seconds=attempts * 15 + 30)
        events.append({
            'table': 'successful_logins',
            'timestamp': breach_time,
            'server_hostname': server,
            'source_ip': attacker_ip,
            'username': username,
            'port': 22,
            'session_duration': random.randint(3600, 14400),
            'raw_event_data': json.dumps({
                'event_type': 'successful_breach',
                'phase': 'compromised',
            }),
            'country': country,
            'city': city,
            'latitude': lat,
            'longitude': lon,
            'timezone': tz,
            'geoip_processed': 1,
            'ip_risk_score': 95,
            'ip_reputation': 'malicious',
            'ip_health_processed': 1,
            'ml_risk_score': random.randint(90, 100),
            'ml_threat_type': 'intrusion',
            'ml_confidence': round(random.uniform(0.90, 0.99), 3),
            'is_anomaly': 1,
            'ml_processed': 1,
            'pipeline_completed': 1
        })

        return events

    def generate_dataset(self, total_events: int = 50000):
        """Generate complete large-scale dataset"""
        print(f"\n🔄 Generating {total_events:,} SSH events for ML training...")
        print(f"📅 Date range: {self.start_time.date()} to {datetime.now().date()}")

        # Distribution
        normal_ratio = 0.60  # 60% normal
        slow_scan_ratio = 0.05  # 5% reconnaissance
        brute_force_ratio = 0.25  # 25% brute force
        distributed_ratio = 0.08  # 8% distributed
        breach_ratio = 0.02  # 2% successful breaches

        all_events = []
        current_time = self.start_time

        # Normal behavior
        normal_count = int(total_events * normal_ratio)
        print(f"\n✅ Generating {normal_count:,} normal behavior events...")
        batch_size = 1000
        for i in range(0, normal_count, batch_size):
            current_time += timedelta(hours=random.randint(1, 6))
            batch = self.generate_normal_behavior(current_time, min(batch_size, normal_count - i))
            all_events.extend(batch)
            if (i + batch_size) % 5000 == 0:
                print(f"   Progress: {i + batch_size:,}/{normal_count:,}")

        # Slow scans
        scan_campaigns = int((total_events * slow_scan_ratio) / 10)
        print(f"\n🔍 Generating ~{scan_campaigns} reconnaissance campaigns...")
        for i in range(scan_campaigns):
            current_time += timedelta(hours=random.randint(12, 48))
            all_events.extend(self.generate_slow_scan(current_time))
            if (i + 1) % 50 == 0:
                print(f"   Campaigns: {i + 1}/{scan_campaigns}")

        # Brute force attacks
        bf_low = int((total_events * brute_force_ratio * 0.4) / 15)
        bf_med = int((total_events * brute_force_ratio * 0.4) / 35)
        bf_high = int((total_events * brute_force_ratio * 0.2) / 75)

        print(f"\n💥 Generating brute force attacks...")
        print(f"   Low severity: ~{bf_low} campaigns")
        for i in range(bf_low):
            current_time += timedelta(hours=random.randint(2, 12))
            all_events.extend(self.generate_brute_force(current_time, 'low'))

        print(f"   Medium severity: ~{bf_med} campaigns")
        for i in range(bf_med):
            current_time += timedelta(hours=random.randint(1, 8))
            all_events.extend(self.generate_brute_force(current_time, 'medium'))

        print(f"   High severity: ~{bf_high} campaigns")
        for i in range(bf_high):
            current_time += timedelta(hours=random.randint(1, 6))
            all_events.extend(self.generate_brute_force(current_time, 'high'))

        # Distributed attacks
        dist_campaigns = int((total_events * distributed_ratio) / 150)
        print(f"\n🌐 Generating ~{dist_campaigns} distributed attack campaigns...")
        for i in range(dist_campaigns):
            current_time += timedelta(hours=random.randint(6, 24))
            all_events.extend(self.generate_distributed_attack(current_time))
            if (i + 1) % 10 == 0:
                print(f"   Campaigns: {i + 1}/{dist_campaigns}")

        # Successful breaches
        breach_campaigns = int((total_events * breach_ratio) / 25)
        print(f"\n🚨 Generating ~{breach_campaigns} successful breach scenarios...")
        for i in range(breach_campaigns):
            current_time += timedelta(hours=random.randint(24, 72))
            all_events.extend(self.generate_successful_breach(current_time))

        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])

        print(f"\n✅ Generated {len(all_events):,} total events")
        return all_events

    def save_events(self, events: List[Dict]):
        """Save events to database"""
        successful = [e for e in events if e['table'] == 'successful_logins']
        failed = [e for e in events if e['table'] == 'failed_logins']

        print(f"\n💾 Saving events to database...")
        print(f"   Successful logins: {len(successful):,}")
        print(f"   Failed logins: {len(failed):,}")

        # Save successful logins
        if successful:
            query = """
            INSERT INTO successful_logins
            (timestamp, server_hostname, source_ip, username, port, session_duration,
             raw_event_data, country, city, latitude, longitude, timezone,
             geoip_processed, ip_risk_score, ip_reputation, ip_health_processed,
             ml_risk_score, ml_threat_type, ml_confidence, is_anomaly,
             ml_processed, pipeline_completed)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """

            batch_size = 1000
            saved = 0
            with self.connection.cursor() as cursor:
                for i in range(0, len(successful), batch_size):
                    batch = successful[i:i+batch_size]
                    values = [(
                        e['timestamp'], e['server_hostname'], e['source_ip'],
                        e['username'], e['port'], e['session_duration'],
                        e['raw_event_data'], e['country'], e['city'],
                        e['latitude'], e['longitude'], e['timezone'],
                        e['geoip_processed'], e['ip_risk_score'],
                        e['ip_reputation'], e['ip_health_processed'],
                        e['ml_risk_score'], e['ml_threat_type'],
                        e['ml_confidence'], e['is_anomaly'],
                        e['ml_processed'], e['pipeline_completed']
                    ) for e in batch]
                    cursor.executemany(query, values)
                    self.connection.commit()
                    saved += len(batch)
                    print(f"   Saved successful: {saved:,}/{len(successful):,}")

        # Save failed logins
        if failed:
            query = """
            INSERT INTO failed_logins
            (timestamp, server_hostname, source_ip, username, port, failure_reason,
             raw_event_data, country, city, latitude, longitude, timezone,
             geoip_processed, ip_risk_score, ip_reputation, ip_health_processed,
             ml_risk_score, ml_threat_type, ml_confidence, is_anomaly,
             ml_processed, pipeline_completed)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """

            batch_size = 1000
            saved = 0
            with self.connection.cursor() as cursor:
                for i in range(0, len(failed), batch_size):
                    batch = failed[i:i+batch_size]
                    values = [(
                        e['timestamp'], e['server_hostname'], e['source_ip'],
                        e['username'], e['port'], e['failure_reason'],
                        e['raw_event_data'], e['country'], e['city'],
                        e['latitude'], e['longitude'], e['timezone'],
                        e['geoip_processed'], e['ip_risk_score'],
                        e['ip_reputation'], e['ip_health_processed'],
                        e['ml_risk_score'], e['ml_threat_type'],
                        e['ml_confidence'], e['is_anomaly'],
                        e['ml_processed'], e['pipeline_completed']
                    ) for e in batch]
                    cursor.executemany(query, values)
                    self.connection.commit()
                    saved += len(batch)
                    print(f"   Saved failed: {saved:,}/{len(failed):,}")

        print(f"✅ All events saved successfully")

    def print_stats(self):
        """Print dataset statistics"""
        print(f"\n{'='*80}")
        print("📊 TRAINING DATASET STATISTICS")
        print(f"{'='*80}")

        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM successful_logins")
            success_total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM failed_logins")
            failed_total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM successful_logins WHERE is_anomaly=1")
            breaches = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM failed_logins WHERE is_anomaly=1")
            attacks = cursor.fetchone()[0]

            total = success_total + failed_total

            print(f"\n📊 Total Events: {total:,}")
            print(f"   ✅ Successful: {success_total:,} ({success_total/total*100:.1f}%)")
            print(f"   ❌ Failed: {failed_total:,} ({failed_total/total*100:.1f}%)")
            print(f"\n🎯 Anomalies: {breaches + attacks:,} ({(breaches+attacks)/total*100:.1f}%)")
            print(f"   🚨 Breaches: {breaches:,}")
            print(f"   ⚔️  Attacks: {attacks:,}")
            print(f"\n{'='*80}")

    def close(self):
        if self.connection:
            self.connection.close()

def main():
    print("="*80)
    print("🛡️  SSH GUARDIAN 2.0 - LARGE-SCALE TRAINING DATA GENERATOR")
    print("="*80)

    generator = LargeScaleDataGenerator()

    if not generator.connect_db():
        sys.exit(1)

    # Generate 50,000 events
    events = generator.generate_dataset(50000)

    # Save to database
    generator.save_events(events)

    # Print statistics
    generator.print_stats()

    generator.close()

    print("\n✅ Training dataset generation complete!")
    print("🎓 Ready for ML model training")

if __name__ == "__main__":
    main()
