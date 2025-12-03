#!/usr/bin/env python3
"""
Enhanced Large-Scale Training Dataset Generator for SSH Guardian 2.0
Generates 100,000+ highly realistic and diverse SSH events for ML training
"""

import random
import pymysql
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import sys
import os
import json
from collections import defaultdict
import numpy as np

from dotenv import load_dotenv
load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', '123123'),
    'database': os.getenv('DB_NAME', 'ssh_guardian_20'),
    'charset': 'utf8mb4'
}

# MASSIVE IP POOLS FOR DIVERSITY
LEGITIMATE_IP_RANGES = {
    'office_networks': [f'192.168.{subnet}.{host}' for subnet in range(1, 20) for host in range(10, 250, 5)],
    'vpn_endpoints': [f'10.{subnet}.{block}.{host}' for subnet in range(10, 50) for block in range(0, 255, 10) for host in range(10, 50, 5)],
    'cloud_aws': [f'52.{subnet}.{block}.{host}' for subnet in range(0, 255, 5) for block in range(0, 255, 20) for host in range(10, 100, 10)],
    'cloud_gcp': [f'35.{subnet}.{block}.{host}' for subnet in range(180, 255, 3) for block in range(1, 255, 15) for host in range(1, 50, 5)],
    'cloud_azure': [f'20.{subnet}.{block}.{host}' for subnet in range(0, 255, 10) for block in range(70, 255, 10) for host in range(1, 50, 5)],
    'cloud_digitalocean': [f'159.{subnet}.{block}.{host}' for subnet in range(0, 255, 20) for block in range(0, 255, 25) for host in range(1, 50, 10)],
    'home_networks': [f'73.{subnet}.{block}.{host}' for subnet in range(0, 255, 15) for block in range(0, 255, 30) for host in range(1, 50, 10)],
}

MALICIOUS_IP_RANGES = {
    'tor_exits': [f'185.220.{subnet}.{host}' for subnet in range(100, 130) for host in range(1, 255, 3)],
    'china_attackers': [f'222.{subnet}.{block}.{host}' for subnet in range(180, 200) for block in range(40, 60) for host in range(10, 100, 5)],
    'russia_attackers': [f'94.{subnet}.{block}.{host}' for subnet in range(230, 245) for block in range(40, 60) for host in range(100, 200, 5)],
    'eastern_europe': [f'45.{subnet}.{block}.{host}' for subnet in range(140, 160) for block in range(100, 150) for host in range(1, 100, 5)],
    'asia_botnets': [f'103.{subnet}.{block}.{host}' for subnet in range(200, 255) for block in range(100, 200) for host in range(10, 100, 5)],
    'compromised_vps': [f'157.{subnet}.{block}.{host}' for subnet in range(240, 255) for block in range(100, 200) for host in range(10, 100, 5)],
    'botnets': [f'159.{subnet}.{block}.{host}' for subnet in range(65, 100) for block in range(80, 150) for host in range(50, 150, 5)],
    'iran_threats': [f'188.{subnet}.{block}.{host}' for subnet in range(34, 50) for block in range(100, 200) for host in range(1, 100, 5)],
    'nkorea_apts': [f'175.45.{subnet}.{host}' for subnet in range(170, 180) for host in range(1, 255, 3)],
    'vietnam_scanners': [f'118.{subnet}.{block}.{host}' for subnet in range(69, 80) for block in range(50, 100) for host in range(1, 100, 5)],
}

LEGITIMATE_IPS = [ip for ips in LEGITIMATE_IP_RANGES.values() for ip in ips]
MALICIOUS_IPS = [ip for ips in MALICIOUS_IP_RANGES.values() for ip in ips]

# Expanded usernames for more realistic patterns
LEGITIMATE_USERNAMES = [
    # System admins
    'admin', 'sysadmin', 'root', 'administrator', 'superuser',
    # DevOps tools
    'jenkins', 'gitlab', 'circleci', 'travis', 'ansible', 'terraform', 'puppet', 'chef',
    'docker', 'kubernetes', 'k8s-admin', 'deploy', 'deployer', 'deployment',
    # OS defaults
    'ubuntu', 'centos', 'debian', 'fedora', 'alpine',
    # Service accounts
    'service', 'appuser', 'webmaster', 'webadmin', 'ops', 'devops', 'monitoring',
    'backup', 'dbadmin', 'developer', 'engineer', 'support', 'maintenance',
    # Real names (common)
    'john', 'sarah', 'mike', 'alice', 'bob', 'charlie', 'david', 'emily',
    'frank', 'grace', 'henry', 'isabella', 'jack', 'kate', 'liam', 'maria',
    'nathan', 'olivia', 'peter', 'quinn', 'rachel', 'sam', 'tina', 'victor',
    'william', 'xavier', 'yolanda', 'zack', 'anna', 'ben', 'cara', 'dan',
    # Project-specific
    'webapp', 'api', 'frontend', 'backend', 'database', 'cache', 'worker',
]

MALICIOUS_USERNAMES = [
    # Default/common targets
    'root', 'admin', 'test', 'guest', 'user', 'oracle', 'postgres', 'mysql',
    'mongodb', 'redis', 'elastic', 'admin123', 'admin1', 'admin2', 'admins',
    'administrator', 'administrators', 'user1', 'user123', 'ftpuser', 'ftp',
    # Services
    'tomcat', 'apache', 'nginx', 'www', 'www-data', 'webadmin', 'webmaster',
    'httpd', 'nobody', 'daemon', 'bin', 'sys', 'sync', 'mail', 'proxy',
    # Common defaults
    'default', 'support', 'help', 'info', 'demo', 'temp', 'temporary', 'backup',
    'nagios', 'zabbix', 'cacti', 'grafana', 'prometheus', 'splunk',
    # IoT/embedded
    'pi', 'raspberry', 'ubnt', 'ubiquiti', 'admin1234', 'password',
    # Gaming
    'minecraft', 'steam', 'teamspeak', 'ts3', 'mumble', 'discord',
    # Dictionary attacks
    'testuser', 'test1', 'test123', 'testing', 'sample', 'example',
    # Numeric patterns
    *[f'user{i}' for i in range(1, 100)],
    *[f'test{i}' for i in range(1, 50)],
    *[f'admin{i}' for i in range(1, 30)],
]

SERVERS = [
    # Web servers
    'web-01', 'web-02', 'web-03', 'web-04', 'web-05', 'web-06', 'web-07', 'web-08',
    # Database servers
    'db-master-01', 'db-replica-01', 'db-replica-02', 'db-backup-01',
    'postgres-01', 'mysql-01', 'redis-01', 'mongodb-01',
    # Application servers
    'app-01', 'app-02', 'app-03', 'app-04', 'app-05', 'app-06',
    # API gateways
    'api-gateway-01', 'api-gateway-02', 'api-gateway-03',
    # Environments
    'staging-web-01', 'staging-app-01', 'staging-db-01',
    'prod-web-01', 'prod-web-02', 'prod-app-01', 'prod-app-02', 'prod-db-01',
    'dev-01', 'dev-02', 'qa-01', 'qa-02',
    # Infrastructure
    'cache-01', 'cache-02', 'queue-01', 'queue-02', 'loadbalancer-01',
    'bastion-01', 'jumphost-01', 'vpn-gateway-01',
]

LEGIT_LOCATIONS = [
    ('US', 'New York', 40.7128, -74.0060, 'America/New_York'),
    ('US', 'San Francisco', 37.7749, -122.4194, 'America/Los_Angeles'),
    ('US', 'Seattle', 47.6062, -122.3321, 'America/Los_Angeles'),
    ('US', 'Chicago', 41.8781, -87.6298, 'America/Chicago'),
    ('US', 'Austin', 30.2672, -97.7431, 'America/Chicago'),
    ('US', 'Boston', 42.3601, -71.0589, 'America/New_York'),
    ('US', 'Denver', 39.7392, -104.9903, 'America/Denver'),
    ('US', 'Atlanta', 33.7490, -84.3880, 'America/New_York'),
    ('GB', 'London', 51.5074, -0.1278, 'Europe/London'),
    ('GB', 'Manchester', 53.4808, -2.2426, 'Europe/London'),
    ('DE', 'Frankfurt', 50.1109, 8.6821, 'Europe/Berlin'),
    ('DE', 'Berlin', 52.5200, 13.4050, 'Europe/Berlin'),
    ('DE', 'Munich', 48.1351, 11.5820, 'Europe/Berlin'),
    ('FR', 'Paris', 48.8566, 2.3522, 'Europe/Paris'),
    ('FR', 'Lyon', 45.7640, 4.8357, 'Europe/Paris'),
    ('CA', 'Toronto', 43.6532, -79.3832, 'America/Toronto'),
    ('CA', 'Vancouver', 49.2827, -123.1207, 'America/Vancouver'),
    ('CA', 'Montreal', 45.5017, -73.5673, 'America/Toronto'),
    ('AU', 'Sydney', -33.8688, 151.2093, 'Australia/Sydney'),
    ('AU', 'Melbourne', -37.8136, 144.9631, 'Australia/Melbourne'),
    ('JP', 'Tokyo', 35.6762, 139.6503, 'Asia/Tokyo'),
    ('JP', 'Osaka', 34.6937, 135.5023, 'Asia/Tokyo'),
    ('SG', 'Singapore', 1.3521, 103.8198, 'Asia/Singapore'),
    ('NL', 'Amsterdam', 52.3676, 4.9041, 'Europe/Amsterdam'),
    ('SE', 'Stockholm', 59.3293, 18.0686, 'Europe/Stockholm'),
    ('IE', 'Dublin', 53.3498, -6.2603, 'Europe/Dublin'),
    ('CH', 'Zurich', 47.3769, 8.5417, 'Europe/Zurich'),
]

MALICIOUS_LOCATIONS = [
    ('CN', 'Beijing', 39.9042, 116.4074, 'Asia/Shanghai'),
    ('CN', 'Shanghai', 31.2304, 121.4737, 'Asia/Shanghai'),
    ('CN', 'Shenzhen', 22.5431, 114.0579, 'Asia/Shanghai'),
    ('CN', 'Guangzhou', 23.1291, 113.2644, 'Asia/Shanghai'),
    ('RU', 'Moscow', 55.7558, 37.6173, 'Europe/Moscow'),
    ('RU', 'St Petersburg', 59.9343, 30.3351, 'Europe/Moscow'),
    ('RU', 'Novosibirsk', 55.0084, 82.9357, 'Asia/Novosibirsk'),
    ('RU', 'Yekaterinburg', 56.8389, 60.6057, 'Asia/Yekaterinburg'),
    ('KP', 'Pyongyang', 39.0392, 125.7625, 'Asia/Pyongyang'),
    ('IR', 'Tehran', 35.6892, 51.3890, 'Asia/Tehran'),
    ('IR', 'Isfahan', 32.6546, 51.6680, 'Asia/Tehran'),
    ('VN', 'Hanoi', 21.0285, 105.8542, 'Asia/Ho_Chi_Minh'),
    ('VN', 'Ho Chi Minh', 10.8231, 106.6297, 'Asia/Ho_Chi_Minh'),
    ('UA', 'Kiev', 50.4501, 30.5234, 'Europe/Kiev'),
    ('UA', 'Kharkiv', 49.9935, 36.2304, 'Europe/Kiev'),
    ('BR', 'Sao Paulo', -23.5505, -46.6333, 'America/Sao_Paulo'),
    ('BR', 'Rio de Janeiro', -22.9068, -43.1729, 'America/Sao_Paulo'),
    ('IN', 'Mumbai', 19.0760, 72.8777, 'Asia/Kolkata'),
    ('IN', 'Bangalore', 12.9716, 77.5946, 'Asia/Kolkata'),
    ('IN', 'Delhi', 28.7041, 77.1025, 'Asia/Kolkata'),
    ('PK', 'Karachi', 24.8607, 67.0011, 'Asia/Karachi'),
    ('PK', 'Lahore', 31.5204, 74.3587, 'Asia/Karachi'),
    ('Unknown', 'Unknown', None, None, None),
]

class EnhancedDataGenerator:
    def __init__(self):
        self.connection = None
        self.start_time = datetime.now() - timedelta(days=180)  # 6 months of data
        self.legitimate_ips_sample = random.sample(LEGITIMATE_IPS, min(5000, len(LEGITIMATE_IPS)))
        self.malicious_ips_sample = random.sample(MALICIOUS_IPS, min(3000, len(MALICIOUS_IPS)))

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

    def generate_normal_activity(self, timestamp: datetime, num_events: int) -> List[Dict]:
        """Generate highly realistic normal user activity"""
        events = []

        # Simulate realistic user sessions
        num_users = max(1, num_events // 5)  # Group into sessions

        for _ in range(num_users):
            ip = random.choice(self.legitimate_ips_sample)
            username = random.choice(LEGITIMATE_USERNAMES)
            server = random.choice(SERVERS)
            country, city, lat, lon, tz = self.get_geo_data(False)

            # User session: 3-10 events
            session_events = random.randint(3, 10)
            session_start = timestamp + timedelta(
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )

            for i in range(session_events):
                event_time = session_start + timedelta(seconds=i * random.randint(30, 300))

                # 95% successful, 5% failed (typos, wrong passwords)
                is_success = random.random() < 0.95

                if is_success:
                    event = {
                        'table': 'successful_logins',
                        'timestamp': event_time,
                        'server_hostname': server,
                        'source_ip': ip,
                        'username': username,
                        'port': 22,
                        'session_duration': random.randint(300, 7200),
                        'raw_event_data': json.dumps({
                            'event_type': 'successful_login',
                            'auth_method': random.choice(['password', 'publickey', 'publickey']),  # More publickey
                        }),
                        'country': country,
                        'city': city,
                        'latitude': lat,
                        'longitude': lon,
                        'timezone': tz,
                        'geoip_processed': 1,
                        'ip_risk_score': random.randint(0, 15),
                        'ip_reputation': 'clean',
                        'ip_health_processed': 1,
                        'ml_risk_score': random.randint(0, 20),
                        'ml_threat_type': 'normal',
                        'ml_confidence': round(random.uniform(0.90, 0.99), 3),
                        'is_anomaly': 0,
                        'ml_processed': 1,
                        'pipeline_completed': 1
                    }
                else:
                    # Legitimate failed login (typo)
                    event = {
                        'table': 'failed_logins',
                        'timestamp': event_time,
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
                        'ip_risk_score': random.randint(0, 20),
                        'ip_reputation': 'clean',
                        'ip_health_processed': 1,
                        'ml_risk_score': random.randint(0, 25),
                        'ml_threat_type': 'failed_auth',
                        'ml_confidence': round(random.uniform(0.80, 0.95), 3),
                        'is_anomaly': 0,
                        'ml_processed': 1,
                        'pipeline_completed': 1
                    }

                events.append(event)

                if len(events) >= num_events:
                    break

            if len(events) >= num_events:
                break

        return events[:num_events]

    def generate_credential_stuffing(self, timestamp: datetime) -> List[Dict]:
        """Generate credential stuffing attack"""
        events = []
        attacker_ip = random.choice(self.malicious_ips_sample)
        target_servers = random.sample(SERVERS, random.randint(3, 8))

        # Try many username/password combos
        attempts = random.randint(50, 200)

        for i in range(attempts):
            event_time = timestamp + timedelta(
                seconds=random.randint(0, 600)  # 10 minute window
            )

            server = random.choice(target_servers)
            username = random.choice(MALICIOUS_USERNAMES + LEGITIMATE_USERNAMES[:10])
            country, city, lat, lon, tz = self.get_geo_data(True)

            risk_score = min(100, 60 + (i * 30 / attempts))

            events.append({
                'table': 'failed_logins',
                'timestamp': event_time,
                'server_hostname': server,
                'source_ip': attacker_ip,
                'username': username,
                'port': 22,
                'failure_reason': random.choice(['invalid_password', 'invalid_user']),
                'raw_event_data': json.dumps({
                    'event_type': 'credential_stuffing',
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
                'ml_threat_type': 'credential_stuffing',
                'ml_confidence': round(random.uniform(0.85, 0.98), 3),
                'is_anomaly': 1,
                'ml_processed': 1,
                'pipeline_completed': 1
            })

        return events

    def generate_slow_scan(self, timestamp: datetime) -> List[Dict]:
        """Generate slow reconnaissance scan"""
        events = []
        attacker_ip = random.choice(self.malicious_ips_sample)
        attempts = random.randint(8, 25)

        for i in range(attempts):
            event_time = timestamp + timedelta(hours=random.randint(1, 72))  # Spread over days
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
                'ip_risk_score': random.randint(45, 65),
                'ip_reputation': 'suspicious',
                'ip_health_processed': 1,
                'ml_risk_score': random.randint(50, 70),
                'ml_threat_type': 'reconnaissance',
                'ml_confidence': round(random.uniform(0.70, 0.88), 3),
                'is_anomaly': 1,
                'ml_processed': 1,
                'pipeline_completed': 1
            })

        return events

    def generate_brute_force(self, timestamp: datetime, severity: str = 'medium') -> List[Dict]:
        """Generate brute force attack"""
        events = []
        attacker_ip = random.choice(self.malicious_ips_sample)
        target_server = random.choice(SERVERS)

        if severity == 'low':
            attempts = random.randint(15, 30)
            time_window_minutes = random.randint(30, 90)
            base_risk = 50
        elif severity == 'medium':
            attempts = random.randint(30, 80)
            time_window_minutes = random.randint(15, 45)
            base_risk = 70
        else:  # high
            attempts = random.randint(80, 200)
            time_window_minutes = random.randint(5, 20)
            base_risk = 85

        for i in range(attempts):
            username = random.choice(MALICIOUS_USERNAMES)

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
                'ml_confidence': round(random.uniform(0.88, 0.99), 3),
                'is_anomaly': 1,
                'ml_processed': 1,
                'pipeline_completed': 1
            })

        return events

    def generate_distributed_attack(self, timestamp: datetime) -> List[Dict]:
        """Generate DDoS/coordinated attack from multiple IPs"""
        events = []
        target_server = random.choice(SERVERS)
        target_user = random.choice(['root', 'admin', 'administrator'])
        num_attackers = random.randint(15, 50)

        for _ in range(num_attackers):
            attacker_ip = random.choice(self.malicious_ips_sample)
            attempts = random.randint(5, 20)

            for i in range(attempts):
                event_time = timestamp + timedelta(
                    minutes=random.randint(0, 180)
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
                    'ip_risk_score': random.randint(75, 95),
                    'ip_reputation': 'malicious',
                    'ip_health_processed': 1,
                    'ml_risk_score': random.randint(80, 98),
                    'ml_threat_type': 'distributed_attack',
                    'ml_confidence': round(random.uniform(0.88, 0.99), 3),
                    'is_anomaly': 1,
                    'ml_processed': 1,
                    'pipeline_completed': 1
                })

        return events

    def generate_successful_breach(self, timestamp: datetime) -> List[Dict]:
        """Generate successful breach after brute force"""
        events = []
        attacker_ip = random.choice(self.malicious_ips_sample)
        server = random.choice(SERVERS)
        username = random.choice(MALICIOUS_USERNAMES[:10])  # Common targets

        # Failed attempts first
        attempts = random.randint(20, 60)
        for i in range(attempts):
            event_time = timestamp + timedelta(seconds=i * random.randint(5, 30))
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
                'ip_risk_score': random.randint(75, 90),
                'ip_reputation': 'malicious',
                'ip_health_processed': 1,
                'ml_risk_score': random.randint(80, 95),
                'ml_threat_type': 'brute_force',
                'ml_confidence': round(random.uniform(0.88, 0.97), 3),
                'is_anomaly': 1,
                'ml_processed': 1,
                'pipeline_completed': 1
            })

        # SUCCESSFUL BREACH
        breach_time = timestamp + timedelta(seconds=attempts * 20 + 60)
        events.append({
            'table': 'successful_logins',
            'timestamp': breach_time,
            'server_hostname': server,
            'source_ip': attacker_ip,
            'username': username,
            'port': 22,
            'session_duration': random.randint(3600, 18000),  # Long sessions
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
            'ip_risk_score': 98,
            'ip_reputation': 'malicious',
            'ip_health_processed': 1,
            'ml_risk_score': random.randint(95, 100),
            'ml_threat_type': 'intrusion',
            'ml_confidence': round(random.uniform(0.92, 0.99), 3),
            'is_anomaly': 1,
            'ml_processed': 1,
            'pipeline_completed': 1
        })

        return events

    def generate_dataset(self, total_events: int = 100000):
        """Generate comprehensive large-scale dataset"""
        print(f"\n{'='*80}")
        print(f"🔄 Generating {total_events:,} Enhanced SSH Events for ML Training")
        print(f"{'='*80}")
        print(f"📅 Date range: {self.start_time.date()} to {datetime.now().date()}")

        # Distribution (more realistic)
        normal_ratio = 0.65  # 65% normal
        slow_scan_ratio = 0.04  # 4% reconnaissance
        brute_force_ratio = 0.18  # 18% brute force
        credential_stuffing_ratio = 0.08  # 8% credential stuffing
        distributed_ratio = 0.04  # 4% distributed
        breach_ratio = 0.01  # 1% successful breaches

        all_events = []
        current_time = self.start_time

        # 1. Normal behavior
        normal_count = int(total_events * normal_ratio)
        print(f"\n✅ Generating {normal_count:,} normal behavior events...")
        batch_size = 2000
        for i in range(0, normal_count, batch_size):
            current_time += timedelta(hours=random.randint(1, 8))
            batch = self.generate_normal_activity(current_time, min(batch_size, normal_count - i))
            all_events.extend(batch)
            if (i + batch_size) % 10000 == 0:
                print(f"   Progress: {len([e for e in all_events if e['table'] == 'successful_logins']):,} events")

        # 2. Credential stuffing
        cs_campaigns = int((total_events * credential_stuffing_ratio) / 100)
        print(f"\n🔐 Generating ~{cs_campaigns} credential stuffing campaigns...")
        for i in range(cs_campaigns):
            current_time += timedelta(hours=random.randint(6, 24))
            all_events.extend(self.generate_credential_stuffing(current_time))
            if (i + 1) % 50 == 0:
                print(f"   Campaigns: {i + 1}/{cs_campaigns}")

        # 3. Slow scans
        scan_campaigns = int((total_events * slow_scan_ratio) / 15)
        print(f"\n🔍 Generating ~{scan_campaigns} reconnaissance campaigns...")
        for i in range(scan_campaigns):
            current_time += timedelta(hours=random.randint(12, 72))
            all_events.extend(self.generate_slow_scan(current_time))
            if (i + 1) % 50 == 0:
                print(f"   Campaigns: {i + 1}/{scan_campaigns}")

        # 4. Brute force attacks
        bf_low = int((total_events * brute_force_ratio * 0.35) / 20)
        bf_med = int((total_events * brute_force_ratio * 0.40) / 50)
        bf_high = int((total_events * brute_force_ratio * 0.25) / 120)

        print(f"\n💥 Generating brute force attacks...")
        print(f"   Low severity: ~{bf_low} campaigns")
        for i in range(bf_low):
            current_time += timedelta(hours=random.randint(2, 18))
            all_events.extend(self.generate_brute_force(current_time, 'low'))

        print(f"   Medium severity: ~{bf_med} campaigns")
        for i in range(bf_med):
            current_time += timedelta(hours=random.randint(1, 12))
            all_events.extend(self.generate_brute_force(current_time, 'medium'))

        print(f"   High severity: ~{bf_high} campaigns")
        for i in range(bf_high):
            current_time += timedelta(hours=random.randint(1, 8))
            all_events.extend(self.generate_brute_force(current_time, 'high'))

        # 5. Distributed attacks
        dist_campaigns = int((total_events * distributed_ratio) / 200)
        print(f"\n🌐 Generating ~{dist_campaigns} distributed attack campaigns...")
        for i in range(dist_campaigns):
            current_time += timedelta(hours=random.randint(12, 48))
            all_events.extend(self.generate_distributed_attack(current_time))
            if (i + 1) % 10 == 0:
                print(f"   Campaigns: {i + 1}/{dist_campaigns}")

        # 6. Successful breaches
        breach_campaigns = int((total_events * breach_ratio) / 35)
        print(f"\n🚨 Generating ~{breach_campaigns} successful breach scenarios...")
        for i in range(breach_campaigns):
            current_time += timedelta(hours=random.randint(24, 96))
            all_events.extend(self.generate_successful_breach(current_time))

        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])

        print(f"\n✅ Generated {len(all_events):,} total events")
        return all_events

    def save_events(self, events: List[Dict]):
        """Save events to database in batches"""
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
        """Print comprehensive dataset statistics"""
        print(f"\n{'='*80}")
        print("📊 ENHANCED TRAINING DATASET STATISTICS")
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

            cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM failed_logins")
            unique_ips = cursor.fetchone()[0]

            total = success_total + failed_total

            print(f"\n📊 Total Events: {total:,}")
            print(f"   ✅ Successful: {success_total:,} ({success_total/total*100:.1f}%)")
            print(f"   ❌ Failed: {failed_total:,} ({failed_total/total*100:.1f}%)")
            print(f"\n🎯 Anomalies: {breaches + attacks:,} ({(breaches+attacks)/total*100:.1f}%)")
            print(f"   🚨 Breaches: {breaches:,}")
            print(f"   ⚔️  Attacks: {attacks:,}")
            print(f"\n🌐 Unique IPs: {unique_ips:,}")
            print(f"\n{'='*80}")

    def close(self):
        if self.connection:
            self.connection.close()

def main():
    print("="*80)
    print("🛡️  SSH GUARDIAN 2.0 - ENHANCED LARGE-SCALE DATA GENERATOR")
    print("="*80)

    generator = EnhancedDataGenerator()

    if not generator.connect_db():
        sys.exit(1)

    # Generate 100,000 events (can increase to 200k, 500k, etc.)
    events = generator.generate_dataset(100000)

    # Save to database
    generator.save_events(events)

    # Print statistics
    generator.print_stats()

    generator.close()

    print("\n✅ Enhanced training dataset generation complete!")
    print("🎓 Ready for high-accuracy ML model training")

if __name__ == "__main__":
    main()
