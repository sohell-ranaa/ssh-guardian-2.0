#!/usr/bin/env python3
"""
SSH Guardian 2.0 - Unified Real-Time System with Comprehensive Analytics & Alerts
Features: Real-time processing + GeoIP + Threat Intel + ML Analysis + Rich Telegram Alerts + Analytics
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from flask import Flask, request, jsonify
import json
import threading
import queue
import time
import hashlib
import re
import requests
from datetime import datetime, timedelta
from connection import get_connection
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
class Config:
    LOG_RECEIVER_PORT = 5000
    LOG_RECEIVER_HOST = '0.0.0.0'
    DATA_DIR = PROJECT_ROOT / "data"
    RECEIVING_DIR = DATA_DIR / "receiving_stream"
    THREAT_FEEDS_DIR = DATA_DIR / "threat_feeds"
    GEOIP_DB = DATA_DIR / "GeoLite2-City.mmdb"
    QUEUE_SIZE = 1000
    TELEGRAM_BOT_TOKEN = ""
    TELEGRAM_CHAT_ID = ""

config = Config()

# Load .env
def load_env():
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    value = value.strip('"')
                    if key == 'TELEGRAM_BOT_TOKEN':
                        config.TELEGRAM_BOT_TOKEN = value
                    elif key == 'TELEGRAM_CHAT_ID':
                        config.TELEGRAM_CHAT_ID = value

load_env()

# Create directories
config.DATA_DIR.mkdir(exist_ok=True)
config.RECEIVING_DIR.mkdir(exist_ok=True)
config.THREAT_FEEDS_DIR.mkdir(exist_ok=True)

# Queues for real-time processing
raw_logs_queue = queue.Queue(maxsize=config.QUEUE_SIZE)

# Global threat intelligence cache
threat_feeds_cache = {}
threat_feeds_last_update = None

# Global analytics cache
analytics_cache = {
    'hourly_stats': {},
    'country_stats': {},
    'threat_stats': {},
    'last_updated': None
}

# SSH Log Parser
class SSHLogParser:
    def __init__(self):
        self.patterns = {
            'accepted_password': r'Accepted password for (?P<username>\w+) from (?P<source_ip>[\d.]+) port (?P<port>\d+)',
            'accepted_publickey': r'Accepted publickey for (?P<username>\w+) from (?P<source_ip>[\d.]+) port (?P<port>\d+)',
            'failed_password': r'Failed password for (?P<username>\w*) from (?P<source_ip>[\d.]+) port (?P<port>\d+)',
            'invalid_user': r'Invalid user (?P<username>\w*) from (?P<source_ip>[\d.]+) port (?P<port>\d+)',
        }
        self.compiled_patterns = {name: re.compile(pattern) for name, pattern in self.patterns.items()}
    
    def parse_line(self, log_line: str, server_name: str = "unknown"):
        if not log_line or log_line.strip() == "":
            return None
        
        for event_type, pattern in self.compiled_patterns.items():
            match = pattern.search(log_line)
            if match:
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'server_hostname': server_name,
                    'event_type': event_type,
                    'raw_log': log_line,
                    'log_hash': hashlib.md5(log_line.encode()).hexdigest(),
                    **match.groupdict()
                }
                if 'port' in event:
                    event['port'] = int(event['port'])
                return event
        return None

# Threat Intelligence Functions
def update_threat_feeds():
    """Download threat feeds once daily and cache locally"""
    global threat_feeds_cache, threat_feeds_last_update
    
    current_time = datetime.now()
    
    # Check if we need to update (every 24 hours)
    if (threat_feeds_last_update and 
        (current_time - threat_feeds_last_update).total_seconds() < 24 * 3600):
        return  # Still fresh, skip update
    
    logger.info("Updating threat feeds...")
    
    feed_urls = {
        'feodo_ips': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'ssh_attackers': 'https://lists.blocklist.de/lists/ssh.txt'
    }
    
    for feed_name, url in feed_urls.items():
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                # Save to local file
                local_file = config.THREAT_FEEDS_DIR / f"{feed_name}.txt"
                with open(local_file, 'w') as f:
                    f.write(response.text)
                
                # Cache IPs in memory
                ips = set()
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and '.' in line:
                        ips.add(line.split()[0])
                
                threat_feeds_cache[feed_name] = ips
                logger.info(f"Updated {feed_name}: {len(ips)} IPs")
                
        except Exception as e:
            logger.error(f"Failed to update {feed_name}: {e}")
            # Try to load from existing file
            local_file = config.THREAT_FEEDS_DIR / f"{feed_name}.txt"
            if local_file.exists():
                try:
                    ips = set()
                    with open(local_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#') and '.' in line:
                                ips.add(line.split()[0])
                    threat_feeds_cache[feed_name] = ips
                    logger.info(f"Loaded cached {feed_name}: {len(ips)} IPs")
                except Exception as e2:
                    logger.error(f"Failed to load cached {feed_name}: {e2}")
    
    threat_feeds_last_update = current_time

def check_ip_reputation(ip: str) -> dict:
    """Check IP against cached threat feeds - enhanced to match existing format"""
    reputation = {
        'is_malicious': False,
        'threat_types': [],
        'risk_score': 0,
        'detailed_threats': []
    }
    
    # Check for private/local IPs first
    if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')):
        reputation['detailed_threats'] = ["Private IP - Low Risk"]
        reputation['risk_score'] = 5
        return reputation
    
    # Check against threat feeds
    for feed_name, ips in threat_feeds_cache.items():
        if ip in ips:
            reputation['is_malicious'] = True
            reputation['threat_types'].append(feed_name)
            
            # Add detailed threat descriptions based on feed
            if feed_name == 'feodo_ips':
                reputation['detailed_threats'].append("Feodo Tracker - Known Botnet")
                reputation['risk_score'] += 40
            elif feed_name == 'ssh_attackers':
                reputation['detailed_threats'].append("SSH Attacker - Brute Force Source")
                reputation['risk_score'] += 35
            else:
                reputation['detailed_threats'].append(f"Threat Feed: {feed_name}")
                reputation['risk_score'] += 30
    
    # If no threats found, it's clean
    if not reputation['detailed_threats']:
        reputation['detailed_threats'] = []
        reputation['risk_score'] = max(reputation['risk_score'], 20)  # Base score for external IPs
    
    return reputation

# GeoIP Functions
def enrich_with_geoip(event: dict) -> dict:
    """Add GeoIP data using existing database - enhanced to match existing format"""
    source_ip = event.get('source_ip')
    if not source_ip:
        return event
    
    try:
        if config.GEOIP_DB.exists():
            import geoip2.database
            with geoip2.database.Reader(str(config.GEOIP_DB)) as reader:
                response = reader.city(source_ip)
                
                # Handle private/local IPs
                if source_ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')):
                    event['geoip'] = {
                        'country': 'Local Network',
                        'country_code': 'LN',
                        'city': 'Private IP',
                        'latitude': None,
                        'longitude': None,
                        'timezone': None
                    }
                else:
                    event['geoip'] = {
                        'country': response.country.name or 'Unknown',
                        'country_code': response.country.iso_code or 'XX',
                        'city': response.city.name or 'Unknown',
                        'latitude': float(response.location.latitude) if response.location.latitude else None,
                        'longitude': float(response.location.longitude) if response.location.longitude else None,
                        'timezone': response.location.time_zone or None
                    }
        else:
            event['geoip'] = {'country': 'Unknown', 'city': 'Unknown', 'timezone': None}
            
    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {source_ip}: {e}")
        event['geoip'] = {'country': 'Unknown', 'city': 'Unknown', 'timezone': None}
    
    return event

# ML Analysis Functions
def calculate_ml_features(event: dict) -> list:
    """Calculate ML features from event data"""
    features = []
    
    # Time-based features
    timestamp = datetime.fromisoformat(event['timestamp'])
    features.extend([
        timestamp.hour,
        timestamp.weekday(),
        1 if timestamp.weekday() >= 5 else 0,  # is_weekend
    ])
    
    # IP-based features
    source_ip = event.get('source_ip', '0.0.0.0')
    if source_ip.startswith(('192.168.', '10.', '172.16.', '127.')):
        features.extend([192, 168, 1, 1])  # Private IP indicator
    else:
        ip_parts = source_ip.split('.')
        if len(ip_parts) == 4:
            features.extend([int(part) for part in ip_parts])
        else:
            features.extend([0, 0, 0, 0])
    
    # Port and event type
    features.append(event.get('port', 22))
    
    # Event type encoding
    event_type = event.get('event_type', 'unknown')
    event_type_scores = {
        'accepted_password': 1,
        'accepted_publickey': 0.5,
        'failed_password': 3,
        'invalid_user': 4,
        'connection_closed': 2,
        'disconnected': 2
    }
    features.append(event_type_scores.get(event_type, 2))
    
    # Geographic features
    geoip = event.get('geoip', {})
    features.extend([
        geoip.get('latitude', 0) or 0,
        geoip.get('longitude', 0) or 0
    ])
    
    # Threat reputation features
    threat_rep = event.get('threat_reputation', {})
    features.extend([
        1 if threat_rep.get('is_malicious') else 0,
        threat_rep.get('risk_score', 0) / 100  # Normalize to 0-1
    ])
    
    return features

def analyze_with_ml(event: dict) -> dict:
    """Perform ML analysis and add results to event - matches existing format"""
    
    try:
        # Calculate features
        features = calculate_ml_features(event)
        
        # Simple ML scoring based on multiple factors
        ml_risk_score = 0
        
        # Time-based risk (night hours)
        hour = datetime.fromisoformat(event['timestamp']).hour
        if hour < 6 or hour > 22:
            ml_risk_score += 10
        
        # Event type risk
        event_type = event.get('event_type', 'unknown')
        if 'failed' in event_type or 'invalid' in event_type:
            ml_risk_score += 20
        elif 'accepted' in event_type:
            ml_risk_score += 5
        
        # IP reputation risk
        threat_rep = event.get('threat_reputation', {})
        ml_risk_score += threat_rep.get('risk_score', 0)
        
        # Geographic risk (very basic)
        geoip = event.get('geoip', {})
        country = geoip.get('country', 'Unknown')
        if country == 'Local Network':
            ml_risk_score -= 10  # Local is safer
        elif country == 'Unknown':
            ml_risk_score += 15
        
        # Ensure reasonable range
        ml_risk_score = max(5, min(100, ml_risk_score))
        
        # Calculate confidence (higher for more extreme scores)
        if ml_risk_score > 70:
            confidence = min(0.9, 0.4 + (ml_risk_score - 70) / 100)
        elif ml_risk_score < 30:
            confidence = min(0.8, 0.3 + (30 - ml_risk_score) / 100)
        else:
            confidence = 0.2 + abs(ml_risk_score - 50) / 200
        
        # Determine threat type
        if ml_risk_score >= 80:
            ml_threat_type = "High Risk Activity"
        elif ml_risk_score >= 60:
            ml_threat_type = "Suspicious Activity"
        elif ml_risk_score >= 40:
            ml_threat_type = "Moderate Activity"
        else:
            ml_threat_type = "Normal Activity"
        
        # Determine if anomaly (threshold around 70)
        is_anomaly = ml_risk_score >= 70
        
        event['ml_analysis'] = {
            'ml_risk_score': ml_risk_score,
            'ml_threat_type': ml_threat_type,
            'ml_confidence': round(confidence, 3),
            'is_anomaly': is_anomaly
        }
        
        return event
        
    except Exception as e:
        logger.error(f"ML analysis failed: {e}")
        # Fallback values
        event['ml_analysis'] = {
            'ml_risk_score': 25,
            'ml_threat_type': "Normal Activity",
            'ml_confidence': 0.250,
            'is_anomaly': False
        }
        return event

# Analytics Functions
def update_analytics_cache():
    """Update analytics cache with current statistics"""
    global analytics_cache
    
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Hourly activity stats (last 24 hours)
        cursor.execute("""
            SELECT 
                HOUR(timestamp) as hour,
                COUNT(*) as total_events,
                SUM(CASE WHEN ml_risk_score >= 70 THEN 1 ELSE 0 END) as high_risk,
                AVG(ml_risk_score) as avg_risk
            FROM failed_logins 
            WHERE timestamp >= NOW() - INTERVAL 24 HOUR
            GROUP BY HOUR(timestamp)
            ORDER BY hour
        """)
        hourly_failed = {row[0]: {'failed': row[1], 'high_risk': row[2], 'avg_risk': float(row[3] or 0)} for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT 
                HOUR(timestamp) as hour,
                COUNT(*) as total_events,
                AVG(ml_risk_score) as avg_risk
            FROM successful_logins 
            WHERE timestamp >= NOW() - INTERVAL 24 HOUR
            GROUP BY HOUR(timestamp)
            ORDER BY hour
        """)
        hourly_success = {row[0]: {'successful': row[1], 'avg_risk': float(row[2] or 0)} for row in cursor.fetchall()}
        
        # Combine hourly stats
        hourly_stats = {}
        for hour in range(24):
            hourly_stats[hour] = {
                'failed': hourly_failed.get(hour, {}).get('failed', 0),
                'successful': hourly_success.get(hour, {}).get('successful', 0),
                'high_risk': hourly_failed.get(hour, {}).get('high_risk', 0),
                'avg_risk': (hourly_failed.get(hour, {}).get('avg_risk', 0) + hourly_success.get(hour, {}).get('avg_risk', 0)) / 2
            }
        
        # Country statistics
        cursor.execute("""
            SELECT 
                country,
                COUNT(*) as events,
                AVG(ml_risk_score) as avg_risk,
                SUM(CASE WHEN ip_reputation = 'malicious' THEN 1 ELSE 0 END) as malicious_count
            FROM (
                SELECT country, ml_risk_score, ip_reputation FROM failed_logins WHERE timestamp >= NOW() - INTERVAL 24 HOUR
                UNION ALL
                SELECT country, ml_risk_score, ip_reputation FROM successful_logins WHERE timestamp >= NOW() - INTERVAL 24 HOUR
            ) as combined
            WHERE country IS NOT NULL
            GROUP BY country
            ORDER BY events DESC
            LIMIT 10
        """)
        country_stats = {row[0]: {'events': row[1], 'avg_risk': float(row[2] or 0), 'malicious': row[3]} for row in cursor.fetchall()}
        
        # Threat statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_events,
                SUM(CASE WHEN ml_risk_score >= 80 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN ml_risk_score >= 60 AND ml_risk_score < 80 THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN ml_risk_score >= 40 AND ml_risk_score < 60 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN ml_risk_score < 40 THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN ip_reputation = 'malicious' THEN 1 ELSE 0 END) as malicious_ips
            FROM (
                SELECT ml_risk_score, ip_reputation FROM failed_logins WHERE timestamp >= NOW() - INTERVAL 24 HOUR
                UNION ALL
                SELECT ml_risk_score, ip_reputation FROM successful_logins WHERE timestamp >= NOW() - INTERVAL 24 HOUR
            ) as combined
        """)
        threat_row = cursor.fetchone()
        threat_stats = {
            'total_events': threat_row[0],
            'critical_risk': threat_row[1],
            'high_risk': threat_row[2],
            'medium_risk': threat_row[3],
            'low_risk': threat_row[4],
            'malicious_ips': threat_row[5]
        }
        
        analytics_cache = {
            'hourly_stats': hourly_stats,
            'country_stats': country_stats,
            'threat_stats': threat_stats,
            'last_updated': datetime.now().isoformat()
        }
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        logger.error(f"Analytics update error: {e}")

# Telegram Alert Functions
def send_telegram_message(message: str):
    """Send message to Telegram"""
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        logger.warning("Telegram not configured - check .env file")
        return False
    
    try:
        url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            'chat_id': config.TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'
        }
        response = requests.post(url, data=data, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")
        return False

def generate_comprehensive_alert(event: dict) -> str:
    """Generate comprehensive alert message with analytics"""
    
    # Get analysis data
    ml_analysis = event.get('ml_analysis', {})
    threat_rep = event.get('threat_reputation', {})
    geoip = event.get('geoip', {})
    
    # Get recent analytics
    if analytics_cache.get('last_updated'):
        update_analytics_cache()
    
    threat_stats = analytics_cache.get('threat_stats', {})
    country_stats = analytics_cache.get('country_stats', {})
    
    # Determine severity emoji
    risk_score = ml_analysis.get('ml_risk_score', 0)
    if risk_score >= 80:
        severity = "🚨 CRITICAL"
    elif risk_score >= 60:
        severity = "⚠️ HIGH RISK"
    elif risk_score >= 40:
        severity = "🟡 MEDIUM RISK"
    else:
        severity = "🟢 LOW RISK"
    
    # Build comprehensive message
    message = f"""{severity} *SSH Security Alert*

📊 *Event Details:*
• Server: `{event.get('server_hostname', 'unknown')}`
• Event: `{event.get('event_type', 'unknown').replace('_', ' ').title()}`
• Source IP: `{event.get('source_ip', 'unknown')}`
• Username: `{event.get('username', 'unknown') or 'N/A'}`
• Port: `{event.get('port', 22)}`

🌍 *Location:*
• City: {geoip.get('city', 'Unknown')}
• Country: {geoip.get('country', 'Unknown')}
• Timezone: {geoip.get('timezone', 'Unknown')}

🤖 *ML Analysis:*
• Risk Score: `{ml_analysis.get('ml_risk_score', 0)}/100`
• Threat Type: `{ml_analysis.get('ml_threat_type', 'Unknown')}`
• Confidence: `{ml_analysis.get('ml_confidence', 0):.1%}`
• Anomaly: {'🔴 YES' if ml_analysis.get('is_anomaly') else '🟢 NO'}

🛡️ *Threat Intelligence:*"""

    if threat_rep.get('detailed_threats'):
        for threat in threat_rep.get('detailed_threats', []):
            message += f"\n• {threat}"
    else:
        message += f"\n• Clean IP (Risk: {threat_rep.get('risk_score', 0)})"

    # Add analytics insights
    message += f"""

📈 *24h Analytics:*
• Total Events: {threat_stats.get('total_events', 0)}
• Critical Risk: {threat_stats.get('critical_risk', 0)}
• High Risk: {threat_stats.get('high_risk', 0)}
• Malicious IPs: {threat_stats.get('malicious_ips', 0)}"""

    # Add country insights if available
    country = geoip.get('country', 'Unknown')
    if country in country_stats:
        country_info = country_stats[country]
        message += f"""

🏴 *Country Stats ({country}):*
• Events: {country_info.get('events', 0)}
• Avg Risk: {country_info.get('avg_risk', 0):.1f}
• Malicious: {country_info.get('malicious', 0)}"""

    # Add recommendations
    message += f"""

💡 *Recommendations:*"""
    
    if risk_score >= 80:
        message += "\n• 🚨 Immediate investigation required"
        message += "\n• Consider IP blocking"
        message += "\n• Review server access policies"
    elif risk_score >= 60:
        message += "\n• Monitor this IP closely"
        message += "\n• Check for additional suspicious activity"
        message += "\n• Verify legitimate access if successful"
    elif 'failed' in event.get('event_type', '') or 'invalid' in event.get('event_type', ''):
        message += "\n• Monitor for brute force patterns"
        message += "\n• Consider rate limiting from this IP"
    else:
        message += "\n• Continue monitoring"
        message += "\n• Log for future analysis"
    
    return message

def check_and_send_alerts(event: dict):
    """Check event and send comprehensive alerts if needed"""
    
    # Get analysis data
    ml_analysis = event.get('ml_analysis', {})
    threat_rep = event.get('threat_reputation', {})
    
    # Alert conditions - LOWERED THRESHOLDS FOR TESTING
    should_alert = False
    alert_reasons = []
    
    # Lower threshold for ML risk (was 60, now 40)
    if ml_analysis.get('ml_risk_score', 0) >= 40:
        should_alert = True
        alert_reasons.append(f"🤖 ML Risk Score: {ml_analysis.get('ml_risk_score')}")
    
    # Malicious IP
    if threat_rep.get('is_malicious'):
        should_alert = True
        alert_reasons.append(f"🚨 Malicious IP detected")
    
    # Failed login attempts
    if 'failed' in event.get('event_type', '') or 'invalid' in event.get('event_type', ''):
        should_alert = True
        alert_reasons.append(f"🔐 Failed/Invalid login attempt")
    
    # Successful logins from high-risk IPs
    if ('accepted' in event.get('event_type', '') and 
        (ml_analysis.get('ml_risk_score', 0) >= 50 or threat_rep.get('is_malicious'))):
        should_alert = True
        alert_reasons.append(f"✅ Successful login from risky IP")
    
    if should_alert:
        # Generate comprehensive alert
        message = generate_comprehensive_alert(event)
        
        # Send alert
        success = send_telegram_message(message)
        
        if success:
            logger.info(f"📱 Telegram alert sent for {event.get('source_ip')} (Risk: {ml_analysis.get('ml_risk_score')})")
        else:
            logger.error(f"❌ Failed to send Telegram alert for {event.get('source_ip')}")

# Database functions
def check_duplicate_by_hash(log_hash: str) -> bool:
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM successful_logins WHERE raw_event_data LIKE %s LIMIT 1", (f'%{log_hash}%',))
        result1 = cursor.fetchone()
        if result1:
            cursor.close()
            conn.close()
            return True
        cursor.execute("SELECT 1 FROM failed_logins WHERE raw_event_data LIKE %s LIMIT 1", (f'%{log_hash}%',))
        result2 = cursor.fetchone()
        cursor.close()
        conn.close()
        return result2 is not None
    except Exception as e:
        logger.error(f"Error checking duplicate: {e}")
        return False

def save_event_to_database(event: dict):
    """Save event to database with proper column population - enhanced format"""
    if check_duplicate_by_hash(event['log_hash']):
        return False
    
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        is_successful = event.get('event_type') in ['accepted_password', 'accepted_publickey']
        
        # Extract enrichment data
        geoip = event.get('geoip', {})
        threat_rep = event.get('threat_reputation', {})
        ml_analysis = event.get('ml_analysis', {})
        
        if is_successful:
            query = """
            INSERT INTO successful_logins (
                timestamp, server_hostname, source_ip, username, port, session_duration, 
                country, city, latitude, longitude, timezone, geoip_processed,
                ip_risk_score, ip_reputation, threat_intel_data, ip_health_processed,
                ml_risk_score, ml_threat_type, ml_confidence, is_anomaly, ml_processed,
                raw_event_data
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (
                datetime.fromisoformat(event['timestamp']),
                event.get('server_hostname', 'unknown'),
                event.get('source_ip', 'unknown'),
                event.get('username', 'unknown'),
                event.get('port', 22),
                0,
                # GeoIP data
                geoip.get('country', None),
                geoip.get('city', None),
                geoip.get('latitude', None),
                geoip.get('longitude', None),
                geoip.get('timezone', None),
                True if geoip else False,
                # Threat intelligence
                threat_rep.get('risk_score', 0),
                'malicious' if threat_rep.get('is_malicious') else 'clean',
                json.dumps(threat_rep.get('detailed_threats', [])),
                True if threat_rep else False,
                # ML analysis
                ml_analysis.get('ml_risk_score', 25),
                ml_analysis.get('ml_threat_type', 'Normal Activity'),
                ml_analysis.get('ml_confidence', 0.250),
                ml_analysis.get('is_anomaly', False),
                True if ml_analysis else False,
                # Raw data
                json.dumps(event)
            )
        else:
            failure_reason = 'invalid_user' if 'invalid_user' in event.get('event_type', '') else 'invalid_password'
            query = """
            INSERT INTO failed_logins (
                timestamp, server_hostname, source_ip, username, port, failure_reason,
                country, city, latitude, longitude, timezone, geoip_processed,
                ip_risk_score, ip_reputation, threat_intel_data, ip_health_processed,
                ml_risk_score, ml_threat_type, ml_confidence, is_anomaly, ml_processed,
                raw_event_data
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (
                datetime.fromisoformat(event['timestamp']),
                event.get('server_hostname', 'unknown'),
                event.get('source_ip', 'unknown'),
                event.get('username', ''),
                event.get('port', 22),
                failure_reason,
                # GeoIP data
                geoip.get('country', None),
                geoip.get('city', None),
                geoip.get('latitude', None),
                geoip.get('longitude', None),
                geoip.get('timezone', None),
                True if geoip else False,
                # Threat intelligence
                threat_rep.get('risk_score', 0),
                'malicious' if threat_rep.get('is_malicious') else 'clean',
                json.dumps(threat_rep.get('detailed_threats', [])),
                True if threat_rep else False,
                # ML analysis
                ml_analysis.get('ml_risk_score', 25),
                ml_analysis.get('ml_threat_type', 'Normal Activity'),
                ml_analysis.get('ml_confidence', 0.250),
                ml_analysis.get('is_anomaly', False),
                True if ml_analysis else False,
                # Raw data
                json.dumps(event)
            )
        
        cursor.execute(query, values)
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Database save error: {e}")
        return False

# Background worker for new logs
def log_processor_worker():
    """Background worker: Process new incoming logs with full enrichment pipeline"""
    parser = SSHLogParser()
    
    while True:
        try:
            log_data = raw_logs_queue.get(timeout=1)
            server_name = log_data['server_name']
            logs = log_data['logs']
            
            processed_count = 0
            for log_line in logs:
                event = parser.parse_line(log_line, server_name)
                if event:
                    # Full enrichment pipeline
                    # Step 1: Enrich with GeoIP
                    event = enrich_with_geoip(event)
                    
                    # Step 2: Check IP reputation
                    event['threat_reputation'] = check_ip_reputation(event.get('source_ip', ''))
                    
                    # Step 3: ML analysis
                    event = analyze_with_ml(event)
                    
                    # Step 4: Save to database
                    if save_event_to_database(event):
                        processed_count += 1
                        
                        # Step 5: Check for comprehensive alerts
                        check_and_send_alerts(event)
            
            if processed_count > 0:
                logger.info(f"✅ Processed {processed_count} new events from {server_name}")
            
            raw_logs_queue.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"❌ Processor error: {e}")

# Background worker for updating existing records
def enrichment_updater_worker():
    """Background worker: Update existing records missing GeoIP/threat data"""
    
    while True:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Find records missing GeoIP data (limit to avoid overload)
            cursor.execute("""
                SELECT id, source_ip, raw_event_data FROM failed_logins 
                WHERE geoip_processed = FALSE AND source_ip != 'unknown' 
                LIMIT 10
            """)
            failed_records = cursor.fetchall()
            
            cursor.execute("""
                SELECT id, source_ip, raw_event_data FROM successful_logins 
                WHERE geoip_processed = FALSE AND source_ip != 'unknown' 
                LIMIT 10
            """)
            success_records = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            # Update failed logins
            for record_id, source_ip, raw_data in failed_records:
                update_existing_record('failed_logins', record_id, source_ip)
            
            # Update successful logins  
            for record_id, source_ip, raw_data in success_records:
                update_existing_record('successful_logins', record_id, source_ip)
            
            if failed_records or success_records:
                logger.info(f"🔄 Updated {len(failed_records + success_records)} existing records with enrichment data")
            
            time.sleep(30)  # Check every 30 seconds
            
        except Exception as e:
            logger.error(f"❌ Enrichment updater error: {e}")
            time.sleep(60)

def update_existing_record(table_name: str, record_id: int, source_ip: str):
    """Update a single existing record with GeoIP, threat data, and ML analysis"""
    try:
        # Create a mock event for enrichment
        mock_event = {'source_ip': source_ip, 'timestamp': datetime.now().isoformat(), 'event_type': 'failed_password', 'port': 22}
        
        # Full enrichment pipeline
        mock_event = enrich_with_geoip(mock_event)
        mock_event['threat_reputation'] = check_ip_reputation(source_ip)
        mock_event = analyze_with_ml(mock_event)
        
        # Extract data
        geoip = mock_event.get('geoip', {})
        threat_rep = mock_event.get('threat_reputation', {})
        ml_analysis = mock_event.get('ml_analysis', {})
        
        # Update database
        conn = get_connection()
        cursor = conn.cursor()
        
        query = f"""
            UPDATE {table_name} SET 
                country = %s, city = %s, latitude = %s, longitude = %s, timezone = %s, geoip_processed = TRUE,
                ip_risk_score = %s, ip_reputation = %s, threat_intel_data = %s, ip_health_processed = TRUE,
                ml_risk_score = %s, ml_threat_type = %s, ml_confidence = %s, is_anomaly = %s, ml_processed = TRUE
            WHERE id = %s
        """
        
        values = (
            geoip.get('country', None),
            geoip.get('city', None), 
            geoip.get('latitude', None),
            geoip.get('longitude', None),
            geoip.get('timezone', None),
            threat_rep.get('risk_score', 0),
            'malicious' if threat_rep.get('is_malicious') else 'clean',
            json.dumps(threat_rep.get('detailed_threats', [])),
            ml_analysis.get('ml_risk_score', 25),
            ml_analysis.get('ml_threat_type', 'Normal Activity'),
            ml_analysis.get('ml_confidence', 0.250),
            ml_analysis.get('is_anomaly', False),
            record_id
        )
        
        cursor.execute(query, values)
        conn.commit()
        cursor.close()
        conn.close()
        
    except Exception as e:
        logger.error(f"❌ Failed to update record {record_id}: {e}")

# Analytics update worker
def analytics_worker():
    """Background worker: Update analytics cache periodically"""
    
    while True:
        try:
            update_analytics_cache()
            logger.info("📊 Analytics cache updated")
            time.sleep(300)  # Update every 5 minutes
        except Exception as e:
            logger.error(f"❌ Analytics worker error: {e}")
            time.sleep(60)

# Flask API
app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy", 
        "service": "ssh_guardian_realtime_comprehensive",
        "threat_feeds_loaded": len(threat_feeds_cache),
        "last_threat_update": threat_feeds_last_update.isoformat() if threat_feeds_last_update else None,
        "analytics_updated": analytics_cache.get('last_updated')
    }), 200

@app.route('/logs/upload', methods=['POST'])
def receive_logs():
    try:
        data = request.get_json()
        if not data or 'server_name' not in data or 'logs' not in data:
            return jsonify({"error": "Missing server_name or logs"}), 400
        
        server_name = data['server_name']
        logs = data['logs']
        
        if not isinstance(logs, list):
            return jsonify({"error": "logs must be an array"}), 400
        
        log_data = {
            'server_name': server_name,
            'logs': logs,
            'received_at': datetime.now().isoformat()
        }
        
        try:
            raw_logs_queue.put_nowait(log_data)
        except queue.Full:
            return jsonify({"error": "Queue full"}), 503
        
        return jsonify({
            "status": "success",
            "server_name": server_name,
            "logs_received": len(logs),
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logs/status', methods=['GET'])
def get_status():
    files = {}
    if config.RECEIVING_DIR.exists():
        for filename in os.listdir(config.RECEIVING_DIR):
            if filename.startswith('authlog_'):
                filepath = config.RECEIVING_DIR / filename
                size = filepath.stat().st_size
                files[filename] = {"size_bytes": size, "size_kb": round(size / 1024, 2)}
    
    return jsonify({
        "active_streams": len(files),
        "files": files,
        "queue_size": raw_logs_queue.qsize(),
        "threat_feeds": {
            "loaded": len(threat_feeds_cache),
            "feeds": list(threat_feeds_cache.keys()),
            "last_update": threat_feeds_last_update.isoformat() if threat_feeds_last_update else None
        }
    }), 200

@app.route('/threat/check/<ip>', methods=['GET'])
def check_single_ip(ip):
    """Check single IP against threat feeds"""
    try:
        reputation = check_ip_reputation(ip)
        return jsonify({
            "ip": ip,
            "reputation": reputation,
            "timestamp": datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/stats/enrichment', methods=['GET'])
def get_enrichment_stats():
    """Get statistics about enrichment processing"""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Count records by processing status
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN geoip_processed = TRUE THEN 1 ELSE 0 END) as geoip_done,
                SUM(CASE WHEN ip_health_processed = TRUE THEN 1 ELSE 0 END) as threat_done,
                SUM(CASE WHEN country IS NOT NULL THEN 1 ELSE 0 END) as has_country
            FROM failed_logins
        """)
        failed_stats = cursor.fetchone()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN geoip_processed = TRUE THEN 1 ELSE 0 END) as geoip_done,
                SUM(CASE WHEN ip_health_processed = TRUE THEN 1 ELSE 0 END) as threat_done,
                SUM(CASE WHEN country IS NOT NULL THEN 1 ELSE 0 END) as has_country
            FROM successful_logins
        """)
        success_stats = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "failed_logins": {
                "total": failed_stats[0],
                "geoip_processed": failed_stats[1],
                "threat_processed": failed_stats[2],
                "has_location": failed_stats[3]
            },
            "successful_logins": {
                "total": success_stats[0],
                "geoip_processed": success_stats[1],
                "threat_processed": success_stats[2],
                "has_location": success_stats[3]
            },
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analytics/comprehensive', methods=['GET'])
def get_comprehensive_analytics():
    """Get comprehensive analytics and insights"""
    try:
        # Ensure analytics are fresh
        update_analytics_cache()
        
        # Add real-time insights
        conn = get_connection()
        cursor = conn.cursor()
        
        # Recent high-risk events
        cursor.execute("""
            SELECT source_ip, country, ml_risk_score, ml_threat_type, timestamp
            FROM (
                SELECT source_ip, country, ml_risk_score, ml_threat_type, timestamp
                FROM failed_logins WHERE ml_risk_score >= 60 AND timestamp >= NOW() - INTERVAL 1 HOUR
                UNION ALL
                SELECT source_ip, country, ml_risk_score, ml_threat_type, timestamp
                FROM successful_logins WHERE ml_risk_score >= 60 AND timestamp >= NOW() - INTERVAL 1 HOUR
            ) as combined
            ORDER BY ml_risk_score DESC, timestamp DESC
            LIMIT 10
        """)
        recent_threats = [
            {
                'ip': row[0], 'country': row[1], 'risk_score': row[2], 
                'threat_type': row[3], 'timestamp': row[4].isoformat()
            } 
            for row in cursor.fetchall()
        ]
        
        # Top attacking IPs
        cursor.execute("""
            SELECT source_ip, country, COUNT(*) as attempts, MAX(ml_risk_score) as max_risk
            FROM failed_logins 
            WHERE timestamp >= NOW() - INTERVAL 24 HOUR
            GROUP BY source_ip, country
            ORDER BY attempts DESC, max_risk DESC
            LIMIT 10
        """)
        top_attackers = [
            {'ip': row[0], 'country': row[1], 'attempts': row[2], 'max_risk': row[3]}
            for row in cursor.fetchall()
        ]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "analytics_cache": analytics_cache,
            "real_time_insights": {
                "recent_high_risk_events": recent_threats,
                "top_attacking_ips": top_attackers
            },
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/test/telegram', methods=['GET'])
def test_telegram():
    """Test Telegram notification"""
    test_message = "🧪 Test message from SSH Guardian 2.0"
    result = send_telegram_message(test_message)
    
    return jsonify({
        "telegram_configured": bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID),
        "bot_token": config.TELEGRAM_BOT_TOKEN[:10] + "..." if config.TELEGRAM_BOT_TOKEN else None,
        "chat_id": config.TELEGRAM_CHAT_ID,
        "message_sent": result
    }), 200

@app.route('/test/alert', methods=['POST'])
def test_alert():
    """Test comprehensive alert system"""
    try:
        # Create a test high-risk event
        test_event = {
            'timestamp': datetime.now().isoformat(),
            'server_hostname': 'test-server',
            'event_type': 'failed_password',
            'source_ip': '203.0.113.42',
            'username': 'admin',
            'port': 22,
            'geoip': {
                'country': 'Test Country',
                'city': 'Test City',
                'timezone': 'UTC'
            },
            'threat_reputation': {
                'is_malicious': False,
                'detailed_threats': ['Test Threat Feed'],
                'risk_score': 30
            },
            'ml_analysis': {
                'ml_risk_score': 75,  # High risk to trigger alert
                'ml_threat_type': 'Suspicious Activity',
                'ml_confidence': 0.850,
                'is_anomaly': True
            }
        }
        
        # Send test alert
        check_and_send_alerts(test_event)
        
        return jsonify({
            "test_alert_sent": True,
            "test_event": test_event,
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Initialize and start
def start_background_workers():
    # Main processor for new logs
    processor_thread = threading.Thread(target=log_processor_worker, daemon=True)
    processor_thread.start()
    
    # Enrichment updater for existing records
    updater_thread = threading.Thread(target=enrichment_updater_worker, daemon=True)
    updater_thread.start()
    
    # Analytics updater
    analytics_thread = threading.Thread(target=analytics_worker, daemon=True)
    analytics_thread.start()
    
    logger.info("🚀 Started background workers (processor + enrichment updater + analytics)")

if __name__ == '__main__':
    print("🛡️  SSH Guardian 2.0 - Comprehensive Real-Time Security System")
    print("=" * 80)
    print("Features:")
    print("✅ Real-time log processing with full enrichment pipeline")
    print("✅ GeoIP location data with timezone support")
    print("✅ Threat intelligence with daily updates")
    print("✅ ML-powered risk analysis and anomaly detection")
    print("✅ Comprehensive Telegram alerts with analytics")
    print("✅ Rich analytics and insights dashboard")
    print("✅ Background processing for existing records")
    print("=" * 80)
    print(f"🌐 Starting API server on {config.LOG_RECEIVER_HOST}:{config.LOG_RECEIVER_PORT}")
    print("📡 Endpoints:")
    print("   - POST /logs/upload          - Receive SSH logs")
    print("   - GET  /logs/status          - Processing status")
    print("   - GET  /health               - System health")
    print("   - GET  /analytics/comprehensive - Full analytics")
    print("   - GET  /test/telegram        - Test Telegram")
    print("   - POST /test/alert           - Test alert system")
    print("=" * 80)
    
    # Test database
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        print("✅ Database connection successful")
    except Exception as e:
        print(f"❌ Database error: {e}")
        sys.exit(1)
    
    # Load threat feeds on startup
    print("🔍 Loading threat intelligence...")
    update_threat_feeds()
    print(f"✅ Loaded {len(threat_feeds_cache)} threat feeds")
    
    # Initialize analytics cache
    print("📊 Initializing analytics...")
    update_analytics_cache()
    print("✅ Analytics cache initialized")
    
    # Start background workers
    start_background_workers()
    
    print("🚀 System ready - processing logs with comprehensive alerts & analytics")
    print("=" * 80)
    
    app.run(
        host=config.LOG_RECEIVER_HOST,
        port=config.LOG_RECEIVER_PORT,
        debug=False,
        threaded=True
    )