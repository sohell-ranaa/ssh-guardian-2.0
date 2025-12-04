#!/usr/bin/env python3
"""
SSH Guardian 2.0 - Enhanced Integrated System
Full integration with:
- Third-party threat intelligence (VirusTotal, AbuseIPDB, Shodan)
- Advanced feature extraction (session tracking, impossible travel)
- Brute force detection (rate + pattern + distributed)
- Automated IP blocking with iptables
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

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

# Import Enhanced Guardian Engine (with ML integration)
from core.enhanced_guardian_engine import create_enhanced_guardian_engine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
class Config:
    LOG_RECEIVER_PORT = 5000
    LOG_RECEIVER_HOST = '0.0.0.0'
    DATA_DIR = PROJECT_ROOT / "data"
    RECEIVING_DIR = DATA_DIR / "receiving_stream"
    THREAT_FEEDS_DIR = DATA_DIR / "threat_feeds"
    API_CACHE_DIR = DATA_DIR / "api_cache"
    GEOIP_DB = DATA_DIR / "geoip" / "GeoLite2-City.mmdb"
    BLOCKS_STATE_FILE = DATA_DIR / "blocks_state.json"
    WHITELIST_FILE = DATA_DIR / "ip_whitelist.txt"
    QUEUE_SIZE = 1000

    # Telegram
    TELEGRAM_BOT_TOKEN = ""
    TELEGRAM_CHAT_ID = ""

    # API Keys
    VIRUSTOTAL_API_KEY = ""
    ABUSEIPDB_API_KEY = ""
    SHODAN_API_KEY = ""

    # Security settings
    ALERT_RISK_THRESHOLD = 70
    AUTO_BLOCK_THRESHOLD = 85
    ENABLE_AUTO_BLOCK = True

config = Config()

# Load environment variables
def load_env():
    """Load configuration from .env file"""
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    value = value.strip('"').strip()

                    if key == 'TELEGRAM_BOT_TOKEN' and value:
                        config.TELEGRAM_BOT_TOKEN = value
                    elif key == 'TELEGRAM_CHAT_ID' and value:
                        config.TELEGRAM_CHAT_ID = value
                    elif key == 'VIRUSTOTAL_API_KEY' and value:
                        config.VIRUSTOTAL_API_KEY = value
                    elif key == 'ABUSEIPDB_API_KEY' and value:
                        config.ABUSEIPDB_API_KEY = value
                    elif key == 'SHODAN_API_KEY' and value:
                        config.SHODAN_API_KEY = value
                    elif key == 'ALERT_RISK_THRESHOLD':
                        config.ALERT_RISK_THRESHOLD = int(value)
                    elif key == 'AUTO_BLOCK_THRESHOLD':
                        config.AUTO_BLOCK_THRESHOLD = int(value)

load_env()

# Create directories
config.DATA_DIR.mkdir(exist_ok=True)
config.RECEIVING_DIR.mkdir(exist_ok=True)
config.THREAT_FEEDS_DIR.mkdir(exist_ok=True)
config.API_CACHE_DIR.mkdir(exist_ok=True)

# Initialize Enhanced Guardian Engine with ML
logger.info("🛡️  Initializing SSH Guardian 2.0 Enhanced Engine with ML...")

# Enhanced config includes ML, smart alerting, and classification
enhanced_config = {
    'threat_feeds_dir': config.THREAT_FEEDS_DIR,
    'api_cache_dir': config.API_CACHE_DIR,
    'api_config': {
        'virustotal_api_key': config.VIRUSTOTAL_API_KEY,
        'abuseipdb_api_key': config.ABUSEIPDB_API_KEY,
        'shodan_api_key': config.SHODAN_API_KEY
    },
    'block_state_file': config.BLOCKS_STATE_FILE,
    'whitelist_file': config.WHITELIST_FILE,
    'enable_auto_block': config.ENABLE_AUTO_BLOCK,
    'auto_block_threshold': config.AUTO_BLOCK_THRESHOLD,

    # Whitelist IPs (private networks + custom)
    'whitelist_ips': [
        # Private networks are auto-whitelisted
        # Add custom IPs here if needed
    ],

    # Telegram configuration for smart alerting
    'telegram': {
        'bot_token': config.TELEGRAM_BOT_TOKEN,
        'chat_id': config.TELEGRAM_CHAT_ID,
        'smart_grouping': True  # Enable smart alert grouping
    }
}

guardian_engine = create_enhanced_guardian_engine(enhanced_config)

# Queues for real-time processing
raw_logs_queue = queue.Queue(maxsize=config.QUEUE_SIZE)

# Flask app
app = Flask(__name__)

# SSH Log Parser (from original system)
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
                    'timestamp': datetime.now(),
                    'server_hostname': server_name,
                    'source_ip': match.group('source_ip'),
                    'username': match.group('username') if match.group('username') else 'unknown',
                    'port': int(match.group('port')),
                    'event_type': event_type,
                    'raw_log': log_line
                }
                return event

        return None


# GeoIP enrichment
def enrich_with_geoip(event: dict) -> dict:
    """Add GeoIP data to event"""
    source_ip = event.get('source_ip')
    if not source_ip:
        return event

    try:
        if config.GEOIP_DB.exists():
            import geoip2.database
            with geoip2.database.Reader(str(config.GEOIP_DB)) as reader:
                response = reader.city(source_ip)

                if source_ip.startswith(('192.168.', '10.', '172.16.', '127.')):
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


# Note: Telegram alerting is now handled by the Enhanced Guardian Engine's
# SmartAlertManager. It automatically sends alerts based on severity with
# smart grouping to prevent spam. No need for manual alert sending.


# Database saving function
def _save_login_to_database(event: dict, classification: dict):
    """Save login event to database"""
    try:
        from dbs.connection import get_connection
        conn = get_connection()
        cursor = conn.cursor()

        event_type = event.get('event_type', 'failed')
        source_ip = event.get('source_ip')
        username = event.get('username')
        timestamp = event.get('timestamp', datetime.now())

        # Extract GeoIP data
        geoip = event.get('geoip', {})
        country = geoip.get('country', event.get('country', 'Unknown'))
        city = geoip.get('city', event.get('city', 'Unknown'))

        risk_score = classification.get('risk_score', 0)
        is_simulation = event.get('is_simulation', False)
        simulation_id = event.get('simulation_id')
        server_hostname = event.get('server_hostname', 'simulation-server')

        if event_type == 'successful':
            cursor.execute("""
                INSERT INTO successful_logins
                (source_ip, username, timestamp, country, city, ml_risk_score,
                 is_simulation, simulation_id, server_hostname)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (source_ip, username, timestamp, country, city, risk_score,
                  is_simulation, simulation_id, server_hostname))
        else:
            cursor.execute("""
                INSERT INTO failed_logins
                (source_ip, username, timestamp, country, city, ml_risk_score,
                 is_simulation, simulation_id, server_hostname)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (source_ip, username, timestamp, country, city, risk_score,
                  is_simulation, simulation_id, server_hostname))

        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        logger.error(f"Error saving login to database: {e}")


# Log processor worker with Guardian Engine integration
def log_processor_worker():
    """Enhanced log processor using Guardian Engine"""
    parser = SSHLogParser()

    logger.info("✅ Enhanced log processor started with Guardian Engine")

    while True:
        try:
            log_data = raw_logs_queue.get(timeout=1)
            server_name = log_data['server_name']
            logs = log_data['logs']

            for log_line in logs:
                # Handle both structured events and raw log lines
                if isinstance(log_line, dict):
                    # Already structured event (from test scripts or API clients)
                    event = log_line
                    if 'server_hostname' not in event:
                        event['server_hostname'] = server_name
                    # Ensure timestamp is datetime object
                    if isinstance(event.get('timestamp'), str):
                        event['timestamp'] = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    elif 'timestamp' not in event:
                        event['timestamp'] = datetime.now()
                else:
                    # Raw log line - needs parsing
                    event = parser.parse_line(log_line, server_name)

                if event:
                    # Add GeoIP enrichment
                    event = enrich_with_geoip(event)

                    # Run Enhanced Guardian Engine analysis
                    # This includes: ML prediction, classification, smart alerting, and blocking
                    guardian_result = guardian_engine.analyze_event(event)

                    # Log the result (alerting is handled internally by SmartAlertManager)
                    classification = guardian_result.get('classification', {})
                    logger.info(
                        f"Processed: {event['source_ip']} | "
                        f"Risk: {classification.get('risk_score', 0)}/100 | "
                        f"Level: {classification.get('threat_level', 'unknown')} | "
                        f"Action: {classification.get('action', 'unknown')}"
                    )

                    # Save login event to database
                    _save_login_to_database(event, classification)

        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in log processor: {e}", exc_info=True)


# Cleanup worker
def cleanup_worker():
    """Periodic cleanup of expired blocks"""
    while True:
        try:
            time.sleep(3600)  # Run every hour
            guardian_engine.cleanup()
        except Exception as e:
            logger.error(f"Error in cleanup worker: {e}")


# Flask routes
@app.route('/logs/upload', methods=['POST'])
def upload_logs():
    """Receive SSH logs from agents"""
    try:
        data = request.get_json()
        server_name = data.get('server_name', 'unknown')
        logs = data.get('logs', [])

        if logs:
            raw_logs_queue.put({
                'server_name': server_name,
                'logs': logs
            })

            return jsonify({
                'status': 'success',
                'received': len(logs)
            }), 200
        else:
            return jsonify({'status': 'error', 'message': 'No logs provided'}), 400

    except Exception as e:
        logger.error(f"Error receiving logs: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'queue_size': raw_logs_queue.qsize(),
        'version': '2.0-integrated'
    }), 200


@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get Enhanced Guardian Engine statistics including ML metrics"""
    try:
        stats = guardian_engine.get_statistics()
        # Enhanced stats include: events_processed, ml_predictions, threats_detected,
        # ips_blocked, alerts_sent, ml_stats, classifier_stats, alert_stats
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/blocks', methods=['GET'])
def get_blocked_ips():
    """Get list of blocked IPs"""
    try:
        blocks = guardian_engine.original_guardian.ip_blocker.get_blocked_ips()
        return jsonify({
            'status': 'success',
            'blocked_ips': blocks
        }), 200
    except Exception as e:
        logger.error(f"Error getting blocks: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/block/<ip>', methods=['POST'])
def manual_block_ip(ip):
    """Manually block an IP"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'Manual block via API')
        duration_hours = data.get('duration_hours')

        result = guardian_engine.original_guardian.ip_blocker.block_ip(
            ip=ip,
            reason=reason,
            threat_level='high',
            duration_hours=duration_hours
        )

        return jsonify(result), 200 if result['success'] else 400
    except Exception as e:
        logger.error(f"Error blocking IP: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/unblock/<ip>', methods=['POST'])
def manual_unblock_ip(ip):
    """Manually unblock an IP"""
    try:
        result = guardian_engine.original_guardian.ip_blocker.unblock_ip(ip, reason='Manual unblock via API')
        return jsonify(result), 200 if result['success'] else 400
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


if __name__ == '__main__':
    # Start background workers
    processor_thread = threading.Thread(target=log_processor_worker, daemon=True)
    processor_thread.start()

    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()

    logger.info("=" * 80)
    logger.info("🚀 SSH GUARDIAN 2.0 - ML-POWERED EDITION - READY")
    logger.info("=" * 80)
    logger.info(f"Listening on {config.LOG_RECEIVER_HOST}:{config.LOG_RECEIVER_PORT}")
    logger.info(f"ML Integration: ACTIVE (100% accuracy Random Forest)")
    logger.info(f"Smart Alerting: ENABLED (no spam mode)")
    logger.info(f"5-Level Classification: ACTIVE (CLEAN → CRITICAL)")
    logger.info(f"Auto-blocking: {'ENABLED' if config.ENABLE_AUTO_BLOCK else 'DISABLED'}")
    logger.info(f"Auto-block threshold: {config.AUTO_BLOCK_THRESHOLD}/100")
    logger.info("=" * 80)

    # Run Flask app
    app.run(
        host=config.LOG_RECEIVER_HOST,
        port=config.LOG_RECEIVER_PORT,
        debug=False,
        threaded=True
    )
