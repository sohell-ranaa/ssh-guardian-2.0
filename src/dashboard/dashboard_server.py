"""
SSH Guardian 2.0 - Web Dashboard Server
Real-time monitoring and management interface with Authentication
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import sys
import secrets
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(Path(__file__).parent))  # Add dashboard dir for auth modules

from dotenv import load_dotenv

# Load environment variables FIRST before importing auth modules
load_dotenv()

from connection import get_connection
import requests

# Import authentication modules AFTER loading .env
from auth import login_required, permission_required, SessionManager
from auth_routes import auth_bp
from multi_agent_api import multi_agent_bp

# Import simulation modules
sys.path.append(str(PROJECT_ROOT / "src"))
from simulation import AttackSimulator, ATTACK_TEMPLATES
from simulation.ip_pools import get_pool_manager
import json as json_module
import threading

# Import ML analytics
from ml.analytics.ml_effectiveness_tracker import MLEffectivenessTracker

# Import IP intelligence (lazy loading)
_ip_enrichment_service = None

def get_ip_enrichment_service():
    """Get or create IP enrichment service instance"""
    global _ip_enrichment_service
    if _ip_enrichment_service is None:
        from intelligence.ip_enrichment_service import IPEnrichmentService

        # Get API keys from environment
        virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        shodan_key = os.getenv('SHODAN_API_KEY')
        abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')

        # Create service
        cache_dir = PROJECT_ROOT / 'cache' / 'ip_intelligence'
        _ip_enrichment_service = IPEnrichmentService(
            virustotal_api_key=virustotal_key,
            shodan_api_key=shodan_key,
            abuseipdb_api_key=abuseipdb_key,
            cache_dir=cache_dir
        )

    return _ip_enrichment_service

app = Flask(__name__,
           template_folder='templates',
           static_folder='static')

# Secret key for session management
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

CORS(app, supports_credentials=True)

# Register authentication blueprint
app.register_blueprint(auth_bp)

# Register multi-agent blueprint
app.register_blueprint(multi_agent_bp)

# Guardian API endpoint
GUARDIAN_API = os.getenv('GUARDIAN_API_URL', 'http://localhost:5000')

@app.route('/login')
def login_page():
    """Login page"""
    # Check if already authenticated
    session_token = request.cookies.get('session_token')
    if session_token and SessionManager.validate_session(session_token):
        return redirect('/')
    return render_template('login.html')

@app.route('/')
def index():
    """Main dashboard page - requires authentication"""
    # Check authentication
    session_token = request.cookies.get('session_token')
    if not session_token or not SessionManager.validate_session(session_token):
        return redirect('/login')
    return render_template('enhanced_dashboard.html')

@app.route('/classic')
def classic_dashboard():
    """Original dashboard page - requires authentication"""
    session_token = request.cookies.get('session_token')
    if not session_token or not SessionManager.validate_session(session_token):
        return redirect('/login')
    return render_template('dashboard.html')

@app.route('/enhanced')
def enhanced_dashboard():
    """Enhanced dashboard with advanced controls - requires authentication"""
    session_token = request.cookies.get('session_token')
    if not session_token or not SessionManager.validate_session(session_token):
        return redirect('/login')
    return render_template('enhanced_dashboard.html')

@app.route('/api/stats/overview')
@login_required
def get_overview_stats():
    """Get high-level overview statistics"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Time ranges
        now = datetime.now()
        last_hour = now - timedelta(hours=1)
        last_24h = now - timedelta(hours=24)

        stats = {}

        # Total events (failed + successful)
        cursor.execute("SELECT COUNT(*) as count FROM failed_logins")
        failed_total = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM successful_logins")
        successful_total = cursor.fetchone()['count']

        stats['total_events'] = failed_total + successful_total

        # Events last 24h
        cursor.execute("""
            SELECT COUNT(*) as count FROM failed_logins
            WHERE timestamp >= %s
        """, (last_24h,))
        failed_24h = cursor.fetchone()['count']

        cursor.execute("""
            SELECT COUNT(*) as count FROM successful_logins
            WHERE timestamp >= %s
        """, (last_24h,))
        successful_24h = cursor.fetchone()['count']

        stats['events_24h'] = failed_24h + successful_24h
        stats['failed_24h'] = failed_24h
        stats['successful_24h'] = successful_24h

        # Events last hour
        cursor.execute("""
            SELECT COUNT(*) as count FROM failed_logins
            WHERE timestamp >= %s
        """, (last_hour,))
        failed_1h = cursor.fetchone()['count']

        cursor.execute("""
            SELECT COUNT(*) as count FROM successful_logins
            WHERE timestamp >= %s
        """, (last_hour,))
        successful_1h = cursor.fetchone()['count']

        stats['events_1h'] = failed_1h + successful_1h

        # Unique IPs (24h)
        cursor.execute("""
            SELECT COUNT(DISTINCT source_ip) as count FROM (
                SELECT source_ip FROM failed_logins WHERE timestamp >= %s
                UNION
                SELECT source_ip FROM successful_logins WHERE timestamp >= %s
            ) AS combined_ips
        """, (last_24h, last_24h))
        stats['unique_ips_24h'] = cursor.fetchone()['count']

        # Anomalies (24h)
        cursor.execute("""
            SELECT COUNT(*) as count FROM (
                SELECT id FROM failed_logins WHERE is_anomaly = 1 AND timestamp >= %s
                UNION ALL
                SELECT id FROM successful_logins WHERE is_anomaly = 1 AND timestamp >= %s
            ) AS combined_anomalies
        """, (last_24h, last_24h))
        stats['anomalies_24h'] = cursor.fetchone()['count']

        # High risk events (24h) - using ml_risk_score
        cursor.execute("""
            SELECT COUNT(*) as count FROM (
                SELECT id FROM failed_logins WHERE ml_risk_score >= 70 AND timestamp >= %s
                UNION ALL
                SELECT id FROM successful_logins WHERE ml_risk_score >= 70 AND timestamp >= %s
            ) AS high_risk
        """, (last_24h, last_24h))
        stats['high_risk_24h'] = cursor.fetchone()['count']

        # Threat types distribution (24h)
        cursor.execute("""
            SELECT ml_threat_type as threat_type, COUNT(*) as count FROM (
                SELECT ml_threat_type FROM failed_logins
                WHERE ml_threat_type IS NOT NULL AND timestamp >= %s
                UNION ALL
                SELECT ml_threat_type FROM successful_logins
                WHERE ml_threat_type IS NOT NULL AND timestamp >= %s
            ) AS combined_threats
            GROUP BY ml_threat_type
        """, (last_24h, last_24h))
        stats['attack_types'] = {row['threat_type']: row['count'] for row in cursor.fetchall()}

        # Get Guardian API stats
        try:
            response = requests.get(f"{GUARDIAN_API}/statistics", timeout=2)
            if response.status_code == 200:
                stats['guardian_stats'] = response.json()
        except:
            stats['guardian_stats'] = {}

        cursor.close()
        conn.close()

        return jsonify(stats)

    except Exception as e:
        print(f"Error in get_overview_stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats/timeline')
@login_required
def get_timeline_stats():
    """Get timeline data for charts"""
    try:
        hours = int(request.args.get('hours', 24))
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        start_time = datetime.now() - timedelta(hours=hours)

        # Events per hour - need to combine both tables
        cursor.execute("""
            SELECT
                DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00') as hour,
                COUNT(*) as failed,
                0 as successful,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                AVG(ml_risk_score) as avg_risk
            FROM failed_logins
            WHERE timestamp >= %s
            GROUP BY hour
        """, (start_time,))
        failed_data = {row['hour']: row for row in cursor.fetchall()}

        cursor.execute("""
            SELECT
                DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00') as hour,
                0 as failed,
                COUNT(*) as successful,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                AVG(ml_risk_score) as avg_risk
            FROM successful_logins
            WHERE timestamp >= %s
            GROUP BY hour
        """, (start_time,))

        # Merge data
        timeline = {}
        for row in cursor.fetchall():
            hour = row['hour']
            if hour in timeline:
                timeline[hour]['successful'] = row['successful']
                timeline[hour]['anomalies'] += row['anomalies']
            else:
                timeline[hour] = row

        # Add failed data
        for hour, data in failed_data.items():
            if hour in timeline:
                timeline[hour]['failed'] = data['failed']
                timeline[hour]['anomalies'] += data['anomalies']
            else:
                timeline[hour] = data

        # Calculate totals and convert to list
        result = []
        for hour in sorted(timeline.keys()):
            data = timeline[hour]
            data['total'] = data['failed'] + data['successful']
            result.append(data)

        cursor.close()
        conn.close()

        return jsonify(result)

    except Exception as e:
        print(f"Error in get_timeline_stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/recent')
@login_required
def get_recent_threats():
    """Get recent high-risk threats"""
    try:
        limit = int(request.args.get('limit', 50))
        agent_id = request.args.get('agent_id', 'all')
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build WHERE clause for agent filtering
        agent_filter = ""
        query_params = []

        if agent_id != 'all':
            agent_filter = "AND server_hostname = %s"
            query_params.append(agent_id)

        # Get high-risk events from both tables
        query = f"""
            SELECT
                id, timestamp, source_ip as ip, username,
                'failed' as event_type, country, city,
                ml_risk_score, is_anomaly, ml_threat_type as threat_type,
                server_hostname as agent_id
            FROM failed_logins
            WHERE ml_risk_score >= 50 {agent_filter}
            UNION ALL
            SELECT
                id, timestamp, source_ip as ip, username,
                'successful' as event_type, country, city,
                ml_risk_score, is_anomaly, ml_threat_type as threat_type,
                server_hostname as agent_id
            FROM successful_logins
            WHERE ml_risk_score >= 50 {agent_filter}
            ORDER BY timestamp DESC
            LIMIT %s
        """

        # Add limit to params for both UNION parts
        if agent_id != 'all':
            cursor.execute(query, (query_params[0], query_params[0], limit))
        else:
            cursor.execute(query, (limit,))

        threats = cursor.fetchall()

        # Convert datetime to string and add risk field
        for threat in threats:
            if threat['timestamp']:
                threat['timestamp'] = threat['timestamp'].isoformat()
            # Add 'risk' field for compatibility (alias for ml_risk_score)
            threat['risk'] = threat.get('ml_risk_score', 0)

        cursor.close()
        conn.close()

        return jsonify({'threats': threats, 'count': len(threats)})

    except Exception as e:
        print(f"Error in get_recent_threats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/geographic')
@login_required
def get_geographic_threats():
    """Get geographic distribution of threats"""
    try:
        hours = int(request.args.get('hours', 24))
        start_time = datetime.now() - timedelta(hours=hours)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Country distribution
        cursor.execute("""
            SELECT
                country,
                COUNT(*) as count,
                AVG(ml_risk_score) as avg_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM (
                SELECT country, ml_risk_score, is_anomaly
                FROM failed_logins WHERE timestamp >= %s AND country IS NOT NULL
                UNION ALL
                SELECT country, ml_risk_score, is_anomaly
                FROM successful_logins WHERE timestamp >= %s AND country IS NOT NULL
            ) AS combined
            GROUP BY country
            ORDER BY count DESC
            LIMIT 20
        """, (start_time, start_time))

        countries = cursor.fetchall()

        # City distribution with coordinates
        cursor.execute("""
            SELECT
                city, country, latitude, longitude,
                COUNT(*) as count,
                AVG(ml_risk_score) as avg_risk
            FROM (
                SELECT city, country, latitude, longitude, ml_risk_score
                FROM failed_logins
                WHERE timestamp >= %s AND city IS NOT NULL AND latitude IS NOT NULL
                UNION ALL
                SELECT city, country, latitude, longitude, ml_risk_score
                FROM successful_logins
                WHERE timestamp >= %s AND city IS NOT NULL AND latitude IS NOT NULL
            ) AS combined
            GROUP BY city, country, latitude, longitude
            ORDER BY count DESC
            LIMIT 50
        """, (start_time, start_time))

        cities = cursor.fetchall()

        # Convert Decimal to float for JSON serialization
        for city in cities:
            if city['latitude']:
                city['latitude'] = float(city['latitude'])
            if city['longitude']:
                city['longitude'] = float(city['longitude'])

        cursor.close()
        conn.close()

        return jsonify({
            'countries': countries,
            'cities': cities
        })

    except Exception as e:
        print(f"Error in get_geographic_threats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/top-ips')
@login_required
def get_top_malicious_ips():
    """Get top malicious IPs"""
    try:
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 20))
        start_time = datetime.now() - timedelta(hours=hours)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                source_ip as ip,
                country,
                COUNT(*) as attempts,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_attempts,
                COUNT(DISTINCT username) as unique_usernames,
                AVG(ml_risk_score) as avg_risk,
                MAX(ml_risk_score) as max_risk,
                MAX(timestamp) as last_seen
            FROM (
                SELECT source_ip, country, 'failed' as event_type, username, ml_risk_score, timestamp
                FROM failed_logins WHERE timestamp >= %s
                UNION ALL
                SELECT source_ip, country, 'successful' as event_type, username, ml_risk_score, timestamp
                FROM successful_logins WHERE timestamp >= %s
            ) AS combined
            GROUP BY source_ip, country
            ORDER BY attempts DESC
            LIMIT %s
        """, (start_time, start_time, limit))

        ips = cursor.fetchall()

        # Convert datetime to string
        for ip in ips:
            if ip['last_seen']:
                ip['last_seen'] = ip['last_seen'].isoformat()

        cursor.close()
        conn.close()

        return jsonify(ips)

    except Exception as e:
        print(f"Error in get_top_malicious_ips: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/usernames')
@login_required
def get_targeted_usernames():
    """Get most targeted usernames"""
    try:
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 20))
        start_time = datetime.now() - timedelta(hours=hours)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                username,
                COUNT(*) as attempts,
                COUNT(DISTINCT source_ip) as unique_ips,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful,
                AVG(ml_risk_score) as avg_risk
            FROM (
                SELECT username, source_ip, 'failed' as event_type, ml_risk_score
                FROM failed_logins WHERE timestamp >= %s AND username IS NOT NULL
                UNION ALL
                SELECT username, source_ip, 'successful' as event_type, ml_risk_score
                FROM successful_logins WHERE timestamp >= %s AND username IS NOT NULL
            ) AS combined
            GROUP BY username
            ORDER BY attempts DESC
            LIMIT %s
        """, (start_time, start_time, limit))

        usernames = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify(usernames)

    except Exception as e:
        print(f"Error in get_targeted_usernames: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/blocks/active')
@login_required
def get_active_blocks():
    """Get currently blocked IPs"""
    try:
        response = requests.get(f"{GUARDIAN_API}/blocks", timeout=2)
        if response.status_code == 200:
            return jsonify(response.json())
        return jsonify({'blocks': []})
    except Exception as e:
        return jsonify({'error': str(e), 'blocks': []}), 500

@app.route('/api/admin/block-ip', methods=['POST'])
@permission_required('manage_blocks')
def block_ip():
    """Manually block an IP"""
    try:
        data = request.json
        ip = data.get('ip')
        duration = data.get('duration', 24)  # hours

        response = requests.post(
            f"{GUARDIAN_API}/block/{ip}",
            json={'duration': duration},
            timeout=2
        )

        return jsonify(response.json()), response.status_code

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/unblock-ip', methods=['POST'])
@permission_required('manage_blocks')
def unblock_ip():
    """Manually unblock an IP"""
    try:
        data = request.json
        ip = data.get('ip')

        response = requests.post(
            f"{GUARDIAN_API}/unblock/{ip}",
            timeout=2
        )

        return jsonify(response.json()), response.status_code

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/health')
@login_required
def get_system_health():
    """Get system health metrics"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        health = {}

        # Database size
        cursor.execute("""
            SELECT
                table_name,
                ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
            FROM information_schema.TABLES
            WHERE table_schema = 'ssh_guardian_20'
            AND table_name IN ('failed_logins', 'successful_logins')
        """)

        total_size = sum(row['size_mb'] for row in cursor.fetchall() if row['size_mb'])
        health['database_size_mb'] = total_size

        # Latest event timestamp
        cursor.execute("""
            SELECT MAX(latest) as latest FROM (
                SELECT MAX(timestamp) as latest FROM failed_logins
                UNION ALL
                SELECT MAX(timestamp) as latest FROM successful_logins
            ) AS combined
        """)

        result = cursor.fetchone()
        if result and result['latest']:
            health['latest_event'] = result['latest'].isoformat()
            health['seconds_since_last_event'] = (datetime.now() - result['latest']).total_seconds()
        else:
            health['latest_event'] = None
            health['seconds_since_last_event'] = None

        # Processing rate (last hour)
        last_hour = datetime.now() - timedelta(hours=1)
        cursor.execute("""
            SELECT COUNT(*) as count FROM (
                SELECT id FROM failed_logins WHERE timestamp >= %s
                UNION ALL
                SELECT id FROM successful_logins WHERE timestamp >= %s
            ) AS combined
        """, (last_hour, last_hour))

        health['events_last_hour'] = cursor.fetchone()['count']
        health['events_per_minute'] = health['events_last_hour'] / 60

        cursor.close()
        conn.close()

        # Get Guardian API health
        try:
            response = requests.get(f"{GUARDIAN_API}/health", timeout=2)
            if response.status_code == 200:
                health['guardian_status'] = 'online'
                health['guardian_api'] = response.json()
            else:
                health['guardian_status'] = 'degraded'
        except:
            health['guardian_status'] = 'offline'

        return jsonify(health)

    except Exception as e:
        print(f"Error in get_system_health: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/lookup/<ip>')
@login_required
def lookup_ip(ip):
    """Lookup detailed threat intelligence for an IP"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get events for this IP
        cursor.execute("""
            SELECT
                timestamp, source_ip, username, country, city,
                'failed' as event_type, ml_risk_score, ml_threat_type
            FROM failed_logins
            WHERE source_ip = %s
            UNION ALL
            SELECT
                timestamp, source_ip, username, country, city,
                'successful' as event_type, ml_risk_score, ml_threat_type
            FROM successful_logins
            WHERE source_ip = %s
            ORDER BY timestamp DESC
            LIMIT 100
        """, (ip, ip))

        events = cursor.fetchall()

        # Convert datetime to string
        for event in events:
            if event['timestamp']:
                event['timestamp'] = event['timestamp'].isoformat()

        # Get statistics
        cursor.execute("""
            SELECT
                COUNT(*) as total_attempts,
                COUNT(DISTINCT username) as unique_usernames,
                AVG(ml_risk_score) as avg_risk,
                MAX(ml_risk_score) as max_risk,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM (
                SELECT username, ml_risk_score, timestamp FROM failed_logins WHERE source_ip = %s
                UNION ALL
                SELECT username, ml_risk_score, timestamp FROM successful_logins WHERE source_ip = %s
            ) AS combined
        """, (ip, ip))

        stats = cursor.fetchone()
        if stats['first_seen']:
            stats['first_seen'] = stats['first_seen'].isoformat()
        if stats['last_seen']:
            stats['last_seen'] = stats['last_seen'].isoformat()

        cursor.close()
        conn.close()

        # Try to get threat intelligence from Guardian API
        threat_intel = {}
        try:
            response = requests.get(f"{GUARDIAN_API}/threat/check/{ip}", timeout=2)
            if response.status_code == 200:
                threat_intel = response.json()
        except:
            pass

        return jsonify({
            'ip': ip,
            'events': events,
            'statistics': stats,
            'threat_intelligence': threat_intel
        })

    except Exception as e:
        print(f"Error in lookup_ip: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/live')
@login_required
def get_live_events():
    """Get most recent events for live stream"""
    try:
        limit = int(request.args.get('limit', 20))
        since_id = request.args.get('since_id')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                id, timestamp, source_ip, username, country, city,
                'failed' as event_type, ml_risk_score, ml_threat_type, is_anomaly
            FROM failed_logins
        """

        params = []
        if since_id:
            query += " WHERE id > %s"
            params.append(since_id)

        query += """
            UNION ALL
            SELECT
                id, timestamp, source_ip, username, country, city,
                'successful' as event_type, ml_risk_score, ml_threat_type, is_anomaly
            FROM successful_logins
        """

        if since_id:
            query += " WHERE id > %s"
            params.append(since_id)

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params if params else (limit,))
        events = cursor.fetchall()

        # Convert datetime to string
        for event in events:
            if event['timestamp']:
                event['timestamp'] = event['timestamp'].isoformat()

        cursor.close()
        conn.close()

        return jsonify(events)

    except Exception as e:
        print(f"Error in get_live_events: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/whitelist', methods=['GET', 'POST', 'DELETE'])
@permission_required('manage_blocks')
def manage_whitelist():
    """Manage IP whitelist"""
    try:
        if request.method == 'GET':
            # Read whitelist
            whitelist_file = PROJECT_ROOT / 'data' / 'ip_whitelist.txt'
            if whitelist_file.exists():
                with open(whitelist_file, 'r') as f:
                    ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                return jsonify({'whitelist': ips})
            return jsonify({'whitelist': []})

        elif request.method == 'POST':
            # Add to whitelist
            data = request.json
            ip = data.get('ip')

            whitelist_file = PROJECT_ROOT / 'data' / 'ip_whitelist.txt'
            with open(whitelist_file, 'a') as f:
                f.write(f"{ip}\n")

            return jsonify({'success': True, 'message': f'Added {ip} to whitelist'})

        elif request.method == 'DELETE':
            # Remove from whitelist
            data = request.json
            ip = data.get('ip')

            whitelist_file = PROJECT_ROOT / 'data' / 'ip_whitelist.txt'
            if whitelist_file.exists():
                with open(whitelist_file, 'r') as f:
                    lines = f.readlines()

                with open(whitelist_file, 'w') as f:
                    for line in lines:
                        if line.strip() != ip:
                            f.write(line)

            return jsonify({'success': True, 'message': f'Removed {ip} from whitelist'})

    except Exception as e:
        print(f"Error in manage_whitelist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/clear-blocks', methods=['POST'])
@permission_required('manage_blocks')
def clear_all_blocks():
    """Clear all IP blocks"""
    try:
        # This would need to be implemented in the Guardian API
        response = requests.post(f"{GUARDIAN_API}/blocks/clear-all", timeout=2)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/test-alert', methods=['POST'])
@permission_required('manage_blocks')
def test_alert():
    """Send a test alert"""
    try:
        data = request.json
        message = data.get('message', 'Test alert from SSH Guardian Dashboard')

        # This would need to be implemented in the Guardian API
        response = requests.post(
            f"{GUARDIAN_API}/alert/test",
            json={'message': message},
            timeout=2
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/search/events')
@login_required
def search_events():
    """Search events with filters"""
    try:
        # Get search parameters
        ip = request.args.get('ip')
        username = request.args.get('username')
        country = request.args.get('country')
        min_risk = request.args.get('min_risk', type=int)
        event_type = request.args.get('event_type')
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 100, type=int)

        start_time = datetime.now() - timedelta(hours=hours)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build query dynamically
        conditions = ["timestamp >= %s"]
        params = [start_time]

        if ip:
            conditions.append("source_ip = %s")
            params.append(ip)

        if username:
            conditions.append("username LIKE %s")
            params.append(f"%{username}%")

        if country:
            conditions.append("country = %s")
            params.append(country)

        if min_risk:
            conditions.append("ml_risk_score >= %s")
            params.append(min_risk)

        where_clause = " AND ".join(conditions)

        # Query based on event type
        if event_type == 'failed' or not event_type:
            query_failed = f"""
                SELECT
                    id, timestamp, source_ip, username, country, city,
                    'failed' as event_type, ml_risk_score, ml_threat_type, is_anomaly
                FROM failed_logins
                WHERE {where_clause}
            """

        if event_type == 'successful' or not event_type:
            query_successful = f"""
                SELECT
                    id, timestamp, source_ip, username, country, city,
                    'successful' as event_type, ml_risk_score, ml_threat_type, is_anomaly
                FROM successful_logins
                WHERE {where_clause}
            """

        if event_type == 'failed':
            query = query_failed
        elif event_type == 'successful':
            query = query_successful
        else:
            query = f"{query_failed} UNION ALL {query_successful}"
            params = params * 2

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        events = cursor.fetchall()

        # Convert datetime to string
        for event in events:
            if event['timestamp']:
                event['timestamp'] = event['timestamp'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'events': events,
            'count': len(events),
            'filters': {
                'ip': ip,
                'username': username,
                'country': country,
                'min_risk': min_risk,
                'event_type': event_type,
                'hours': hours
            }
        })

    except Exception as e:
        print(f"Error in search_events: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# SIMULATION API ENDPOINTS
# ============================================================================

# Global storage for active simulations (for SSE streaming)
active_simulations = {}
simulation_locks = {}


@app.route('/api/simulation/templates')
@login_required
def get_simulation_templates():
    """Get all available attack templates"""
    try:
        templates = []
        for template_id, template_data in ATTACK_TEMPLATES.items():
            templates.append({
                'id': template_id,
                'name': template_data['name'],
                'description': template_data['description'],
                'category': template_data['category'],
                'severity': template_data['severity'],
                'icon': template_data['icon'],
                'template': template_data['template']
            })

        return jsonify({
            'success': True,
            'templates': templates,
            'count': len(templates)
        })

    except Exception as e:
        print(f"Error getting templates: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/template/<template_id>')
@login_required
def get_simulation_template(template_id):
    """Get a specific template with IP auto-filled"""
    try:
        if template_id not in ATTACK_TEMPLATES:
            return jsonify({'error': 'Template not found'}), 404

        template = ATTACK_TEMPLATES[template_id].copy()
        template_json = template['template'].copy()

        # Auto-fill IPs based on template type
        ip_param = template_json.get('source_ip', '')
        if ip_param.startswith('<from_pool:'):
            # Parse and populate with actual IP
            pool_manager = get_pool_manager()
            parts = ip_param.strip('<>').split(':')
            pool_type = parts[1]

            count = 1
            if len(parts) >= 4 and parts[2] == 'multiple':
                count = int(parts[3])

            ips = pool_manager.get_ips(pool_type, count)

            # Replace placeholder with actual IPs
            if count == 1:
                template_json['source_ip'] = ips[0]
            else:
                template_json['source_ip'] = ips

            template_json['_ip_pool_type'] = pool_type
            template_json['_ip_count'] = count

        return jsonify({
            'success': True,
            'template': template,
            'json': template_json
        })

    except Exception as e:
        print(f"Error getting template {template_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/ip-pool/<pool_type>')
@login_required
def get_ip_pool(pool_type):
    """Get IPs from a specific pool"""
    try:
        count = int(request.args.get('count', 10))
        pool_manager = get_pool_manager()

        if pool_type not in ['malicious', 'trusted', 'random']:
            return jsonify({'error': 'Invalid pool type'}), 400

        ips = pool_manager.get_ips(pool_type, count)

        return jsonify({
            'success': True,
            'pool_type': pool_type,
            'ips': ips,
            'count': len(ips)
        })

    except Exception as e:
        print(f"Error getting IP pool: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/ip-pool/info')
@login_required
def get_ip_pool_info():
    """Get information about available IP pools"""
    try:
        pool_manager = get_pool_manager()
        info = pool_manager.get_pool_info()

        return jsonify({
            'success': True,
            'pools': info
        })

    except Exception as e:
        print(f"Error getting pool info: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/execute', methods=['POST'])
@login_required
@permission_required('simulation_execute')
def execute_simulation():
    """Execute an attack simulation"""
    try:
        data = request.get_json()

        template_name = data.get('template_name')
        custom_params = data.get('parameters', {})

        if not template_name:
            return jsonify({'error': 'template_name is required'}), 400

        # Get current user info
        session_token = request.cookies.get('session_token')
        user_data = SessionManager.get_user_from_session(session_token)

        # Execute simulation synchronously (it's fast enough)
        simulator = AttackSimulator(guardian_api_url=GUARDIAN_API)
        result = simulator.execute(
            template_name=template_name,
            custom_params=custom_params,
            user_id=user_data.get('id'),
            user_email=user_data.get('email')
        )

        simulation_id = result['simulation_id']

        return jsonify({
            'success': True,
            'message': 'Simulation completed',
            'simulation_id': simulation_id,
            'status': result['status'],
            'summary': result['summary']
        })

    except Exception as e:
        print(f"Error executing simulation: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/history')
@login_required
def get_simulation_history():
    """Get simulation history"""
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        attack_type = request.args.get('attack_type', '').strip()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build query with optional attack_type filter
        query = """
            SELECT
                id,
                user_email,
                template_name,
                template_display_name,
                status,
                total_events,
                events_processed,
                ips_blocked,
                alerts_sent,
                error_message,
                created_at,
                completed_at,
                duration_seconds
            FROM simulation_history
        """

        params = []
        if attack_type:
            query += " WHERE template_name = %s"
            params.append(attack_type)

        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cursor.execute(query, tuple(params))
        history = cursor.fetchall()

        # Convert datetime to string
        for record in history:
            if record['created_at']:
                record['created_at'] = record['created_at'].isoformat()
            if record['completed_at']:
                record['completed_at'] = record['completed_at'].isoformat()

        # Get total count with same filter
        count_query = "SELECT COUNT(*) as total FROM simulation_history"
        count_params = []
        if attack_type:
            count_query += " WHERE template_name = %s"
            count_params.append(attack_type)

        cursor.execute(count_query, tuple(count_params))
        total = cursor.fetchone()['total']

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'history': history,
            'total': total,
            'limit': limit,
            'offset': offset,
            'attack_type': attack_type
        })

    except Exception as e:
        print(f"Error getting simulation history: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/attack-types')
@login_required
def get_attack_types():
    """Get distinct attack types from simulation history"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT
                template_name,
                template_display_name
            FROM simulation_history
            WHERE template_name IS NOT NULL
            ORDER BY template_display_name
        """)

        attack_types = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'attack_types': attack_types
        })

    except Exception as e:
        print(f"Error getting attack types: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/history/<int:simulation_id>')
@login_required
def get_simulation_detail(simulation_id):
    """Get detailed information about a specific simulation"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get simulation record
        cursor.execute("""
            SELECT * FROM simulation_history
            WHERE id = %s
        """, (simulation_id,))

        simulation = cursor.fetchone()

        if not simulation:
            return jsonify({'error': 'Simulation not found'}), 404

        # Convert datetime
        if simulation['created_at']:
            simulation['created_at'] = simulation['created_at'].isoformat()
        if simulation['completed_at']:
            simulation['completed_at'] = simulation['completed_at'].isoformat()

        # Parse JSON
        if simulation['request_json']:
            simulation['request_json'] = json_module.loads(simulation['request_json'])

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'simulation': simulation
        })

    except Exception as e:
        print(f"Error getting simulation detail: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/logs/<int:simulation_id>')
@login_required
def get_simulation_logs(simulation_id):
    """Get logs for a specific simulation"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                timestamp,
                sequence_number,
                stage,
                level,
                message,
                metadata
            FROM simulation_logs
            WHERE simulation_id = %s
            ORDER BY sequence_number ASC
        """, (simulation_id,))

        logs = cursor.fetchall()

        # Convert datetime and parse JSON
        for log in logs:
            if log['timestamp']:
                log['timestamp'] = log['timestamp'].isoformat()
            if log['metadata']:
                try:
                    log['metadata'] = json_module.loads(log['metadata'])
                except:
                    pass

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'simulation_id': simulation_id,
            'logs': logs,
            'count': len(logs)
        })

    except Exception as e:
        print(f"Error getting simulation logs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/analytics/<int:simulation_id>')
@login_required
def get_simulation_analytics(simulation_id):
    """Get detailed IP analytics for a simulation"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get simulation basic info
        cursor.execute("""
            SELECT template_name, template_display_name, created_at, status
            FROM simulation_history
            WHERE id = %s
        """, (simulation_id,))
        sim_info = cursor.fetchone()

        if not sim_info:
            return jsonify({'error': 'Simulation not found'}), 404

        # Rename fields for consistency
        if sim_info:
            sim_info['attack_type'] = sim_info.get('template_display_name') or sim_info.get('template_name')
            sim_info['executed_at'] = sim_info.get('created_at')

        # Try to get blocked IP first
        cursor.execute("""
            SELECT ip_address, MAX(blocked_at) as blocked_at, MAX(block_reason) as reason
            FROM ip_blocks
            WHERE simulation_id = %s AND is_simulation = TRUE
            GROUP BY ip_address
            ORDER BY MAX(blocked_at) DESC
            LIMIT 1
        """, (simulation_id,))
        blocked_ip_info = cursor.fetchone()

        # If no blocked IPs, get the most active IP from logins
        if not blocked_ip_info:
            cursor.execute("""
                SELECT source_ip as ip_address, COUNT(*) as login_count
                FROM (
                    SELECT source_ip FROM successful_logins WHERE simulation_id = %s
                    UNION ALL
                    SELECT source_ip FROM failed_logins WHERE simulation_id = %s
                ) as all_logins
                GROUP BY source_ip
                ORDER BY login_count DESC
                LIMIT 1
            """, (simulation_id, simulation_id))
            active_ip_info = cursor.fetchone()

            if not active_ip_info:
                cursor.close()
                conn.close()
                return jsonify({
                    'success': True,
                    'has_data': False,
                    'message': 'No login activity in this simulation'
                })

            ip_address = active_ip_info['ip_address']
            # Create a fake blocked_ip_info structure for consistency
            blocked_ip_info = {
                'ip_address': ip_address,
                'blocked_at': None,
                'reason': None
            }
        else:
            ip_address = blocked_ip_info['ip_address']

        # Get successful logins for this IP
        cursor.execute("""
            SELECT username, timestamp, country, city, ml_risk_score
            FROM successful_logins
            WHERE simulation_id = %s AND source_ip = %s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (simulation_id, ip_address))
        successful_logins = cursor.fetchall()

        # Get failed logins for this IP
        cursor.execute("""
            SELECT username, timestamp, country, city, ml_risk_score
            FROM failed_logins
            WHERE simulation_id = %s AND source_ip = %s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (simulation_id, ip_address))
        failed_logins = cursor.fetchall()

        # Get counts
        cursor.execute("""
            SELECT COUNT(*) as count FROM successful_logins
            WHERE simulation_id = %s AND source_ip = %s
        """, (simulation_id, ip_address))
        successful_count = cursor.fetchone()['count']

        cursor.execute("""
            SELECT COUNT(*) as count FROM failed_logins
            WHERE simulation_id = %s AND source_ip = %s
        """, (simulation_id, ip_address))
        failed_count = cursor.fetchone()['count']

        # Get avg risk score
        cursor.execute("""
            SELECT AVG(ml_risk_score) as avg_risk
            FROM (
                SELECT ml_risk_score FROM successful_logins WHERE simulation_id = %s AND source_ip = %s
                UNION ALL
                SELECT ml_risk_score FROM failed_logins WHERE simulation_id = %s AND source_ip = %s
            ) as all_events
        """, (simulation_id, ip_address, simulation_id, ip_address))
        avg_risk = cursor.fetchone()['avg_risk'] or 0

        # Convert datetime objects
        for login in successful_logins:
            if login.get('timestamp'):
                login['timestamp'] = login['timestamp'].isoformat()
        for login in failed_logins:
            if login.get('timestamp'):
                login['timestamp'] = login['timestamp'].isoformat()
        if blocked_ip_info.get('blocked_at'):
            blocked_ip_info['blocked_at'] = blocked_ip_info['blocked_at'].isoformat()

        cursor.close()
        conn.close()

        # Determine risk level
        if avg_risk >= 70:
            risk_level = 'Critical'
        elif avg_risk >= 50:
            risk_level = 'High'
        elif avg_risk >= 30:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'

        # Get location from first login
        location = None
        country = None
        if successful_logins:
            location = f"{successful_logins[0].get('city', 'Unknown')}, {successful_logins[0].get('country', 'Unknown')}"
            country = successful_logins[0].get('country', 'Unknown')
        elif failed_logins:
            location = f"{failed_logins[0].get('city', 'Unknown')}, {failed_logins[0].get('country', 'Unknown')}"
            country = failed_logins[0].get('country', 'Unknown')

        return jsonify({
            'success': True,
            'has_data': True,
            'ip_address': ip_address,
            'stats': {
                'total_logins': successful_count + failed_count,
                'successful': successful_count,
                'failed': failed_count,
                'location': location,
                'country': country,
                'risk_score': round(avg_risk, 1),
                'risk_level': risk_level,
                'blocked_at': blocked_ip_info.get('blocked_at') if isinstance(blocked_ip_info, dict) else blocked_ip_info['blocked_at'],
                'block_reason': blocked_ip_info.get('reason') if isinstance(blocked_ip_info, dict) else blocked_ip_info['reason'],
                'was_blocked': blocked_ip_info.get('reason') is not None if isinstance(blocked_ip_info, dict) else blocked_ip_info['reason'] is not None
            },
            'successful_logins': successful_logins,
            'failed_logins': failed_logins,
            'simulation_info': sim_info
        })

    except Exception as e:
        print(f"Error getting simulation analytics: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulation/stream/<int:simulation_id>')
@login_required
def stream_simulation_logs(simulation_id):
    """Server-Sent Events stream for real-time simulation logs"""
    from flask import Response
    import time

    def generate():
        """Generator for SSE"""
        last_sequence = 0

        # Send initial message
        yield f"data: {json_module.dumps({'type': 'connected', 'simulation_id': simulation_id})}\n\n"

        try:
            while True:
                conn = get_connection()
                cursor = conn.cursor(dictionary=True)

                # Fetch new logs
                cursor.execute("""
                    SELECT
                        timestamp,
                        sequence_number,
                        stage,
                        level,
                        message,
                        metadata
                    FROM simulation_logs
                    WHERE simulation_id = %s AND sequence_number > %s
                    ORDER BY sequence_number ASC
                """, (simulation_id, last_sequence))

                new_logs = cursor.fetchall()

                for log in new_logs:
                    # Convert datetime
                    if log['timestamp']:
                        log['timestamp'] = log['timestamp'].isoformat()
                    if log['metadata']:
                        try:
                            log['metadata'] = json_module.loads(log['metadata'])
                        except:
                            pass

                    # Send log via SSE
                    yield f"data: {json_module.dumps(log)}\n\n"

                    last_sequence = log['sequence_number']

                cursor.close()
                conn.close()

                # Check if simulation is complete
                conn = get_connection()
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT status FROM simulation_history WHERE id = %s
                """, (simulation_id,))
                status_row = cursor.fetchone()
                cursor.close()
                conn.close()

                if status_row and status_row['status'] in ['completed', 'failed', 'cancelled']:
                    # Send completion message
                    yield f"data: {json_module.dumps({'type': 'completed', 'status': status_row['status']})}\n\n"
                    break

                time.sleep(1)  # Poll every second

        except GeneratorExit:
            # Client disconnected
            pass
        except Exception as e:
            yield f"data: {json_module.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream')


# ==================== ML ANALYTICS ENDPOINTS ====================

@app.route('/api/ml/effectiveness')
@login_required
def get_ml_effectiveness():
    """
    Get ML effectiveness metrics
    Query params:
        days: Number of days to analyze (default: 7)
    """
    try:
        days = request.args.get('days', 7, type=int)

        tracker = MLEffectivenessTracker()
        metrics = tracker.get_ml_performance_metrics(days)
        tracker.close()

        return jsonify({
            'status': 'success',
            'data': metrics
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/ml/comparison')
@login_required
def get_ml_comparison():
    """
    Compare ML-based detection vs rule-based detection
    Query params:
        days: Number of days to analyze (default: 7)
    """
    try:
        days = request.args.get('days', 7, type=int)

        tracker = MLEffectivenessTracker()
        comparison = tracker.compare_ml_vs_baseline(days)
        tracker.close()

        return jsonify({
            'status': 'success',
            'data': comparison
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/ml/report')
@login_required
def get_ml_report():
    """
    Generate comprehensive ML effectiveness report
    Query params:
        days: Number of days to analyze (default: 7)
        format: 'text' or 'json' (default: 'json')
    """
    try:
        days = request.args.get('days', 7, type=int)
        format_type = request.args.get('format', 'json', type=str)

        tracker = MLEffectivenessTracker()

        if format_type == 'text':
            report = tracker.generate_effectiveness_report(days)
            tracker.close()
            return Response(report, mimetype='text/plain')
        else:
            metrics = tracker.get_ml_performance_metrics(days)
            comparison = tracker.compare_ml_vs_baseline(days)
            model_info = tracker.get_ml_model_info()
            tracker.close()

            return jsonify({
                'status': 'success',
                'data': {
                    'model_info': model_info,
                    'performance_metrics': metrics,
                    'ml_vs_baseline_comparison': comparison
                }
            })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/analytics/top-ips')
@login_required
def get_analytics_top_ips():
    """Get top IPs for analytics"""
    try:
        limit = int(request.args.get('limit', 10))
        hours = int(request.args.get('hours', 24))
        start_time = datetime.now() - timedelta(hours=hours)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                source_ip as ip,
                country,
                COUNT(*) as count,
                AVG(ml_risk_score) as avg_risk
            FROM (
                SELECT source_ip, country, ml_risk_score FROM failed_logins WHERE timestamp >= %s
                UNION ALL
                SELECT source_ip, country, ml_risk_score FROM successful_logins WHERE timestamp >= %s
            ) AS combined
            GROUP BY source_ip, country
            ORDER BY count DESC
            LIMIT %s
        """, (start_time, start_time, limit))

        top_ips = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'top_ips': top_ips
        })

    except Exception as e:
        print(f"Error getting top IPs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analytics/top-usernames')
@login_required
def get_analytics_top_usernames():
    """Get top targeted usernames for analytics"""
    try:
        limit = int(request.args.get('limit', 10))
        hours = int(request.args.get('hours', 24))
        start_time = datetime.now() - timedelta(hours=hours)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                username,
                COUNT(*) as count,
                COUNT(DISTINCT source_ip) as unique_ips,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) / COUNT(*) as success_rate
            FROM (
                SELECT username, source_ip, 'failed' as event_type FROM failed_logins
                WHERE timestamp >= %s AND username IS NOT NULL
                UNION ALL
                SELECT username, source_ip, 'successful' as event_type FROM successful_logins
                WHERE timestamp >= %s AND username IS NOT NULL
            ) AS combined
            GROUP BY username
            ORDER BY count DESC
            LIMIT %s
        """, (start_time, start_time, limit))

        top_usernames = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'top_usernames': top_usernames
        })

    except Exception as e:
        print(f"Error getting top usernames: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analytics/geographic')
@login_required
def get_analytics_geographic():
    """Get geographic distribution for analytics"""
    try:
        limit = int(request.args.get('limit', 15))
        hours = int(request.args.get('hours', 24))
        start_time = datetime.now() - timedelta(hours=hours)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                country,
                COUNT(*) as count
            FROM (
                SELECT country FROM failed_logins WHERE timestamp >= %s AND country IS NOT NULL
                UNION ALL
                SELECT country FROM successful_logins WHERE timestamp >= %s AND country IS NOT NULL
            ) AS combined
            GROUP BY country
            ORDER BY count DESC
            LIMIT %s
        """, (start_time, start_time, limit))

        countries = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'countries': countries
        })

    except Exception as e:
        print(f"Error getting geographic data: {e}")
        return jsonify({'error': str(e)}), 500


# ===================================================================
# IP THREAT INTELLIGENCE ENDPOINTS
# ===================================================================

@app.route('/api/ip/intel/lookup/<ip_address>')
@login_required
def intel_lookup_ip(ip_address):
    """
    Comprehensive IP lookup across all threat intelligence sources

    Returns aggregated data from VirusTotal, Shodan, and AbuseIPDB
    """
    try:
        service = get_ip_enrichment_service()
        result = service.lookup_ip(ip_address, use_cache=True)

        return jsonify({
            'status': 'success',
            'data': result
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/ip/intel/virustotal/<ip_address>')
@login_required
def intel_lookup_virustotal(ip_address):
    """
    VirusTotal-specific IP lookup

    Returns detailed VirusTotal analysis
    """
    try:
        service = get_ip_enrichment_service()

        if service.virustotal_client:
            result = service.virustotal_client.lookup(ip_address, use_cache=True)
            return jsonify({
                'status': 'success',
                'data': result
            })
        else:
            return jsonify({
                'status': 'error',
                'error': 'VirusTotal API key not configured'
            }), 503

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/ip/intel/shodan/<ip_address>')
@login_required
def intel_lookup_shodan(ip_address):
    """
    Shodan-specific IP lookup

    Returns open ports, services, and vulnerabilities
    """
    try:
        service = get_ip_enrichment_service()

        if service.shodan_client:
            result = service.shodan_client.lookup(ip_address, use_cache=True)
            return jsonify({
                'status': 'success',
                'data': result
            })
        else:
            return jsonify({
                'status': 'error',
                'error': 'Shodan API key not configured'
            }), 503

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/ip/intel/abuseipdb/<ip_address>')
@login_required
def intel_lookup_abuseipdb(ip_address):
    """
    AbuseIPDB-specific IP lookup

    Returns abuse reports and confidence score
    """
    try:
        service = get_ip_enrichment_service()

        if service.abuseipdb_client:
            result = service.abuseipdb_client.lookup(ip_address, use_cache=True)
            return jsonify({
                'status': 'success',
                'data': result
            })
        else:
            return jsonify({
                'status': 'error',
                'error': 'AbuseIPDB API key not configured'
            }), 503

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/ip/intelligence/status')
@login_required
def intelligence_service_status():
    """
    Get status of all threat intelligence services

    Returns which services are available and cache statistics
    """
    try:
        service = get_ip_enrichment_service()
        status = service.get_service_status()

        return jsonify({
            'status': 'success',
            'data': status
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/ip/intelligence/cache/clear', methods=['POST'])
@login_required
@permission_required('admin')
def clear_intelligence_cache():
    """
    Clear all IP intelligence caches (admin only)
    """
    try:
        service = get_ip_enrichment_service()
        results = service.clear_all_caches()

        return jsonify({
            'status': 'success',
            'message': 'All caches cleared',
            'data': results
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/ip/analytics/<ip_address>')
@login_required
def ip_comprehensive_analytics(ip_address):
    """
    Comprehensive IP analytics combining local DB data and 3rd party intelligence

    Returns:
    - Login history (successful and failed)
    - Session patterns and duration stats
    - Geographic data
    - Threat intelligence from VirusTotal, AbuseIPDB, Shodan
    - Behavioral patterns and anomaly detection
    """
    print(f"\n{'='*80}")
    print(f"[IP_ANALYTICS] Request for IP: {ip_address}")
    print(f"{'='*80}")

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # === LOCAL DATABASE ANALYTICS ===
        print(f"[DB_QUERY] Fetching successful logins for {ip_address}...")

        # Get successful login history
        cursor.execute("""
            SELECT
                id, timestamp, server_hostname, username, port,
                session_duration, country, city, latitude, longitude,
                ip_risk_score, ip_reputation, ml_risk_score, is_anomaly,
                created_at
            FROM successful_logins
            WHERE source_ip = %s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (ip_address,))
        successful_logins = cursor.fetchall()

        print(f"[DB_RESULT] Found {len(successful_logins)} successful logins")

        # Get failed login attempts
        print(f"[DB_QUERY] Fetching failed logins for {ip_address}...")
        cursor.execute("""
            SELECT
                id, timestamp, server_hostname, username, port,
                failure_reason, country, city, latitude, longitude,
                ip_risk_score, ip_reputation, ml_risk_score, is_anomaly,
                created_at
            FROM failed_logins
            WHERE source_ip = %s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (ip_address,))
        failed_logins = cursor.fetchall()

        print(f"[DB_RESULT] Found {len(failed_logins)} failed logins")

        # Get login statistics
        print(f"[DB_QUERY] Calculating login statistics...")
        cursor.execute("""
            SELECT
                COUNT(*) as total_successful,
                AVG(session_duration) as avg_session_duration,
                MAX(session_duration) as max_session_duration,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                COUNT(DISTINCT username) as unique_usernames,
                COUNT(DISTINCT server_hostname) as unique_servers
            FROM successful_logins
            WHERE source_ip = %s
        """, (ip_address,))
        success_stats = cursor.fetchone()

        cursor.execute("""
            SELECT
                COUNT(*) as total_failed,
                COUNT(DISTINCT username) as unique_usernames_tried
            FROM failed_logins
            WHERE source_ip = %s
        """, (ip_address,))
        failed_stats = cursor.fetchone()

        print(f"[DB_STATS] Successful: {success_stats['total_successful']}, Failed: {failed_stats['total_failed']}")

        # Get most used usernames
        print(f"[DB_QUERY] Getting username patterns...")
        cursor.execute("""
            SELECT username, COUNT(*) as count
            FROM (
                SELECT username FROM successful_logins WHERE source_ip = %s
                UNION ALL
                SELECT username FROM failed_logins WHERE source_ip = %s
            ) AS combined
            GROUP BY username
            ORDER BY count DESC
            LIMIT 5
        """, (ip_address, ip_address))
        username_patterns = cursor.fetchall()

        # Get hourly activity pattern
        print(f"[DB_QUERY] Analyzing hourly activity pattern...")
        cursor.execute("""
            SELECT
                HOUR(timestamp) as hour,
                COUNT(*) as activity_count
            FROM (
                SELECT timestamp FROM successful_logins WHERE source_ip = %s
                UNION ALL
                SELECT timestamp FROM failed_logins WHERE source_ip = %s
            ) AS combined
            GROUP BY HOUR(timestamp)
            ORDER BY hour
        """, (ip_address, ip_address))
        hourly_pattern = cursor.fetchall()

        # Convert datetime objects to ISO format
        for login in successful_logins:
            if login.get('timestamp'):
                login['timestamp'] = login['timestamp'].isoformat()
            if login.get('created_at'):
                login['created_at'] = login['created_at'].isoformat()

        for login in failed_logins:
            if login.get('timestamp'):
                login['timestamp'] = login['timestamp'].isoformat()
            if login.get('created_at'):
                login['created_at'] = login['created_at'].isoformat()

        if success_stats.get('first_seen'):
            success_stats['first_seen'] = success_stats['first_seen'].isoformat()
        if success_stats.get('last_seen'):
            success_stats['last_seen'] = success_stats['last_seen'].isoformat()

        cursor.close()
        conn.close()

        # === 3RD PARTY THREAT INTELLIGENCE ===
        print(f"[INTEL] Fetching threat intelligence for {ip_address}...")
        threat_intel = {}

        try:
            service = get_ip_enrichment_service()
            threat_intel_result = service.lookup_ip(ip_address, use_cache=True)
            threat_intel = threat_intel_result or {}
            print(f"[INTEL] Successfully fetched threat intelligence")
        except Exception as e:
            print(f"[INTEL_ERROR] Failed to fetch threat intelligence: {e}")
            threat_intel = {'error': str(e)}

        # === PATTERN ANALYSIS ===
        print(f"[ANALYSIS] Performing pattern analysis...")
        patterns = {
            'behavior_type': 'unknown',
            'risk_indicators': [],
            'suggestions': []
        }

        total_attempts = success_stats['total_successful'] + failed_stats['total_failed']
        success_rate = (success_stats['total_successful'] / total_attempts * 100) if total_attempts > 0 else 0

        # Determine behavior type
        if success_stats['total_successful'] > 0 and failed_stats['total_failed'] == 0:
            patterns['behavior_type'] = 'trusted_user'
            patterns['suggestions'].append('Consistent successful authentication - appears to be legitimate user')
        elif failed_stats['total_failed'] > success_stats['total_successful'] * 3:
            patterns['behavior_type'] = 'brute_force_suspected'
            patterns['risk_indicators'].append(f'High failure rate: {failed_stats["total_failed"]} failed vs {success_stats["total_successful"]} successful')
            patterns['suggestions'].append('Consider adding rate limiting or temporary IP block')
        elif failed_stats['total_failed'] > 0 and success_stats['total_successful'] > 0:
            patterns['behavior_type'] = 'mixed_activity'
            patterns['risk_indicators'].append(f'Mixed success/failure pattern detected')
            patterns['suggestions'].append('Monitor for credential stuffing attempts')

        if failed_stats['unique_usernames_tried'] > 5:
            patterns['risk_indicators'].append(f'Multiple usernames tried: {failed_stats["unique_usernames_tried"]}')
            patterns['suggestions'].append('User enumeration detected - consider hiding user existence in auth responses')

        print(f"[ANALYSIS] Behavior type: {patterns['behavior_type']}")
        print(f"[ANALYSIS] Risk indicators: {len(patterns['risk_indicators'])}")

        # Compile response
        response = {
            'ip_address': ip_address,
            'local_analytics': {
                'successful_logins': successful_logins,
                'failed_logins': failed_logins,
                'statistics': {
                    'total_successful': success_stats['total_successful'],
                    'total_failed': failed_stats['total_failed'],
                    'success_rate': round(success_rate, 2),
                    'avg_session_duration': float(success_stats['avg_session_duration']) if success_stats['avg_session_duration'] else 0,
                    'max_session_duration': success_stats['max_session_duration'],
                    'first_seen': success_stats['first_seen'],
                    'last_seen': success_stats['last_seen'],
                    'unique_usernames': success_stats['unique_usernames'],
                    'unique_servers': success_stats['unique_servers']
                },
                'patterns': {
                    'username_frequency': username_patterns,
                    'hourly_activity': hourly_pattern
                }
            },
            'threat_intelligence': threat_intel,
            'pattern_analysis': patterns
        }

        print(f"[SUCCESS] IP analytics compiled successfully")
        print(f"{'='*80}\n")

        return jsonify({
            'status': 'success',
            'data': response
        })

    except Exception as e:
        print(f"[ERROR] IP analytics failed: {e}")
        import traceback
        traceback.print_exc()
        print(f"{'='*80}\n")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


if __name__ == '__main__':
    print("🚀 Starting SSH Guardian Dashboard Server...")
    print("📊 Dashboard: http://localhost:8080")
    print("🔌 API Endpoint: http://localhost:8080/api/")
    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)
