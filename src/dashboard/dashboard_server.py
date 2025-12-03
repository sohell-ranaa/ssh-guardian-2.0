"""
SSH Guardian 2.0 - Web Dashboard Server
Real-time monitoring and management interface
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__,
           template_folder='templates',
           static_folder='static')
CORS(app)

# Guardian API endpoint
GUARDIAN_API = os.getenv('GUARDIAN_API_URL', 'http://localhost:5000')

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats/overview')
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
def get_recent_threats():
    """Get recent high-risk threats"""
    try:
        limit = int(request.args.get('limit', 50))
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get high-risk events from both tables
        cursor.execute("""
            SELECT
                id, timestamp, source_ip as ip, username,
                'failed' as event_type, country, city,
                ml_risk_score, is_anomaly, ml_threat_type as threat_type
            FROM failed_logins
            WHERE ml_risk_score >= 50
            UNION ALL
            SELECT
                id, timestamp, source_ip as ip, username,
                'successful' as event_type, country, city,
                ml_risk_score, is_anomaly, ml_threat_type as threat_type
            FROM successful_logins
            WHERE ml_risk_score >= 50
            ORDER BY timestamp DESC
            LIMIT %s
        """, (limit,))

        threats = cursor.fetchall()

        # Convert datetime to string
        for threat in threats:
            if threat['timestamp']:
                threat['timestamp'] = threat['timestamp'].isoformat()

        cursor.close()
        conn.close()

        return jsonify(threats)

    except Exception as e:
        print(f"Error in get_recent_threats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/geographic')
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

if __name__ == '__main__':
    print("🚀 Starting SSH Guardian Dashboard Server...")
    print("📊 Dashboard: http://localhost:8080")
    print("🔌 API Endpoint: http://localhost:8080/api/")
    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)
