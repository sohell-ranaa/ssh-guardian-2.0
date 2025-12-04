"""
Multi-Agent API Endpoints
Handles API routes for multi-agent dashboard functionality
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from auth import login_required

# Create blueprint
multi_agent_bp = Blueprint('multi_agent', __name__)


@multi_agent_bp.route('/api/agents')
@login_required
def get_agents():
    """Get list of all registered agents"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                agent_id,
                hostname,
                display_name,
                ip_address,
                location,
                status,
                last_heartbeat,
                version,
                is_active,
                created_at
            FROM agents
            WHERE is_active = 1
            ORDER BY display_name
        """)

        agents = cursor.fetchall()

        # Get event counts for each agent
        for agent in agents:
            # Failed logins count
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM failed_logins
                WHERE server_hostname = %s
            """, (agent['hostname'],))
            agent['failed_logins_count'] = cursor.fetchone()['count']

            # Blocked IPs count
            cursor.execute("""
                SELECT COUNT(DISTINCT ip_address) as count
                FROM ip_blocks
                WHERE is_active = 1
            """)
            agent['blocked_ips_count'] = cursor.fetchone()['count']

            # Format datetime
            if agent['last_heartbeat']:
                agent['last_heartbeat'] = agent['last_heartbeat'].isoformat()
            if agent['created_at']:
                agent['created_at'] = agent['created_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'status': 'success',
            'agents': agents,
            'count': len(agents)
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@multi_agent_bp.route('/api/agents/<agent_id>/stats')
@login_required
def get_agent_stats(agent_id):
    """Get statistics for a specific agent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent info
        cursor.execute("""
            SELECT hostname FROM agents WHERE agent_id = %s
        """, (agent_id,))

        agent = cursor.fetchone()
        if not agent:
            return jsonify({
                'status': 'error',
                'error': 'Agent not found'
            }), 404

        hostname = agent['hostname']
        stats = {}

        # Time ranges
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_hour = now - timedelta(hours=1)

        # Total events
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM failed_logins
            WHERE server_hostname = %s
        """, (hostname,))
        stats['total_failed_logins'] = cursor.fetchone()['count']

        cursor.execute("""
            SELECT COUNT(*) as count
            FROM successful_logins
            WHERE server_hostname = %s
        """, (hostname,))
        stats['total_successful_logins'] = cursor.fetchone()['count']

        # Last 24h
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM failed_logins
            WHERE server_hostname = %s AND timestamp >= %s
        """, (hostname, last_24h))
        stats['failed_24h'] = cursor.fetchone()['count']

        # Last hour
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM failed_logins
            WHERE server_hostname = %s AND timestamp >= %s
        """, (hostname, last_hour))
        stats['failed_1h'] = cursor.fetchone()['count']

        # Unique IPs
        cursor.execute("""
            SELECT COUNT(DISTINCT source_ip) as count
            FROM failed_logins
            WHERE server_hostname = %s
        """, (hostname,))
        stats['unique_ips'] = cursor.fetchone()['count']

        # High risk threats
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM failed_logins
            WHERE server_hostname = %s
            AND (ml_risk_score >= 80 OR ip_reputation = 'malicious')
        """, (hostname,))
        stats['high_risk_threats'] = cursor.fetchone()['count']

        cursor.close()
        conn.close()

        return jsonify({
            'status': 'success',
            'agent_id': agent_id,
            'hostname': hostname,
            'stats': stats
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@multi_agent_bp.route('/api/stats/overview/multi-agent')
@login_required
def get_multi_agent_overview():
    """Get aggregated overview stats across all agents or filtered by agent"""
    try:
        agent_filter = request.args.get('agent_id', 'all')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Time ranges
        now = datetime.now()
        last_hour = now - timedelta(hours=1)
        last_24h = now - timedelta(hours=24)

        stats = {}

        # Build WHERE clause for agent filtering
        where_clause = ""
        params_failed = []
        params_successful = []

        if agent_filter != 'all':
            # Get hostname for agent_id
            cursor.execute("SELECT hostname FROM agents WHERE agent_id = %s", (agent_filter,))
            agent = cursor.fetchone()
            if agent:
                hostname = agent['hostname']
                where_clause = "WHERE server_hostname = %s"
                params_failed = [hostname]
                params_successful = [hostname]

        # Total events
        cursor.execute(f"SELECT COUNT(*) as count FROM failed_logins {where_clause}", params_failed)
        failed_total = cursor.fetchone()['count']

        cursor.execute(f"SELECT COUNT(*) as count FROM successful_logins {where_clause}", params_successful)
        successful_total = cursor.fetchone()['count']

        stats['total_events'] = failed_total + successful_total

        # Events last 24h
        where_24h = f"{where_clause} AND timestamp >= %s" if where_clause else "WHERE timestamp >= %s"
        cursor.execute(f"SELECT COUNT(*) as count FROM failed_logins {where_24h}",
                      params_failed + [last_24h])
        failed_24h = cursor.fetchone()['count']

        cursor.execute(f"SELECT COUNT(*) as count FROM successful_logins {where_24h}",
                      params_successful + [last_24h])
        successful_24h = cursor.fetchone()['count']

        stats['events_24h'] = failed_24h + successful_24h

        # Events last hour
        where_1h = f"{where_clause} AND timestamp >= %s" if where_clause else "WHERE timestamp >= %s"
        cursor.execute(f"SELECT COUNT(*) as count FROM failed_logins {where_1h}",
                      params_failed + [last_hour])
        failed_1h = cursor.fetchone()['count']

        cursor.execute(f"SELECT COUNT(*) as count FROM successful_logins {where_1h}",
                      params_successful + [last_hour])
        successful_1h = cursor.fetchone()['count']

        stats['events_1h'] = failed_1h + successful_1h

        # Failed login attempts
        stats['failed_logins'] = failed_total
        stats['failed_24h'] = failed_24h
        stats['failed_1h'] = failed_1h

        # Successful logins
        stats['successful_logins'] = successful_total
        stats['successful_24h'] = successful_24h
        stats['successful_1h'] = successful_1h

        # Unique attacking IPs
        cursor.execute(f"""
            SELECT COUNT(DISTINCT source_ip) as count
            FROM failed_logins {where_clause}
        """, params_failed)
        stats['unique_ips'] = cursor.fetchone()['count']

        # Currently blocked IPs (global, not per-agent)
        cursor.execute("SELECT COUNT(*) as count FROM ip_blocks WHERE is_active = 1")
        stats['blocked_ips'] = cursor.fetchone()['count']

        # High risk threats (ML risk score >= 80 or malicious reputation)
        cursor.execute(f"""
            SELECT COUNT(*) as count
            FROM failed_logins
            {where_clause}
            {'AND' if where_clause else 'WHERE'} (ml_risk_score >= 80 OR ip_reputation = 'malicious')
        """, params_failed)
        stats['high_risk_threats'] = cursor.fetchone()['count']

        # Top countries
        cursor.execute(f"""
            SELECT country, COUNT(*) as count
            FROM failed_logins
            {where_clause}
            {'AND' if where_clause else 'WHERE'} country IS NOT NULL
            GROUP BY country
            ORDER BY count DESC
            LIMIT 5
        """, params_failed)
        stats['top_countries'] = cursor.fetchall()

        # Get agent info if filtered
        if agent_filter != 'all':
            cursor.execute("""
                SELECT agent_id, hostname, display_name, status
                FROM agents WHERE agent_id = %s
            """, (agent_filter,))
            stats['agent_info'] = cursor.fetchone()
        else:
            # Get total agent count
            cursor.execute("SELECT COUNT(*) as count FROM agents WHERE is_active = 1")
            stats['total_agents'] = cursor.fetchone()['count']

        cursor.close()
        conn.close()

        return jsonify({
            'status': 'success',
            'filter': agent_filter,
            'stats': stats
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
