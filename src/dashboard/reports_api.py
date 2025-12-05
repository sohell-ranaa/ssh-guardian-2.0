"""
SSH Guardian 2.0 - Daily Reports API
Provides endpoints for generating and retrieving daily security reports
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from auth import login_required

reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')


@reports_bp.route('/daily/summary')
@login_required
def get_daily_summary():
    """
    Get daily summary report for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Total events
        cursor.execute("""
            SELECT
                COUNT(*) as total_failed,
                COUNT(DISTINCT source_ip) as unique_ips_failed,
                COUNT(DISTINCT username) as unique_usernames_failed,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                SUM(CASE WHEN ml_risk_score >= 80 THEN 1 ELSE 0 END) as critical_events,
                SUM(CASE WHEN ml_risk_score >= 60 AND ml_risk_score < 80 THEN 1 ELSE 0 END) as high_events,
                SUM(CASE WHEN ml_risk_score >= 40 AND ml_risk_score < 60 THEN 1 ELSE 0 END) as medium_events,
                SUM(CASE WHEN ml_risk_score < 40 THEN 1 ELSE 0 END) as low_events,
                AVG(ml_risk_score) as avg_risk_score
            FROM failed_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
        """, (start_time, end_time))
        failed_stats = cursor.fetchone()

        cursor.execute("""
            SELECT
                COUNT(*) as total_successful,
                COUNT(DISTINCT source_ip) as unique_ips_successful,
                COUNT(DISTINCT username) as unique_usernames_successful,
                AVG(session_duration) as avg_session_duration
            FROM successful_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
        """, (start_time, end_time))
        success_stats = cursor.fetchone()

        # Blocked IPs count for the day
        cursor.execute("""
            SELECT COUNT(*) as blocked_count
            FROM ip_blocks
            WHERE blocked_at >= %s AND blocked_at <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
        """, (start_time, end_time))
        blocked_stats = cursor.fetchone()

        summary = {
            'date': report_date.isoformat(),
            'total_events': (failed_stats['total_failed'] or 0) + (success_stats['total_successful'] or 0),
            'failed_logins': failed_stats['total_failed'] or 0,
            'successful_logins': success_stats['total_successful'] or 0,
            'unique_ips': max(failed_stats['unique_ips_failed'] or 0, success_stats['unique_ips_successful'] or 0),
            'unique_usernames': max(failed_stats['unique_usernames_failed'] or 0, success_stats['unique_usernames_successful'] or 0),
            'anomalies': failed_stats['anomalies'] or 0,
            'blocked_ips': blocked_stats['blocked_count'] or 0,
            'risk_breakdown': {
                'critical': failed_stats['critical_events'] or 0,
                'high': failed_stats['high_events'] or 0,
                'medium': failed_stats['medium_events'] or 0,
                'low': failed_stats['low_events'] or 0
            },
            'avg_risk_score': round(float(failed_stats['avg_risk_score'] or 0), 2),
            'avg_session_duration': round(float(success_stats['avg_session_duration'] or 0), 2)
        }

        return jsonify({
            'success': True,
            'summary': summary
        })

    except Exception as e:
        print(f"Error in get_daily_summary: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@reports_bp.route('/daily/hourly-breakdown')
@login_required
def get_hourly_breakdown():
    """
    Get hourly breakdown of events for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get hourly breakdown for failed logins
        cursor.execute("""
            SELECT
                HOUR(timestamp) as hour,
                COUNT(*) as failed_count,
                AVG(ml_risk_score) as avg_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM failed_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
            GROUP BY HOUR(timestamp)
            ORDER BY hour
        """, (start_time, end_time))
        failed_hourly = {row['hour']: row for row in cursor.fetchall()}

        # Get hourly breakdown for successful logins
        cursor.execute("""
            SELECT
                HOUR(timestamp) as hour,
                COUNT(*) as success_count
            FROM successful_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
            GROUP BY HOUR(timestamp)
            ORDER BY hour
        """, (start_time, end_time))
        success_hourly = {row['hour']: row for row in cursor.fetchall()}

        # Combine into 24-hour breakdown
        hourly_data = []
        for hour in range(24):
            failed_data = failed_hourly.get(hour, {})
            success_data = success_hourly.get(hour, {})

            hourly_data.append({
                'hour': hour,
                'hour_label': f"{hour:02d}:00",
                'failed': failed_data.get('failed_count', 0),
                'successful': success_data.get('success_count', 0),
                'total': failed_data.get('failed_count', 0) + success_data.get('success_count', 0),
                'avg_risk': round(float(failed_data.get('avg_risk', 0) or 0), 2),
                'anomalies': failed_data.get('anomalies', 0)
            })

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'hourly_data': hourly_data
        })

    except Exception as e:
        print(f"Error in get_hourly_breakdown: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@reports_bp.route('/daily/top-threats')
@login_required
def get_top_threats():
    """
    Get top threat IPs for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
        limit: Number of results (default: 10)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        limit = int(request.args.get('limit', 10))

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                source_ip as ip,
                country,
                city,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT username) as unique_usernames,
                AVG(ml_risk_score) as avg_risk,
                MAX(ml_risk_score) as max_risk,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                MAX(ml_threat_type) as threat_type
            FROM failed_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
            GROUP BY source_ip, country, city
            ORDER BY attempt_count DESC
            LIMIT %s
        """, (start_time, end_time, limit))

        top_ips = cursor.fetchall()

        # Convert datetime to ISO format
        for ip_data in top_ips:
            if ip_data.get('first_seen'):
                ip_data['first_seen'] = ip_data['first_seen'].isoformat()
            if ip_data.get('last_seen'):
                ip_data['last_seen'] = ip_data['last_seen'].isoformat()
            ip_data['avg_risk'] = round(float(ip_data['avg_risk'] or 0), 2)
            ip_data['max_risk'] = int(ip_data['max_risk'] or 0)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'top_threats': top_ips
        })

    except Exception as e:
        print(f"Error in get_top_threats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@reports_bp.route('/daily/geographic')
@login_required
def get_geographic_breakdown():
    """
    Get geographic breakdown of attacks for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
        limit: Number of countries (default: 15)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        limit = int(request.args.get('limit', 15))

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                country,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT source_ip) as unique_ips,
                AVG(ml_risk_score) as avg_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM failed_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND country IS NOT NULL
            AND (is_simulation = FALSE OR is_simulation IS NULL)
            GROUP BY country
            ORDER BY attempt_count DESC
            LIMIT %s
        """, (start_time, end_time, limit))

        countries = cursor.fetchall()

        for country_data in countries:
            country_data['avg_risk'] = round(float(country_data['avg_risk'] or 0), 2)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'countries': countries
        })

    except Exception as e:
        print(f"Error in get_geographic_breakdown: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@reports_bp.route('/daily/usernames')
@login_required
def get_targeted_usernames_daily():
    """
    Get most targeted usernames for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
        limit: Number of results (default: 10)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        limit = int(request.args.get('limit', 10))

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                username,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT source_ip) as unique_ips,
                AVG(ml_risk_score) as avg_risk
            FROM failed_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND username IS NOT NULL
            AND (is_simulation = FALSE OR is_simulation IS NULL)
            GROUP BY username
            ORDER BY attempt_count DESC
            LIMIT %s
        """, (start_time, end_time, limit))

        usernames = cursor.fetchall()

        for username_data in usernames:
            username_data['avg_risk'] = round(float(username_data['avg_risk'] or 0), 2)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'usernames': usernames
        })

    except Exception as e:
        print(f"Error in get_targeted_usernames_daily: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@reports_bp.route('/daily/threat-types')
@login_required
def get_threat_types_breakdown():
    """
    Get threat types breakdown for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                COALESCE(ml_threat_type, 'Unknown') as threat_type,
                COUNT(*) as count,
                AVG(ml_risk_score) as avg_risk,
                COUNT(DISTINCT source_ip) as unique_ips
            FROM failed_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
            GROUP BY ml_threat_type
            ORDER BY count DESC
        """, (start_time, end_time))

        threat_types = cursor.fetchall()

        for threat_data in threat_types:
            threat_data['avg_risk'] = round(float(threat_data['avg_risk'] or 0), 2)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'threat_types': threat_types
        })

    except Exception as e:
        print(f"Error in get_threat_types_breakdown: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@reports_bp.route('/daily/comparison')
@login_required
def get_daily_comparison():
    """
    Get comparison with previous day

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        prev_date = report_date - timedelta(days=1)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Current day stats
        current_start = datetime.combine(report_date, datetime.min.time())
        current_end = datetime.combine(report_date, datetime.max.time())

        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                COUNT(DISTINCT source_ip) as unique_ips
            FROM failed_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
        """, (current_start, current_end))
        current_stats = cursor.fetchone()

        # Previous day stats
        prev_start = datetime.combine(prev_date, datetime.min.time())
        prev_end = datetime.combine(prev_date, datetime.max.time())

        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                COUNT(DISTINCT source_ip) as unique_ips
            FROM failed_logins
            WHERE timestamp >= %s AND timestamp <= %s
            AND (is_simulation = FALSE OR is_simulation IS NULL)
        """, (prev_start, prev_end))
        prev_stats = cursor.fetchone()

        # Calculate changes
        def calc_change(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)

        comparison = {
            'current_date': report_date.isoformat(),
            'previous_date': prev_date.isoformat(),
            'current': {
                'total_events': current_stats['total_events'] or 0,
                'high_risk': current_stats['high_risk'] or 0,
                'unique_ips': current_stats['unique_ips'] or 0
            },
            'previous': {
                'total_events': prev_stats['total_events'] or 0,
                'high_risk': prev_stats['high_risk'] or 0,
                'unique_ips': prev_stats['unique_ips'] or 0
            },
            'changes': {
                'total_events': calc_change(
                    current_stats['total_events'] or 0,
                    prev_stats['total_events'] or 0
                ),
                'high_risk': calc_change(
                    current_stats['high_risk'] or 0,
                    prev_stats['high_risk'] or 0
                ),
                'unique_ips': calc_change(
                    current_stats['unique_ips'] or 0,
                    prev_stats['unique_ips'] or 0
                )
            }
        }

        return jsonify({
            'success': True,
            'comparison': comparison
        })

    except Exception as e:
        print(f"Error in get_daily_comparison: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@reports_bp.route('/daily/available-dates')
@login_required
def get_available_dates():
    """
    Get list of dates that have data available

    Query Parameters:
        limit: Number of dates to return (default: 30)
    """
    conn = None
    cursor = None
    try:
        limit = int(request.args.get('limit', 30))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT DATE(timestamp) as date, COUNT(*) as event_count
            FROM failed_logins
            WHERE (is_simulation = FALSE OR is_simulation IS NULL)
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
            LIMIT %s
        """, (limit,))

        dates = cursor.fetchall()

        for date_data in dates:
            date_data['date'] = date_data['date'].isoformat()

        return jsonify({
            'success': True,
            'dates': dates
        })

    except Exception as e:
        print(f"Error in get_available_dates: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
