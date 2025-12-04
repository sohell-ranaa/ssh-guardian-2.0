"""
Attack Simulator - Main simulation execution engine
Generates realistic attack scenarios and processes them through the Guardian pipeline
"""

import json
import time
import requests
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import sys
import random
import os

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from .templates import ATTACK_TEMPLATES
from .ip_pools import get_pool_manager

# Import Telegram alerting
from src.intelligence.smart_alerting import SmartAlertManager


class SimulationLogger:
    """Handles verbose logging for simulation execution"""

    def __init__(self, simulation_id: int):
        self.simulation_id = simulation_id
        self.sequence = 0
        self.logs = []
        self.conn = get_connection()

    def log(self, stage: str, message: str, level: str = "INFO", metadata: Optional[Dict] = None):
        """
        Log a simulation step

        Args:
            stage: Pipeline stage (submission, geoip, ml, blocking, telegram)
            message: Log message
            level: Log level (INFO, SUCCESS, WARNING, ERROR, DEBUG)
            metadata: Additional structured data
        """
        self.sequence += 1
        timestamp = datetime.now()

        log_entry = {
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'sequence': self.sequence,
            'stage': stage,
            'level': level,
            'message': message,
            'metadata': metadata or {}
        }

        self.logs.append(log_entry)

        # Store in database
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO simulation_logs
                (simulation_id, timestamp, sequence_number, stage, level, message, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                self.simulation_id,
                timestamp,
                self.sequence,
                stage,
                level,
                message,
                json.dumps(metadata) if metadata else None
            ))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            print(f"❌ Error storing log: {e}")

        # Also print to console
        level_emoji = {
            'INFO': 'ℹ️',
            'SUCCESS': '✅',
            'WARNING': '⚠️',
            'ERROR': '❌',
            'DEBUG': '🔍'
        }
        emoji = level_emoji.get(level, 'ℹ️')
        print(f"{emoji} [{stage}] {message}")

    def get_logs(self) -> List[Dict]:
        """Get all logs for this simulation"""
        return self.logs

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


class AttackSimulator:
    """Main simulator class that executes attack scenarios"""

    def __init__(self, guardian_api_url: str = "http://localhost:5000"):
        self.guardian_api_url = guardian_api_url
        self.ip_pool_manager = get_pool_manager()

        # Initialize Telegram alert manager
        self.alert_manager = None
        try:
            from dotenv import load_dotenv
            load_dotenv(PROJECT_ROOT / '.env')

            telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
            telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')

            if telegram_bot_token and telegram_chat_id:
                self.alert_manager = SmartAlertManager(
                    telegram_bot_token=telegram_bot_token,
                    telegram_chat_id=telegram_chat_id,
                    enable_smart_grouping=True
                )
                print("✅ Telegram alerting enabled for simulations")
            else:
                print("⚠️ Telegram credentials not found - alerts disabled")
        except Exception as e:
            print(f"⚠️ Could not initialize Telegram alerts: {e}")

    def execute(self, template_name: str, custom_params: Optional[Dict] = None,
                user_id: Optional[int] = None, user_email: Optional[str] = None) -> Dict:
        """
        Execute a simulation based on template

        Args:
            template_name: Name of attack template
            custom_params: Override template parameters
            user_id: User executing the simulation
            user_email: User's email

        Returns:
            Simulation result summary
        """
        # Get template
        if template_name not in ATTACK_TEMPLATES:
            raise ValueError(f"Unknown template: {template_name}")

        template = ATTACK_TEMPLATES[template_name]
        params = template['template'].copy()

        # Override with custom params
        if custom_params:
            params.update(custom_params)

        # Create simulation record
        simulation_id = self._create_simulation_record(
            template_name=template_name,
            template_display_name=template['name'],
            request_json=params,
            user_id=user_id,
            user_email=user_email
        )

        # Initialize logger
        logger = SimulationLogger(simulation_id)

        try:
            logger.log('INIT', f"🚀 Starting simulation: {template['name']}", 'INFO', {
                'template': template_name,
                'user': user_email
            })

            # Process template and generate events
            events = self._generate_events(params, logger)

            logger.log('GENERATION', f"Generated {len(events)} events for simulation", 'SUCCESS', {
                'event_count': len(events)
            })

            # Submit events to Guardian API
            results = self._submit_events(events, simulation_id, logger)

            # Track outcomes
            summary = self._analyze_results(results, logger, simulation_id)

            # Update simulation record
            self._complete_simulation(simulation_id, summary, logger)

            logger.log('COMPLETE', f"✨ Simulation completed successfully", 'SUCCESS', summary)

            return {
                'simulation_id': simulation_id,
                'status': 'completed',
                'summary': summary,
                'logs': logger.get_logs()
            }

        except Exception as e:
            error_msg = f"Simulation failed: {str(e)}"
            logger.log('ERROR', error_msg, 'ERROR', {'exception': str(e)})
            self._fail_simulation(simulation_id, error_msg)
            raise

        finally:
            logger.close()

    def _create_simulation_record(self, template_name: str, template_display_name: str,
                                   request_json: Dict, user_id: Optional[int],
                                   user_email: Optional[str]) -> int:
        """Create initial simulation record in database"""
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO simulation_history
            (user_id, user_email, template_name, template_display_name, request_json, status)
            VALUES (%s, %s, %s, %s, %s, 'running')
        """, (user_id, user_email, template_name, template_display_name, json.dumps(request_json)))

        conn.commit()
        simulation_id = cursor.lastrowid
        cursor.close()
        conn.close()

        return simulation_id

    def _generate_events(self, params: Dict, logger: SimulationLogger) -> List[Dict]:
        """Generate SSH log events based on parameters"""
        events = []

        # Parse IP allocation
        source_ips = self._parse_ip_parameter(params.get('source_ip', '192.168.1.1'), logger)

        # Parse username(s)
        usernames = params.get('username')
        if isinstance(usernames, str):
            usernames = [usernames]
        elif not isinstance(usernames, list):
            usernames = ['root']

        # Determine number of attempts
        if 'attempts' in params:
            total_attempts = params['attempts']
            attempts_per_ip = total_attempts // len(source_ips) if len(source_ips) > 1 else total_attempts
        elif 'attempts_per_ip' in params:
            attempts_per_ip = params['attempts_per_ip']
            total_attempts = attempts_per_ip * len(source_ips)
        elif 'attempts_per_user' in params:
            attempts_per_user = params['attempts_per_user']
            total_attempts = attempts_per_user * len(usernames)
            attempts_per_ip = total_attempts // len(source_ips)
        else:
            attempts_per_ip = 1
            total_attempts = len(source_ips)

        logger.log('PLANNING', f"Will generate {total_attempts} events from {len(source_ips)} IPs", 'INFO', {
            'ips': len(source_ips),
            'total_attempts': total_attempts
        })

        # Time distribution
        time_window = params.get('time_window_seconds', 60)
        start_time = datetime.now() - timedelta(seconds=time_window)

        # Generate events
        event_count = 0
        for ip in source_ips:
            for attempt in range(attempts_per_ip):
                # Select username (rotate through list)
                username = usernames[event_count % len(usernames)]

                # Calculate timestamp (distributed across time window)
                timestamp_offset = (event_count / total_attempts) * time_window
                timestamp = start_time + timedelta(seconds=timestamp_offset)

                # Build event
                event = self._build_ssh_log_event(
                    event_type=params.get('event_type', 'failed'),
                    source_ip=ip,
                    username=username,
                    server_hostname=params.get('server_hostname', 'simulation-server'),
                    port=params.get('port', 22),
                    timestamp=timestamp,
                    failure_reason=params.get('failure_reason', 'invalid_password'),
                    session_duration=params.get('session_duration'),
                    auth_method=params.get('auth_method', 'password')
                )

                events.append(event)
                event_count += 1

        return events

    def _parse_ip_parameter(self, ip_param: str, logger: SimulationLogger) -> List[str]:
        """
        Parse IP parameter which can be:
        - <from_pool:malicious> - single malicious IP
        - <from_pool:malicious:multiple:5> - 5 malicious IPs
        - <from_pool:trusted>
        - <from_pool:random>
        - 192.168.1.1 - specific IP
        """
        if not isinstance(ip_param, str):
            return [str(ip_param)]

        if ip_param.startswith('<from_pool:'):
            # Parse pool directive
            parts = ip_param.strip('<>').split(':')
            pool_type = parts[1]  # malicious, trusted, or random

            count = 1
            if len(parts) >= 4 and parts[2] == 'multiple':
                count = int(parts[3])

            logger.log('IP_POOL', f"Fetching {count} IP(s) from {pool_type} pool", 'INFO')

            ips = self.ip_pool_manager.get_ips(pool_type, count)

            logger.log('IP_POOL', f"Selected IPs: {', '.join(ips)}", 'SUCCESS', {
                'ips': ips,
                'pool_type': pool_type
            })

            return ips
        else:
            # Specific IP provided
            return [ip_param]

    def _build_ssh_log_event(self, event_type: str, source_ip: str, username: str,
                              server_hostname: str, port: int, timestamp: datetime,
                              failure_reason: Optional[str] = None,
                              session_duration: Optional[int] = None,
                              auth_method: str = 'password') -> Dict:
        """Build SSH log event in Guardian-compatible format"""
        event = {
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'server_hostname': server_hostname,
            'source_ip': source_ip,
            'username': username,
            'port': port,
            'event_type': event_type,
            'auth_method': auth_method,
            'is_simulation': True  # Mark as simulation
        }

        if event_type == 'failed':
            event['failure_reason'] = failure_reason or 'invalid_password'
        elif event_type == 'successful':
            event['session_duration'] = session_duration or 3600

        return event

    def _submit_events(self, events: List[Dict], simulation_id: int,
                       logger: SimulationLogger) -> List[Dict]:
        """Submit events to Guardian API and track processing"""
        results = []

        for idx, event in enumerate(events, 1):
            logger.log('SUBMISSION', f"📤 Submitting event {idx}/{len(events)} - {event['source_ip']} → {event['username']}", 'INFO', {
                'event_number': idx,
                'ip': event['source_ip'],
                'username': event['username']
            })

            try:
                # Add simulation metadata
                event['simulation_id'] = simulation_id

                # Submit to Guardian API
                response = requests.post(
                    f"{self.guardian_api_url}/logs/upload",
                    json={'logs': [event]},
                    timeout=30
                )

                if response.status_code == 200:
                    logger.log('SUBMISSION', f"✅ Event {idx} accepted by Guardian API", 'SUCCESS')

                    # Give Guardian time to process
                    time.sleep(0.5)

                    # Track the processing pipeline
                    self._track_event_processing(event, simulation_id, logger)

                    results.append({
                        'event': event,
                        'status': 'success',
                        'response': response.json() if response.content else {}
                    })
                else:
                    logger.log('SUBMISSION', f"⚠️ Event {idx} rejected: {response.status_code}", 'WARNING', {
                        'status_code': response.status_code,
                        'response': response.text
                    })
                    results.append({
                        'event': event,
                        'status': 'failed',
                        'error': f"HTTP {response.status_code}"
                    })

            except Exception as e:
                logger.log('SUBMISSION', f"❌ Error submitting event {idx}: {str(e)}", 'ERROR')
                results.append({
                    'event': event,
                    'status': 'error',
                    'error': str(e)
                })

        return results

    def _track_event_processing(self, event: Dict, simulation_id: int, logger: SimulationLogger):
        """Track event through Guardian's processing pipeline"""
        source_ip = event['source_ip']
        username = event['username']

        # Query database to check processing stages
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Wait a bit for processing to complete
        time.sleep(2)

        try:
            # Find the event in database
            table_name = 'failed_logins' if event['event_type'] == 'failed' else 'successful_logins'

            cursor.execute(f"""
                SELECT * FROM {table_name}
                WHERE source_ip = %s AND username = %s AND is_simulation = TRUE
                ORDER BY id DESC LIMIT 1
            """, (source_ip, username))

            record = cursor.fetchone()

            if record:
                logger.log('PIPELINE', f"📊 Event found in database (ID: {record['id']})", 'INFO')

                # Check GeoIP processing
                if record.get('geoip_processed'):
                    logger.log('GEOIP', f"🌍 GeoIP enrichment completed: {record.get('country', 'Unknown')}, {record.get('city', 'Unknown')}", 'SUCCESS', {
                        'country': record.get('country'),
                        'city': record.get('city'),
                        'latitude': record.get('latitude'),
                        'longitude': record.get('longitude')
                    })
                else:
                    logger.log('GEOIP', f"⏳ GeoIP processing pending", 'INFO')

                # Check IP health processing
                if record.get('ip_health_processed'):
                    logger.log('IP_HEALTH', f"🔍 IP reputation check completed: {record.get('ip_reputation', 'unknown')}", 'SUCCESS', {
                        'reputation': record.get('ip_reputation'),
                        'risk_score': record.get('ip_risk_score')
                    })
                else:
                    logger.log('IP_HEALTH', f"⏳ IP health check pending", 'INFO')

                # Check ML processing
                if record.get('ml_processed'):
                    ml_score = record.get('ml_risk_score', 0)
                    ml_type = record.get('ml_threat_type', 'unknown')
                    is_anomaly = record.get('is_anomaly', False)

                    logger.log('ML_ANALYSIS', f"🤖 ML analysis completed: Risk={ml_score}, Type={ml_type}, Anomaly={is_anomaly}", 'SUCCESS', {
                        'risk_score': ml_score,
                        'threat_type': ml_type,
                        'is_anomaly': is_anomaly,
                        'confidence': record.get('ml_confidence')
                    })

                    # Check if blocking should occur
                    if ml_score >= 70:
                        logger.log('DECISION', f"⚠️ High risk detected (score={ml_score}), IP should be blocked", 'WARNING')
                        self._check_ip_blocking(source_ip, logger)
                    else:
                        logger.log('DECISION', f"✅ Risk acceptable (score={ml_score}), no blocking needed", 'INFO')
                else:
                    logger.log('ML_ANALYSIS', f"⏳ ML analysis pending", 'INFO')

                # Check pipeline completion
                if record.get('pipeline_completed'):
                    logger.log('PIPELINE', f"✅ Full pipeline completed for this event", 'SUCCESS')
                else:
                    logger.log('PIPELINE', f"⏳ Pipeline still processing...", 'INFO')

            else:
                logger.log('PIPELINE', f"⚠️ Event not yet visible in database (may be in queue)", 'WARNING')

        except Exception as e:
            logger.log('PIPELINE', f"❌ Error tracking pipeline: {str(e)}", 'ERROR')
        finally:
            cursor.close()
            conn.close()

    def _check_ip_blocking(self, ip: str, logger: SimulationLogger):
        """Check if IP was actually blocked"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM ip_blocks
                WHERE ip_address = %s AND is_active = TRUE
                ORDER BY id DESC LIMIT 1
            """, (ip,))

            block = cursor.fetchone()

            if block:
                logger.log('BLOCKING', f"🚫 IP {ip} successfully blocked via iptables", 'SUCCESS', {
                    'ip': ip,
                    'reason': block.get('block_reason'),
                    'duration': block.get('block_source'),
                    'blocked_at': str(block.get('blocked_at'))
                })

                # Send Telegram alert if alert manager is available
                if self.alert_manager:
                    try:
                        # Get the event that triggered this block
                        cursor.execute("""
                            SELECT * FROM failed_logins
                            WHERE source_ip = %s AND is_simulation = TRUE
                            ORDER BY id DESC LIMIT 1
                        """, (ip,))

                        event = cursor.fetchone()

                        if event:
                            # Create alert data in format expected by SmartAlertManager
                            event_data = {
                                'source_ip': ip,
                                'username': event.get('username', 'unknown'),
                                'server_hostname': event.get('server_hostname', 'simulation-server'),
                                'event_type': 'failed',
                                'country': event.get('country', 'Unknown')
                            }

                            guardian_result = {
                                'threat_detected': 'simulation_attack',
                                'overall_risk_score': event.get('ml_risk_score', 85),
                                'threat_level': 'high',
                                'recommended_actions': [
                                    f"IP {ip} blocked by iptables",
                                    "Review simulation results in dashboard",
                                    "[SIMULATION MODE - Test Alert]"
                                ]
                            }

                            # Trigger the alert
                            self.alert_manager.add_alert(event_data, guardian_result)
                            logger.log('TELEGRAM', f"📱 Telegram alert sent for blocked IP {ip}", 'SUCCESS')
                        else:
                            logger.log('TELEGRAM', f"⚠️ Could not find event data for alert", 'WARNING')

                    except Exception as e:
                        logger.log('TELEGRAM', f"❌ Failed to send Telegram alert: {str(e)}", 'ERROR')
                else:
                    logger.log('TELEGRAM', f"ℹ️ Telegram alerts disabled (no credentials configured)", 'INFO')
            else:
                logger.log('BLOCKING', f"ℹ️ IP {ip} not blocked (may be below threshold or whitelisted)", 'INFO')

        except Exception as e:
            logger.log('BLOCKING', f"❌ Error checking IP blocks: {str(e)}", 'ERROR')
        finally:
            cursor.close()
            conn.close()

    def _analyze_results(self, results: List[Dict], logger: SimulationLogger, simulation_id: int) -> Dict:
        """Analyze simulation results"""
        logger.log('ANALYSIS', f"📊 Analyzing simulation results...", 'INFO')

        successful_submissions = len([r for r in results if r['status'] == 'success'])
        failed_submissions = len([r for r in results if r['status'] != 'success'])

        # Query database for outcomes
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get blocked IPs list (distinct IPs in order of first block)
            cursor.execute("""
                SELECT ip_address
                FROM ip_blocks
                WHERE is_simulation = TRUE AND simulation_id = %s
                GROUP BY ip_address
                ORDER BY MIN(blocked_at) DESC
            """, (simulation_id,))
            blocked_ips = [row['ip_address'] for row in cursor.fetchall()]
            blocked_count = len(blocked_ips)

            # Count events by risk level
            cursor.execute("""
                SELECT
                    COUNT(*) as high_risk_count
                FROM (
                    SELECT ml_risk_score FROM failed_logins WHERE simulation_id = %s
                    UNION ALL
                    SELECT ml_risk_score FROM successful_logins WHERE simulation_id = %s
                ) as all_events
                WHERE ml_risk_score >= 70
            """, (simulation_id, simulation_id))
            high_risk_count = cursor.fetchone()['high_risk_count']

            summary = {
                'total_events': len(results),
                'successful_submissions': successful_submissions,
                'failed_submissions': failed_submissions,
                'ips_blocked': blocked_count,
                'blocked_ips': blocked_ips,  # Add list of blocked IPs
                'high_risk_events': high_risk_count,
                'completion_rate': (successful_submissions / len(results) * 100) if results else 0
            }

            logger.log('ANALYSIS', f"📈 Results: {successful_submissions}/{len(results)} events processed, {blocked_count} IPs blocked", 'SUCCESS', summary)

            return summary

        except Exception as e:
            logger.log('ANALYSIS', f"❌ Error analyzing results: {str(e)}", 'ERROR')
            return {
                'total_events': len(results),
                'successful_submissions': successful_submissions,
                'failed_submissions': failed_submissions,
                'error': str(e)
            }
        finally:
            cursor.close()
            conn.close()

    def _complete_simulation(self, simulation_id: int, summary: Dict, logger: SimulationLogger):
        """Mark simulation as completed"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE simulation_history
                SET status = 'completed',
                    completed_at = NOW(),
                    duration_seconds = TIMESTAMPDIFF(SECOND, created_at, NOW()),
                    total_events = %s,
                    events_processed = %s,
                    ips_blocked = %s
                WHERE id = %s
            """, (
                summary.get('total_events', 0),
                summary.get('successful_submissions', 0),
                summary.get('ips_blocked', 0),
                simulation_id
            ))
            conn.commit()
        except Exception as e:
            logger.log('ERROR', f"Failed to update simulation record: {str(e)}", 'ERROR')
        finally:
            cursor.close()
            conn.close()

    def _fail_simulation(self, simulation_id: int, error_message: str):
        """Mark simulation as failed"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE simulation_history
                SET status = 'failed',
                    completed_at = NOW(),
                    error_message = %s,
                    duration_seconds = TIMESTAMPDIFF(SECOND, created_at, NOW())
                WHERE id = %s
            """, (error_message, simulation_id))
            conn.commit()
        except Exception as e:
            print(f"❌ Failed to update simulation record: {e}")
        finally:
            cursor.close()
            conn.close()

    def get_simulation_logs(self, simulation_id: int) -> List[Dict]:
        """Retrieve logs for a specific simulation"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM simulation_logs
                WHERE simulation_id = %s
                ORDER BY sequence_number ASC
            """, (simulation_id,))

            logs = cursor.fetchall()

            # Parse JSON metadata
            for log in logs:
                if log.get('metadata'):
                    try:
                        log['metadata'] = json.loads(log['metadata'])
                    except:
                        pass

            return logs

        finally:
            cursor.close()
            conn.close()
