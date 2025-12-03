"""
Smart Telegram Alerting System
Aggregates and prioritizes alerts to avoid message bombardment
"""

import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List
from collections import defaultdict
from dataclasses import dataclass, field
import threading
import logging

logger = logging.getLogger(__name__)

@dataclass
class Alert:
    """Individual alert"""
    timestamp: datetime
    source_ip: str
    username: str
    server: str
    threat_type: str
    risk_score: int
    severity: str
    details: Dict = field(default_factory=dict)

@dataclass
class AlertDigest:
    """Aggregated alert summary"""
    start_time: datetime
    end_time: datetime
    total_events: int
    unique_ips: set = field(default_factory=set)
    unique_servers: set = field(default_factory=set)
    by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_threat_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_attackers: List[tuple] = field(default_factory=list)
    critical_alerts: List[Alert] = field(default_factory=list)

class SmartAlertManager:
    """
    Intelligent alert aggregation system that prevents Telegram spam
    """

    # Severity thresholds
    SEVERITY_THRESHOLDS = {
        'info': (0, 39),
        'low': (40, 59),
        'medium': (60, 74),
        'high': (75, 89),
        'critical': (90, 100)
    }

    # Alert rules
    ALERT_RULES = {
        'critical_immediate': {
            'min_risk_score': 90,
            'send_immediately': True,
            'description': 'Critical threat detected'
        },
        'high_immediate': {
            'min_risk_score': 85,
            'max_delay_seconds': 60,
            'description': 'High-risk threat requires attention'
        },
        'medium_batched': {
            'min_risk_score': 70,
            'batch_interval_minutes': 15,
            'description': 'Medium threats - batched alerts'
        },
        'low_digest': {
            'min_risk_score': 50,
            'digest_interval_minutes': 60,
            'description': 'Low threats - hourly digest'
        },
        'info_daily': {
            'min_risk_score': 0,
            'digest_interval_hours': 24,
            'description': 'Daily security summary'
        }
    }

    def __init__(self, telegram_bot_token: str, telegram_chat_id: str,
                 enable_smart_grouping: bool = True):
        self.bot_token = telegram_bot_token
        self.chat_id = telegram_chat_id
        self.enable_smart_grouping = enable_smart_grouping

        # Alert buffers
        self.pending_alerts = []
        self.alert_history = []
        self.last_digest_time = datetime.now()
        self.last_batch_time = datetime.now()

        # Deduplication tracking
        self.seen_events = {}  # key: (ip, server, threat), value: last_seen_time
        self.attack_campaigns = defaultdict(list)  # Track ongoing campaigns

        # Statistics
        self.stats = {
            'total_alerts_generated': 0,
            'total_messages_sent': 0,
            'alerts_batched': 0,
            'alerts_deduplicated': 0
        }

        # Thread safety
        self.lock = threading.Lock()

        # Start background processor
        if enable_smart_grouping:
            self.processor_thread = threading.Thread(target=self._process_pending_alerts, daemon=True)
            self.processor_thread.start()

    def get_severity(self, risk_score: int) -> str:
        """Determine severity level from risk score"""
        for severity, (min_score, max_score) in self.SEVERITY_THRESHOLDS.items():
            if min_score <= risk_score <= max_score:
                return severity
        return 'info'

    def should_send_immediately(self, alert: Alert) -> bool:
        """Determine if alert should be sent immediately"""
        # Critical alerts always immediate
        if alert.risk_score >= 90:
            return True

        # High severity within threshold
        if alert.risk_score >= 85:
            return True

        # Successful breaches always immediate
        if alert.threat_type == 'intrusion' and alert.risk_score >= 80:
            return True

        return False

    def is_duplicate(self, alert: Alert, time_window_minutes: int = 10) -> bool:
        """Check if alert is a duplicate within time window"""
        key = (alert.source_ip, alert.server, alert.threat_type)
        now = datetime.now()

        if key in self.seen_events:
            last_seen = self.seen_events[key]
            if (now - last_seen).total_seconds() < time_window_minutes * 60:
                return True

        self.seen_events[key] = now
        return False

    def add_alert(self, event: Dict, guardian_result: Dict):
        """Add new alert to the system"""
        with self.lock:
            alert = Alert(
                timestamp=datetime.now(),
                source_ip=event.get('source_ip', 'unknown'),
                username=event.get('username', 'unknown'),
                server=event.get('server_hostname', 'unknown'),
                threat_type=guardian_result.get('threat_detected', 'unknown'),
                risk_score=guardian_result.get('overall_risk_score', 0),
                severity=self.get_severity(guardian_result.get('overall_risk_score', 0)),
                details={
                    'event_type': event.get('event_type', 'unknown'),
                    'country': event.get('country', 'unknown'),
                    'threat_level': guardian_result.get('threat_level', 'unknown'),
                    'actions': guardian_result.get('recommended_actions', [])
                }
            )

            self.stats['total_alerts_generated'] += 1

            # Check if should send immediately
            if self.should_send_immediately(alert):
                self._send_immediate_alert(alert)
                return

            # Check for duplicates
            if self.is_duplicate(alert):
                self.stats['alerts_deduplicated'] += 1
                logger.debug(f"Duplicate alert suppressed: {alert.source_ip}")
                return

            # Add to pending queue
            self.pending_alerts.append(alert)
            self.stats['alerts_batched'] += 1

            # Track attack campaigns
            campaign_key = (alert.source_ip, alert.server)
            self.attack_campaigns[campaign_key].append(alert)

    def _send_immediate_alert(self, alert: Alert):
        """Send immediate critical/high alert"""
        emoji_map = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': '🔍',
            'info': 'ℹ️'
        }

        emoji = emoji_map.get(alert.severity, '⚠️')

        # Escape special Markdown characters to avoid parsing errors
        def escape_md(text):
            """Escape special characters for Telegram Markdown"""
            if not text:
                return text
            special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
            for char in special_chars:
                text = str(text).replace(char, f'\\{char}')
            return text

        message = f"{emoji} *{alert.severity.upper()} SECURITY ALERT*\n\n"
        message += f"*Threat:* {escape_md(alert.threat_type)}\n"
        message += f"*Risk Score:* {alert.risk_score}/100\n\n"
        message += f"*Attacker:* {alert.source_ip}\n"  # IPs are safe, no need to escape
        message += f"*Target:* {escape_md(alert.server)}\n"
        message += f"*User:* {escape_md(alert.username)}\n"
        message += f"*Location:* {escape_md(alert.details.get('country', 'Unknown'))}\n\n"

        if alert.details.get('actions'):
            message += "*Recommended Actions:*\n"
            for action in alert.details['actions'][:3]:
                message += f"• {escape_md(action)}\n"

        message += f"\n🕐 {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

        self._send_telegram_message(message)

    def _process_pending_alerts(self):
        """Background thread to process pending alerts"""
        while True:
            try:
                time.sleep(30)  # Check every 30 seconds

                with self.lock:
                    now = datetime.now()

                    # Send batched alerts every 15 minutes for medium severity
                    if (now - self.last_batch_time).total_seconds() >= 900:  # 15 min
                        self._send_batch_alert()
                        self.last_batch_time = now

                    # Send digest every hour
                    if (now - self.last_digest_time).total_seconds() >= 3600:  # 1 hour
                        self._send_digest_alert()
                        self.last_digest_time = now

            except Exception as e:
                logger.error(f"Error in alert processor: {e}")

    def _send_batch_alert(self):
        """Send batched medium-priority alerts"""
        if not self.pending_alerts:
            return

        # Group by severity
        by_severity = defaultdict(list)
        for alert in self.pending_alerts:
            by_severity[alert.severity].append(alert)

        # Send medium/high batches
        for severity in ['high', 'medium']:
            alerts = by_severity.get(severity, [])
            if alerts:
                message = f"⚡ *{severity.upper()} PRIORITY BATCH ALERT*\n\n"
                message += f"*{len(alerts)} threats detected in last 15 minutes*\n\n"

                # Group by IP
                by_ip = defaultdict(list)
                for alert in alerts:
                    by_ip[alert.source_ip].append(alert)

                # Top 5 attackers
                top_attackers = sorted(by_ip.items(), key=lambda x: len(x[1]), reverse=True)[:5]

                for ip, ip_alerts in top_attackers:
                    message += f"📍 `{ip}` - {len(ip_alerts)} attempts\n"
                    message += f"   Servers: {', '.join(set(a.server for a in ip_alerts[:3]))}\n"

                message += f"\n📊 Use dashboard for full details"

                self._send_telegram_message(message)

                # Remove sent alerts
                alert_ids = set(id(a) for a in alerts)
                self.pending_alerts = [a for a in self.pending_alerts if id(a) not in alert_ids]

    def _send_digest_alert(self):
        """Send hourly digest of low-priority alerts"""
        if not self.pending_alerts:
            return

        digest = AlertDigest(
            start_time=self.last_digest_time,
            end_time=datetime.now(),
            total_events=len(self.pending_alerts)
        )

        # Analyze alerts
        for alert in self.pending_alerts:
            digest.unique_ips.add(alert.source_ip)
            digest.unique_servers.add(alert.server)
            digest.by_severity[alert.severity] += 1
            digest.by_threat_type[alert.threat_type] += 1

        # Top attackers
        ip_counts = defaultdict(int)
        for alert in self.pending_alerts:
            ip_counts[alert.source_ip] += 1
        digest.top_attackers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Build message
        message = f"📊 *HOURLY SECURITY DIGEST*\n\n"
        message += f"Period: {digest.start_time.strftime('%H:%M')} - {digest.end_time.strftime('%H:%M')}\n\n"
        message += f"*Summary:*\n"
        message += f"• Total Events: {digest.total_events}\n"
        message += f"• Unique IPs: {len(digest.unique_ips)}\n"
        message += f"• Servers Targeted: {len(digest.unique_servers)}\n\n"

        if digest.by_severity:
            message += "*By Severity:*\n"
            for sev in ['medium', 'low', 'info']:
                if sev in digest.by_severity:
                    message += f"• {sev.title()}: {digest.by_severity[sev]}\n"
            message += "\n"

        if digest.top_attackers:
            message += "*Top Attackers:*\n"
            for ip, count in digest.top_attackers:
                message += f"• `{ip}` - {count} attempts\n"

        message += f"\n🔗 View dashboard for details"

        self._send_telegram_message(message)

        # Clear pending alerts
        self.pending_alerts.clear()

    def send_daily_summary(self, stats: Dict):
        """Send daily summary with analytics"""
        message = f"📈 *DAILY SECURITY SUMMARY*\n\n"
        message += f"Date: {datetime.now().strftime('%Y-%m-%d')}\n\n"

        message += f"*Events Processed:* {stats.get('total_events', 0):,}\n"
        message += f"*Threats Detected:* {stats.get('threats_detected', 0):,}\n"
        message += f"*IPs Blocked:* {stats.get('ips_blocked', 0)}\n"
        message += f"*Successful Logins:* {stats.get('successful_logins', 0):,}\n"
        message += f"*Failed Attempts:* {stats.get('failed_attempts', 0):,}\n\n"

        if stats.get('top_threat_types'):
            message += "*Top Threat Types:*\n"
            for threat, count in stats['top_threat_types'][:5]:
                message += f"• {threat}: {count}\n"
            message += "\n"

        if stats.get('top_countries'):
            message += "*Attack Sources:*\n"
            for country, count in stats['top_countries'][:5]:
                message += f"• {country}: {count}\n"

        message += f"\n📊 System Health: ✅ Operational"
        message += f"\n🔗 Access dashboard for detailed analytics"

        self._send_telegram_message(message)

    def _send_telegram_message(self, message: str):
        """Send message to Telegram"""
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'Markdown',
                'disable_web_page_preview': True
            }

            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                self.stats['total_messages_sent'] += 1
                logger.info(f"Telegram alert sent successfully")
            else:
                logger.error(f"Telegram send failed: {response.status_code} - {response.text}")

        except Exception as e:
            logger.error(f"Telegram error: {e}")

    def get_statistics(self) -> Dict:
        """Get alert statistics"""
        with self.lock:
            return {
                'total_alerts_generated': self.stats['total_alerts_generated'],
                'total_messages_sent': self.stats['total_messages_sent'],
                'alerts_batched': self.stats['alerts_batched'],
                'alerts_deduplicated': self.stats['alerts_deduplicated'],
                'pending_alerts': len(self.pending_alerts),
                'active_campaigns': len(self.attack_campaigns),
                'compression_ratio': f"{self.stats['total_messages_sent']}/{self.stats['total_alerts_generated']}" if self.stats['total_alerts_generated'] > 0 else "0/0"
            }
