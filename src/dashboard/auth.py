"""
SSH Guardian 2.0 - Authentication System
RBAC with password + OTP, session management, and email integration
"""

import os
import sys
import secrets
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session
import bcrypt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

# Email configuration
EMAIL_CONFIG = {
    'smtp_host': os.getenv('SMTP_HOST', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', 587)),
    'smtp_user': os.getenv('SMTP_USER', '').strip('"'),
    'smtp_password': os.getenv('SMTP_PASSWORD', '').strip('"'),
    'from_email': os.getenv('FROM_EMAIL', '').strip('"'),
    'from_name': os.getenv('FROM_NAME', 'SSH Guardian')
}

# Session configuration
SESSION_DURATION_DAYS = 30  # Remember me for 30 days
OTP_VALIDITY_MINUTES = 5
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


class AuthenticationError(Exception):
    """Base exception for authentication errors"""
    pass


class EmailService:
    """Email service for sending OTPs and notifications"""

    @staticmethod
    def send_email(to_email, subject, body_html, body_text=None):
        """Send email using SMTP"""
        try:
            if not EMAIL_CONFIG['smtp_user'] or not EMAIL_CONFIG['smtp_password']:
                print(f"⚠️  Email not configured. OTP for {to_email}: Would send email")
                print(f"   Subject: {subject}")
                print(f"   Body: {body_text or 'See HTML body'}")
                return True

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{EMAIL_CONFIG['from_name']} <{EMAIL_CONFIG['from_email']}>"
            msg['To'] = to_email

            if body_text:
                part1 = MIMEText(body_text, 'plain')
                msg.attach(part1)

            part2 = MIMEText(body_html, 'html')
            msg.attach(part2)

            with smtplib.SMTP(EMAIL_CONFIG['smtp_host'], EMAIL_CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['smtp_user'], EMAIL_CONFIG['smtp_password'])
                server.send_message(msg)

            return True

        except Exception as e:
            print(f"❌ Email send error: {e}")
            return False

    @staticmethod
    def send_otp_email(to_email, otp_code, full_name):
        """Send OTP email"""
        subject = "SSH Guardian - Your Login OTP"

        body_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                           color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f7f7f7; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-code {{ font-size: 32px; font-weight: bold; color: #667eea;
                            letter-spacing: 8px; text-align: center; padding: 20px;
                            background: white; border-radius: 8px; margin: 20px 0; }}
                .warning {{ color: #e74c3c; font-size: 14px; margin-top: 20px; }}
                .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ SSH Guardian</h1>
                    <p>Security Dashboard Login</p>
                </div>
                <div class="content">
                    <p>Hello <strong>{full_name}</strong>,</p>
                    <p>Your One-Time Password (OTP) for logging into SSH Guardian is:</p>
                    <div class="otp-code">{otp_code}</div>
                    <p><strong>This OTP is valid for {OTP_VALIDITY_MINUTES} minutes.</strong></p>
                    <p>If you didn't request this OTP, please ignore this email and ensure your account is secure.</p>
                    <div class="warning">
                        ⚠️ Never share this OTP with anyone. SSH Guardian will never ask for your OTP via phone or email.
                    </div>
                </div>
                <div class="footer">
                    <p>SSH Guardian 2.0 - Advanced SSH Security Monitoring System</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        body_text = f"""
        SSH Guardian - Your Login OTP

        Hello {full_name},

        Your One-Time Password (OTP) for logging into SSH Guardian is:

        {otp_code}

        This OTP is valid for {OTP_VALIDITY_MINUTES} minutes.

        If you didn't request this OTP, please ignore this email.

        Never share this OTP with anyone.

        SSH Guardian 2.0
        """

        return EmailService.send_email(to_email, subject, body_html, body_text)


class PasswordManager:
    """Password hashing and validation"""

    @staticmethod
    def hash_password(password):
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(password, password_hash):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

    @staticmethod
    def validate_password_strength(password):
        """Validate password meets security requirements"""
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")

        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            errors.append("Password must contain at least one special character")

        return len(errors) == 0, errors


class OTPManager:
    """OTP generation and validation"""

    @staticmethod
    def generate_otp():
        """Generate 6-digit OTP"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

    @staticmethod
    def create_otp(user_id, purpose='login', ip_address=None):
        """Create and store OTP"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Generate OTP
            otp_code = OTPManager.generate_otp()
            expires_at = datetime.now() + timedelta(minutes=OTP_VALIDITY_MINUTES)

            # Store OTP
            cursor.execute("""
                INSERT INTO user_otps (user_id, otp_code, purpose, expires_at, ip_address)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, otp_code, purpose, expires_at, ip_address))

            conn.commit()

            return otp_code

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def verify_otp(user_id, otp_code, purpose='login'):
        """Verify OTP is valid and not expired"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Find valid OTP
            cursor.execute("""
                SELECT * FROM user_otps
                WHERE user_id = %s
                AND otp_code = %s
                AND purpose = %s
                AND expires_at > NOW()
                AND is_used = FALSE
                ORDER BY created_at DESC
                LIMIT 1
            """, (user_id, otp_code, purpose))

            otp = cursor.fetchone()

            if not otp:
                return False

            # Mark as used
            cursor.execute("""
                UPDATE user_otps
                SET is_used = TRUE, used_at = NOW()
                WHERE id = %s
            """, (otp['id'],))

            conn.commit()

            return True

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def cleanup_expired_otps():
        """Delete expired OTPs"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM user_otps
                WHERE expires_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            conn.commit()

        finally:
            cursor.close()
            conn.close()


class SessionManager:
    """Session management with secure cookies"""

    @staticmethod
    def generate_session_token():
        """Generate secure session token"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def create_session(user_id, ip_address=None, user_agent=None):
        """Create new session"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            session_token = SessionManager.generate_session_token()
            expires_at = datetime.now() + timedelta(days=SESSION_DURATION_DAYS)

            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, session_token, ip_address, user_agent, expires_at))

            conn.commit()

            return session_token, expires_at

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def validate_session(session_token):
        """Validate session token and return user"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT s.*, u.*, r.name as role_name, r.permissions
                FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                JOIN roles r ON u.role_id = r.id
                WHERE s.session_token = %s
                AND s.expires_at > NOW()
                AND u.is_active = TRUE
            """, (session_token,))

            session_data = cursor.fetchone()

            if session_data:
                # Update last activity
                cursor.execute("""
                    UPDATE user_sessions
                    SET last_activity = NOW()
                    WHERE session_token = %s
                """, (session_token,))
                conn.commit()

            return session_data

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_session(session_token):
        """Delete session (logout)"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM user_sessions
                WHERE session_token = %s
            """, (session_token,))

            conn.commit()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def cleanup_expired_sessions():
        """Delete expired sessions"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM user_sessions
                WHERE expires_at < NOW()
            """)
            conn.commit()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_user_from_session(session_token):
        """Get user data from session token"""
        session_data = SessionManager.validate_session(session_token)
        if not session_data:
            return None

        return {
            'id': session_data['user_id'],
            'email': session_data['email'],
            'full_name': session_data['full_name'],
            'role': session_data['role_name'],
            'permissions': json.loads(session_data['permissions']) if isinstance(session_data['permissions'], str) else session_data['permissions']
        }


class UserManager:
    """User management operations"""

    @staticmethod
    def get_user_by_email(email):
        """Get user by email"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT u.*, r.name as role_name, r.permissions
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.email = %s
            """, (email,))

            return cursor.fetchone()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_user_by_id(user_id):
        """Get user by ID"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT u.*, r.name as role_name, r.permissions
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.id = %s
            """, (user_id,))

            return cursor.fetchone()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def create_user(email, password, full_name, role_id, created_by_id=None):
        """Create new user"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            password_hash = PasswordManager.hash_password(password)

            cursor.execute("""
                INSERT INTO users (email, password_hash, full_name, role_id, created_by)
                VALUES (%s, %s, %s, %s, %s)
            """, (email, password_hash, full_name, role_id, created_by_id))

            conn.commit()
            user_id = cursor.lastrowid

            # Log action
            AuditLogger.log_action(created_by_id, 'user_created', 'user', str(user_id),
                                  {'email': email, 'role_id': role_id})

            return user_id

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_user(user_id, **kwargs):
        """Update user"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            allowed_fields = ['full_name', 'role_id', 'is_active']
            updates = []
            values = []

            for field in allowed_fields:
                if field in kwargs:
                    updates.append(f"{field} = %s")
                    values.append(kwargs[field])

            if updates:
                values.append(user_id)
                query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
                cursor.execute(query, values)
                conn.commit()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_user(user_id, deleted_by_id):
        """Delete user (soft delete by deactivating)"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE users
                SET is_active = FALSE
                WHERE id = %s
            """, (user_id,))

            conn.commit()

            # Log action
            AuditLogger.log_action(deleted_by_id, 'user_deleted', 'user', str(user_id))

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def list_users():
        """List all users"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT u.id, u.email, u.full_name, u.is_active, u.last_login,
                       u.created_at, r.name as role_name
                FROM users u
                JOIN roles r ON u.role_id = r.id
                ORDER BY u.created_at DESC
            """)

            return cursor.fetchall()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def check_account_locked(user_id):
        """Check if account is locked"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT locked_until FROM users
                WHERE id = %s
            """, (user_id,))

            result = cursor.fetchone()

            if result and result['locked_until']:
                if result['locked_until'] > datetime.now():
                    return True, result['locked_until']
                else:
                    # Unlock account
                    cursor.execute("""
                        UPDATE users
                        SET locked_until = NULL, failed_login_attempts = 0
                        WHERE id = %s
                    """, (user_id,))
                    conn.commit()

            return False, None

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def record_failed_login(user_id):
        """Record failed login attempt"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE users
                SET failed_login_attempts = failed_login_attempts + 1
                WHERE id = %s
            """, (user_id,))

            # Check if should lock
            cursor.execute("""
                SELECT failed_login_attempts FROM users WHERE id = %s
            """, (user_id,))

            result = cursor.fetchone()

            if result and result[0] >= MAX_FAILED_ATTEMPTS:
                locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                cursor.execute("""
                    UPDATE users
                    SET locked_until = %s
                    WHERE id = %s
                """, (locked_until, user_id))

            conn.commit()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def reset_failed_attempts(user_id):
        """Reset failed login attempts"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE users
                SET failed_login_attempts = 0, locked_until = NULL
                WHERE id = %s
            """, (user_id,))

            conn.commit()

        finally:
            cursor.close()
            conn.close()


class AuditLogger:
    """Audit logging for security actions"""

    @staticmethod
    def log_action(user_id, action, resource_type=None, resource_id=None, details=None,
                   ip_address=None, user_agent=None):
        """Log user action"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            details_json = json.dumps(details) if details else None

            cursor.execute("""
                INSERT INTO audit_logs (user_id, action, resource_type, resource_id,
                                       details, ip_address, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, action, resource_type, resource_id, details_json,
                  ip_address, user_agent))

            conn.commit()

        finally:
            cursor.close()
            conn.close()


# Authentication decorators
def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')

        if not session_token:
            return jsonify({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}), 401

        session_data = SessionManager.validate_session(session_token)

        if not session_data:
            return jsonify({'error': 'Invalid or expired session', 'code': 'INVALID_SESSION'}), 401

        # Add user data to request context
        request.current_user = session_data

        return f(*args, **kwargs)

    return decorated_function


def permission_required(permission_name):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_token = request.cookies.get('session_token')

            if not session_token:
                return jsonify({'error': 'Authentication required'}), 401

            session_data = SessionManager.validate_session(session_token)

            if not session_data:
                return jsonify({'error': 'Invalid session'}), 401

            # Check permission
            permissions = json.loads(session_data['permissions']) if isinstance(session_data['permissions'], str) else session_data['permissions']

            if not permissions.get(permission_name, False):
                return jsonify({'error': 'Insufficient permissions'}), 403

            request.current_user = session_data

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def role_required(*role_names):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_token = request.cookies.get('session_token')

            if not session_token:
                return jsonify({'error': 'Authentication required'}), 401

            session_data = SessionManager.validate_session(session_token)

            if not session_data:
                return jsonify({'error': 'Invalid session'}), 401

            # Check role
            if session_data['role_name'] not in role_names:
                return jsonify({'error': 'Insufficient permissions'}), 403

            request.current_user = session_data

            return f(*args, **kwargs)

        return decorated_function

    return decorator
