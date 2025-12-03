"""
SSH Guardian 2.0 - Authentication Routes
Login, OTP, User Management, and RBAC endpoints
"""

from flask import Blueprint, request, jsonify, make_response, render_template
from datetime import datetime, timedelta
import json

from auth import (
    UserManager, PasswordManager, OTPManager, SessionManager,
    EmailService, AuditLogger, AuthenticationError,
    login_required, permission_required, role_required
)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['POST'])
def login_step1():
    """Step 1: Validate password and send OTP"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        # Get user
        user = UserManager.get_user_by_email(email)

        if not user:
            # Don't reveal if user exists
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check if account is active
        if not user['is_active']:
            return jsonify({'error': 'Account is deactivated'}), 403

        # Check if account is locked
        is_locked, locked_until = UserManager.check_account_locked(user['id'])

        if is_locked:
            minutes_left = int((locked_until - datetime.now()).total_seconds() / 60)
            return jsonify({
                'error': f'Account locked due to too many failed attempts. Try again in {minutes_left} minutes'
            }), 403

        # Verify password
        if not PasswordManager.verify_password(password, user['password_hash']):
            UserManager.record_failed_login(user['id'])
            AuditLogger.log_action(user['id'], 'login_failed', details={'reason': 'invalid_password'},
                                  ip_address=request.remote_addr, user_agent=request.user_agent.string)
            return jsonify({'error': 'Invalid credentials'}), 401

        # Password correct - generate and send OTP
        otp_code = OTPManager.create_otp(user['id'], 'login', request.remote_addr)

        # Send OTP via email
        email_sent = EmailService.send_otp_email(user['email'], otp_code, user['full_name'])

        if not email_sent:
            # Log but don't fail - print OTP for development
            print(f"📧 OTP for {email}: {otp_code}")

        # Log login attempt
        AuditLogger.log_action(user['id'], 'login_otp_sent',
                              ip_address=request.remote_addr, user_agent=request.user_agent.string)

        return jsonify({
            'success': True,
            'message': 'OTP sent to your email',
            'user_id': user['id'],
            'email_sent': email_sent,
            'otp_for_dev': otp_code if not email_sent else None  # Only for development
        }), 200

    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    """Step 2: Verify OTP and create session"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        otp_code = data.get('otp_code', '').strip()
        remember_me = data.get('remember_me', True)

        if not user_id or not otp_code:
            return jsonify({'error': 'User ID and OTP are required'}), 400

        # Verify OTP
        if not OTPManager.verify_otp(user_id, otp_code, 'login'):
            AuditLogger.log_action(user_id, 'login_otp_failed',
                                  ip_address=request.remote_addr, user_agent=request.user_agent.string)
            return jsonify({'error': 'Invalid or expired OTP'}), 401

        # Get user details
        user = UserManager.get_user_by_id(user_id)

        if not user or not user['is_active']:
            return jsonify({'error': 'User account not found or inactive'}), 403

        # Reset failed attempts
        UserManager.reset_failed_attempts(user_id)

        # Update last login
        from connection import get_connection
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()

        # Create session
        session_token, expires_at = SessionManager.create_session(
            user_id,
            request.remote_addr,
            request.user_agent.string
        )

        # Log successful login
        AuditLogger.log_action(user_id, 'login_success',
                              details={'role': user['role_name']},
                              ip_address=request.remote_addr, user_agent=request.user_agent.string)

        # Create response with cookie
        response = make_response(jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role_name'],
                'permissions': json.loads(user['permissions']) if isinstance(user['permissions'], str) else user['permissions']
            }
        }))

        # Set secure HTTP-only cookie
        # Always set max_age to keep session active while browser is open
        # If remember_me is true, extend to 30 days
        # If remember_me is false, set to 24 hours (persists across browser reopens for convenience)
        response.set_cookie(
            'session_token',
            session_token,
            max_age=30*24*60*60 if remember_me else 24*60*60,  # 30 days or 24 hours
            secure=False,  # Set to True in production with HTTPS
            httponly=True,  # Not accessible via JavaScript
            samesite='Lax',
            path='/'  # Ensure cookie is available for all paths
        )

        return response, 200

    except Exception as e:
        print(f"❌ OTP verification error: {e}")
        return jsonify({'error': 'OTP verification failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout and delete session"""
    try:
        session_token = request.cookies.get('session_token')

        if session_token:
            SessionManager.delete_session(session_token)

        # Log logout
        AuditLogger.log_action(request.current_user['id'], 'logout',
                              ip_address=request.remote_addr, user_agent=request.user_agent.string)

        response = make_response(jsonify({'success': True, 'message': 'Logged out successfully'}))
        response.delete_cookie('session_token', path='/', samesite='Lax')

        return response, 200

    except Exception as e:
        print(f"❌ Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_bp.route('/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user info"""
    try:
        user = request.current_user

        return jsonify({
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role_name'],
                'permissions': json.loads(user['permissions']) if isinstance(user['permissions'], str) else user['permissions'],
                'last_login': user['last_login'].isoformat() if user['last_login'] else None
            }
        }), 200

    except Exception as e:
        print(f"❌ Get user error: {e}")
        return jsonify({'error': 'Failed to get user info'}), 500


@auth_bp.route('/check-session', methods=['GET'])
def check_session():
    """Check if session is valid (for frontend to verify auth status)"""
    session_token = request.cookies.get('session_token')

    if not session_token:
        return jsonify({'authenticated': False}), 200

    session_data = SessionManager.validate_session(session_token)

    if not session_data:
        return jsonify({'authenticated': False}), 200

    return jsonify({
        'authenticated': True,
        'user': {
            'id': session_data['id'],
            'email': session_data['email'],
            'full_name': session_data['full_name'],
            'role': session_data['role_name']
        }
    }), 200


# User Management Routes (Super Admin only)
@auth_bp.route('/users', methods=['GET'])
@permission_required('user_management')
def list_users():
    """List all users"""
    try:
        users = UserManager.list_users()

        return jsonify({
            'users': [{
                'id': u['id'],
                'email': u['email'],
                'full_name': u['full_name'],
                'role': u['role_name'],
                'is_active': bool(u['is_active']),
                'last_login': u['last_login'].isoformat() if u['last_login'] else None,
                'created_at': u['created_at'].isoformat() if u['created_at'] else None
            } for u in users]
        }), 200

    except Exception as e:
        print(f"❌ List users error: {e}")
        return jsonify({'error': 'Failed to list users'}), 500


@auth_bp.route('/users', methods=['POST'])
@permission_required('user_management')
def create_user():
    """Create new user"""
    try:
        data = request.get_json()

        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        role_id = data.get('role_id')

        # Validate required fields
        if not all([email, password, full_name, role_id]):
            return jsonify({'error': 'All fields are required'}), 400

        # Validate email format
        if '@' not in email:
            return jsonify({'error': 'Invalid email format'}), 400

        # Validate password strength
        is_strong, errors = PasswordManager.validate_password_strength(password)
        if not is_strong:
            return jsonify({'error': 'Weak password', 'details': errors}), 400

        # Check if user already exists
        existing_user = UserManager.get_user_by_email(email)
        if existing_user:
            return jsonify({'error': 'User with this email already exists'}), 409

        # Create user
        user_id = UserManager.create_user(
            email, password, full_name, role_id,
            created_by_id=request.current_user['id']
        )

        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user_id': user_id
        }), 201

    except Exception as e:
        print(f"❌ Create user error: {e}")
        return jsonify({'error': 'Failed to create user'}), 500


@auth_bp.route('/users/<int:user_id>', methods=['PUT'])
@permission_required('user_management')
def update_user(user_id):
    """Update user"""
    try:
        data = request.get_json()

        # Don't allow updating yourself
        if user_id == request.current_user['id']:
            return jsonify({'error': 'Cannot modify your own account through this endpoint'}), 403

        UserManager.update_user(user_id, **data)

        # Log action
        AuditLogger.log_action(request.current_user['id'], 'user_updated', 'user', str(user_id),
                              details=data, ip_address=request.remote_addr)

        return jsonify({'success': True, 'message': 'User updated successfully'}), 200

    except Exception as e:
        print(f"❌ Update user error: {e}")
        return jsonify({'error': 'Failed to update user'}), 500


@auth_bp.route('/users/<int:user_id>', methods=['DELETE'])
@permission_required('user_management')
def delete_user(user_id):
    """Delete (deactivate) user"""
    try:
        # Don't allow deleting yourself
        if user_id == request.current_user['id']:
            return jsonify({'error': 'Cannot delete your own account'}), 403

        UserManager.delete_user(user_id, request.current_user['id'])

        return jsonify({'success': True, 'message': 'User deleted successfully'}), 200

    except Exception as e:
        print(f"❌ Delete user error: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500


@auth_bp.route('/roles', methods=['GET'])
@login_required
def list_roles():
    """List all available roles"""
    try:
        from connection import get_connection
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id, name, description, permissions FROM roles ORDER BY id")
        roles = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'roles': [{
                'id': r['id'],
                'name': r['name'],
                'description': r['description'],
                'permissions': json.loads(r['permissions']) if isinstance(r['permissions'], str) else r['permissions']
            } for r in roles]
        }), 200

    except Exception as e:
        print(f"❌ List roles error: {e}")
        return jsonify({'error': 'Failed to list roles'}), 500


# Change password
@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user's own password"""
    try:
        data = request.get_json()

        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not current_password or not new_password:
            return jsonify({'error': 'Current and new passwords are required'}), 400

        # Get user
        user = UserManager.get_user_by_id(request.current_user['id'])

        # Verify current password
        if not PasswordManager.verify_password(current_password, user['password_hash']):
            return jsonify({'error': 'Current password is incorrect'}), 401

        # Validate new password strength
        is_strong, errors = PasswordManager.validate_password_strength(new_password)
        if not is_strong:
            return jsonify({'error': 'Weak password', 'details': errors}), 400

        # Update password
        from connection import get_connection
        conn = get_connection()
        cursor = conn.cursor()

        new_hash = PasswordManager.hash_password(new_password)
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                      (new_hash, request.current_user['id']))
        conn.commit()
        cursor.close()
        conn.close()

        # Log action
        AuditLogger.log_action(request.current_user['id'], 'password_changed',
                              ip_address=request.remote_addr)

        return jsonify({'success': True, 'message': 'Password changed successfully'}), 200

    except Exception as e:
        print(f"❌ Change password error: {e}")
        return jsonify({'error': 'Failed to change password'}), 500


# Audit logs (Super Admin only)
@auth_bp.route('/audit-logs', methods=['GET'])
@permission_required('audit_logs')
def get_audit_logs():
    """Get audit logs"""
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)

        from connection import get_connection
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT a.*, u.email, u.full_name
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.created_at DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))

        logs = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'logs': [{
                'id': log['id'],
                'user_email': log['email'],
                'user_name': log['full_name'],
                'action': log['action'],
                'resource_type': log['resource_type'],
                'resource_id': log['resource_id'],
                'details': json.loads(log['details']) if log['details'] else None,
                'ip_address': log['ip_address'],
                'created_at': log['created_at'].isoformat() if log['created_at'] else None
            } for log in logs]
        }), 200

    except Exception as e:
        print(f"❌ Get audit logs error: {e}")
        return jsonify({'error': 'Failed to get audit logs'}), 500
