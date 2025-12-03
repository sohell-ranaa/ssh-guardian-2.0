# SSH Guardian 2.0 - Authentication System Setup Guide

## Overview

SSH Guardian 2.0 now includes a comprehensive authentication system with:

- **Two-Factor Authentication (2FA)**: Password + OTP (6-digit code)
- **Role-Based Access Control (RBAC)**: 4 predefined roles
- **User Management**: Super admin can create/edit/delete users
- **Email Notifications**: OTP codes sent via SMTP
- **Persistent Sessions**: 30-day sessions with secure cookies
- **Audit Logging**: All security actions are logged

---

## Quick Start

### 1. Database Setup

The authentication database schema has already been created. If you need to reapply it:

```bash
docker exec $(docker ps -q -f name=mysql) mysql -u root -p123123 ssh_guardian_20 < dbs/migrations/005_authentication_system.sql
```

### 2. Configure Email SMTP (Required for OTP delivery)

Edit `.env` file and add your email SMTP credentials:

#### Option A: Gmail (Recommended for testing)

1. **Enable 2-Factor Authentication** on your Google account
2. **Create App Password**:
   - Go to https://myaccount.google.com/apppasswords
   - Select "Mail" and "Other" (name it "SSH Guardian")
   - Copy the 16-character password

3. **Update .env**:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=xxxx xxxx xxxx xxxx  # 16-char app password from step 2
FROM_EMAIL=your-email@gmail.com
FROM_NAME=SSH Guardian Security
```

#### Option B: SendGrid

```env
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=your-sendgrid-api-key
FROM_EMAIL=your-verified-sender@example.com
FROM_NAME=SSH Guardian Security
```

#### Option C: AWS SES

```env
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=your-ses-smtp-username
SMTP_PASSWORD=your-ses-smtp-password
FROM_EMAIL=your-verified-email@example.com
FROM_NAME=SSH Guardian Security
```

### 3. Restart Services

Stop any running services and restart with authentication enabled:

```bash
# Kill existing processes
pkill -f dashboard_server.py
pkill -f ssh_guardian_v2

# Start dashboard with authentication
cd /home/rana-workspace/ssh_guardian_2.0
venv/bin/python3 src/dashboard/dashboard_server.py
```

The dashboard will now run on **http://31.220.94.187:8080** with authentication enabled.

---

## Default Login Credentials

**Email**: `admin@localhost`
**Password**: `Admin@123`

**Important**: Change this password immediately after first login!

---

## User Roles & Permissions

### 1. Super Admin
- **Full system access**
- User management (create/edit/delete users)
- View audit logs
- All viewer, analyst, and admin permissions

**Permissions**:
- `view_dashboard`
- `view_events`
- `manage_blocks`
- `export_data`
- `user_management`
- `audit_logs`

### 2. Admin
- Manage IP blocks/whitelist
- View all data
- Export data
- Cannot manage users

**Permissions**:
- `view_dashboard`
- `view_events`
- `manage_blocks`
- `export_data`

### 3. Analyst
- View all security data
- Export reports
- Cannot manage blocks or users

**Permissions**:
- `view_dashboard`
- `view_events`
- `export_data`

### 4. Viewer
- Read-only access
- View dashboard and events
- Cannot make any changes

**Permissions**:
- `view_dashboard`
- `view_events`

---

## Login Flow

1. **Enter Email & Password** → System validates credentials
2. **OTP Sent to Email** → 6-digit code valid for 5 minutes
3. **Enter OTP Code** → System verifies and creates session
4. **Session Created** → 30-day persistent cookie (even after browser close)

---

## User Management (Super Admin Only)

### Access User Management

1. Login as super admin
2. Click **"User Management"** in the sidebar
3. View all users, create new users, edit roles, deactivate accounts

### Create New User

1. Click **"Create User"** button
2. Fill in:
   - Email (must be valid format)
   - Password (min 8 chars with uppercase, lowercase, digit, special char)
   - Full Name
   - Role (select from dropdown)
3. Click **"Create User"**

The new user will receive their credentials and can login immediately.

### Edit User

1. Click **Edit** (pencil icon) next to user
2. Update: Full Name, Role, Active Status
3. Click **"Update User"**

**Note**: Email cannot be changed. Password cannot be changed via admin (users must use "Change Password" feature).

### Delete User

1. Click **Delete** (trash icon) next to user
2. Confirm deletion
3. User account is **deactivated** (not permanently deleted)

**Note**: Cannot delete your own account.

---

## Security Features

### Account Lockout
- **5 failed login attempts** → Account locked for 30 minutes
- Prevents brute force attacks

### OTP Security
- **6-digit random codes**
- **5-minute expiry**
- **Single-use only**
- New OTP invalidates previous ones

### Session Security
- **HTTP-only cookies** (not accessible via JavaScript)
- **30-day expiration** (with "remember me")
- **IP and user agent tracking**
- **Automatic session cleanup** of expired sessions

### Password Requirements
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character

### Audit Logging
All security actions are logged:
- Login attempts (success/failure)
- OTP requests and verifications
- User creation/modification/deletion
- Password changes
- Session creation/deletion

View logs: **User Management → Audit Logs** (super admin only)

---

## Testing the Authentication System

### Test 1: Login Flow

```bash
# 1. Access login page
curl http://31.220.94.187:8080/login

# 2. Login (Step 1 - Password)
curl -X POST http://31.220.94.187:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@localhost","password":"Admin@123"}'

# Response will include user_id and otp_for_dev (if email not configured)

# 3. Verify OTP (Step 2)
curl -X POST http://31.220.94.187:8080/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"user_id":1,"otp_code":"123456","remember_me":true}'

# Response sets session cookie
```

### Test 2: Session Validation

```bash
# Check if session is valid
curl http://31.220.94.187:8080/auth/check-session \
  -H "Cookie: session_token=YOUR_SESSION_TOKEN"
```

### Test 3: User Management

```bash
# List all users (super admin only)
curl http://31.220.94.187:8080/auth/users \
  -H "Cookie: session_token=YOUR_SESSION_TOKEN"

# Create new user
curl -X POST http://31.220.94.187:8080/auth/users \
  -H "Cookie: session_token=YOUR_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email":"analyst@example.com",
    "password":"Analyst@123",
    "full_name":"Security Analyst",
    "role_id":3
  }'
```

---

## Development Mode (Email Not Configured)

If email SMTP is **not configured**, OTP codes will be **printed to console**:

```
📧 OTP for admin@localhost: 123456
```

This allows testing without email setup. **Do not use in production!**

---

## Troubleshooting

### Issue: Cannot receive OTP emails

**Solutions**:
1. Check SMTP credentials in `.env`
2. For Gmail: Ensure you're using **App Password**, not regular password
3. Check spam/junk folder
4. Look for OTP in console output (development mode)
5. Test SMTP connection:
   ```python
   from src.dashboard.auth import EmailService
   EmailService.send_otp_email("test@example.com", "123456", "Test User")
   ```

### Issue: "Invalid or expired OTP"

**Solutions**:
- OTP expires after 5 minutes
- Each OTP can only be used once
- Request a new OTP by logging in again

### Issue: "Account locked"

**Solutions**:
- Wait 30 minutes for automatic unlock
- Or super admin can manually unlock via database:
  ```sql
  UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = 'user@example.com';
  ```

### Issue: Session not persisting

**Solutions**:
1. Check browser allows cookies
2. Verify `SECRET_KEY` in `.env` is set
3. Check cookie settings in `dashboard_server.py`:
   - `httponly=True`
   - `secure=False` (for HTTP), `secure=True` (for HTTPS)
   - `samesite='Lax'`

### Issue: 403 Forbidden on protected routes

**Solutions**:
- Ensure you're logged in
- Check your role has required permissions
- Verify session cookie is being sent with requests

---

## Production Deployment

### Security Checklist

- [ ] Change default admin password
- [ ] Configure email SMTP properly
- [ ] Set `SESSION_COOKIE_SECURE=True` in `.env` (requires HTTPS)
- [ ] Use strong `SECRET_KEY` (generate new one)
- [ ] Enable HTTPS/SSL
- [ ] Set up firewall rules
- [ ] Regular database backups
- [ ] Monitor audit logs
- [ ] Implement rate limiting (if needed)

### Generate New SECRET_KEY

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Replace `SECRET_KEY` in `.env` with output.

---

## API Endpoints Reference

### Authentication Routes

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/auth/login` | POST | No | Step 1: Validate password, send OTP |
| `/auth/verify-otp` | POST | No | Step 2: Verify OTP, create session |
| `/auth/logout` | POST | Yes | Logout, delete session |
| `/auth/me` | GET | Yes | Get current user info |
| `/auth/check-session` | GET | No | Check if session is valid |
| `/auth/change-password` | POST | Yes | Change own password |

### User Management Routes (Super Admin)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/auth/users` | GET | Super Admin | List all users |
| `/auth/users` | POST | Super Admin | Create new user |
| `/auth/users/<id>` | PUT | Super Admin | Update user |
| `/auth/users/<id>` | DELETE | Super Admin | Delete (deactivate) user |
| `/auth/roles` | GET | Authenticated | List available roles |
| `/auth/audit-logs` | GET | Super Admin | View audit logs |

---

## File Structure

```
src/dashboard/
├── auth.py                 # Authentication backend classes
├── auth_routes.py          # Authentication API endpoints
├── dashboard_server.py     # Main dashboard server (with auth)
├── templates/
│   ├── login.html         # Login & OTP verification UI
│   └── enhanced_dashboard.html  # Main dashboard (with user management)
└── static/
    └── js/
        └── enhanced-dashboard.js  # Dashboard JavaScript (with auth)

dbs/migrations/
└── 005_authentication_system.sql  # Database schema

docs/
└── AUTHENTICATION_SETUP.md  # This file
```

---

## Support

For issues or questions:
- Check troubleshooting section above
- Review audit logs for security events
- Check console output for error messages
- Ensure database migration was applied successfully

---

## Next Steps

1. ✅ Login with default credentials
2. ✅ Change admin password
3. ✅ Configure email SMTP (if not done)
4. ✅ Create additional user accounts
5. ✅ Test user management features
6. ✅ Review audit logs
7. ✅ Configure production settings (if deploying)

**Your SSH Guardian dashboard is now fully secured with enterprise-grade authentication!** 🔒
