-- SSH Guardian 2.0 - Authentication System Database Schema
-- RBAC with OTP-based authentication

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_email_verified BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by INT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_email (email),
    INDEX idx_role (role_id),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (session_token),
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create OTP table
CREATE TABLE IF NOT EXISTS user_otps (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    purpose ENUM('login', 'password_reset', 'email_verification') DEFAULT 'login',
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_otp (user_id, otp_code),
    INDEX idx_expires (expires_at),
    INDEX idx_purpose (purpose)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user (user_id),
    INDEX idx_action (action),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert default roles
INSERT INTO roles (name, description, permissions) VALUES
('super_admin', 'Super Administrator - Full system access', JSON_OBJECT(
    'user_management', true,
    'view_dashboard', true,
    'manage_blocks', true,
    'manage_whitelist', true,
    'view_logs', true,
    'system_settings', true,
    'audit_logs', true
)),
('admin', 'Administrator - Can manage security operations', JSON_OBJECT(
    'user_management', false,
    'view_dashboard', true,
    'manage_blocks', true,
    'manage_whitelist', true,
    'view_logs', true,
    'system_settings', false,
    'audit_logs', false
)),
('analyst', 'Security Analyst - Read-only access with search', JSON_OBJECT(
    'user_management', false,
    'view_dashboard', true,
    'manage_blocks', false,
    'manage_whitelist', false,
    'view_logs', true,
    'system_settings', false,
    'audit_logs', false
)),
('viewer', 'Viewer - Read-only access to dashboard', JSON_OBJECT(
    'user_management', false,
    'view_dashboard', true,
    'manage_blocks', false,
    'manage_whitelist', false,
    'view_logs', false,
    'system_settings', false,
    'audit_logs', false
));

-- Create default super admin user (password: Admin@123 - MUST CHANGE ON FIRST LOGIN)
-- Password hash for 'Admin@123' using bcrypt
INSERT INTO users (email, password_hash, full_name, role_id, is_active, is_email_verified)
VALUES (
    'admin@localhost',
    '$2b$12$xfeOt/siJgpvyFscIxGBwOykp2cFuvC/cqefYaFGD08TCEZ5tBIBW',
    'Super Administrator',
    1,
    TRUE,
    TRUE
);

-- Create indexes for performance
CREATE INDEX idx_sessions_active ON user_sessions(user_id, expires_at);
CREATE INDEX idx_otps_valid ON user_otps(user_id, expires_at, is_used);
CREATE INDEX idx_audit_recent ON audit_logs(created_at DESC);
