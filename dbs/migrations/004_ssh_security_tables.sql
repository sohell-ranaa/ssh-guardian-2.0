-- SSH Security Pipeline Database Schema
-- Stores processed login attempts with enrichment data

-- Table for successful SSH logins
CREATE TABLE IF NOT EXISTS successful_logins (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- Basic login data (from JSON)
    timestamp DATETIME NOT NULL,
    server_hostname VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    username VARCHAR(255) NOT NULL,
    port INT DEFAULT 22,
    session_duration INT DEFAULT 0,
    
    -- Raw data storage (minimize DB records as requested)
    raw_event_data JSON,  -- Store complete JSON event here
    
    -- Enrichment data (populated in pipeline stages)
    -- Stage 2: GeoIP data
    country VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    timezone VARCHAR(50),
    geoip_processed BOOLEAN DEFAULT FALSE,
    
    -- Stage 3: IP Health data  
    ip_risk_score INT DEFAULT 0,
    ip_reputation ENUM('clean', 'suspicious', 'malicious', 'unknown') DEFAULT 'unknown',
    threat_intel_data JSON,
    ip_health_processed BOOLEAN DEFAULT FALSE,
    
    -- Stage 4: ML Analysis
    ml_risk_score INT DEFAULT 0,
    ml_threat_type VARCHAR(100),
    ml_confidence DECIMAL(4,3),
    is_anomaly BOOLEAN DEFAULT FALSE,
    ml_processed BOOLEAN DEFAULT FALSE,
    
    -- Processing status
    pipeline_completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_timestamp (timestamp),
    INDEX idx_ip (source_ip),
    INDEX idx_username (username),
    INDEX idx_server (server_hostname),
    INDEX idx_anomaly (is_anomaly),
    INDEX idx_pipeline_status (geoip_processed, ip_health_processed, ml_processed)
);

-- Table for failed SSH login attempts  
CREATE TABLE IF NOT EXISTS failed_logins (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- Basic attempt data (from JSON)
    timestamp DATETIME NOT NULL,
    server_hostname VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    username VARCHAR(255),
    port INT DEFAULT 22,
    failure_reason ENUM('invalid_password', 'invalid_user', 'connection_refused', 'other') NOT NULL,
    
    -- Raw data storage (minimize DB records as requested)
    raw_event_data JSON,  -- Store complete JSON event here
    
    -- Enrichment data (populated in pipeline stages)
    -- Stage 2: GeoIP data
    country VARCHAR(100),
    city VARCHAR(100), 
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    timezone VARCHAR(50),
    geoip_processed BOOLEAN DEFAULT FALSE,
    
    -- Stage 3: IP Health data
    ip_risk_score INT DEFAULT 0,
    ip_reputation ENUM('clean', 'suspicious', 'malicious', 'unknown') DEFAULT 'unknown',
    threat_intel_data JSON,
    ip_health_processed BOOLEAN DEFAULT FALSE,
    
    -- Stage 4: ML Analysis  
    ml_risk_score INT DEFAULT 0,
    ml_threat_type VARCHAR(100),
    ml_confidence DECIMAL(4,3),
    is_anomaly BOOLEAN DEFAULT FALSE,
    ml_processed BOOLEAN DEFAULT FALSE,
    
    -- Processing status
    pipeline_completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_timestamp (timestamp),
    INDEX idx_ip (source_ip),
    INDEX idx_username (username),
    INDEX idx_server (server_hostname),
    INDEX idx_anomaly (is_anomaly),
    INDEX idx_pipeline_status (geoip_processed, ip_health_processed, ml_processed)
);

-- IP blocking/management table
CREATE TABLE IF NOT EXISTS ip_blocks (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    block_reason VARCHAR(255) NOT NULL,
    block_source ENUM('manual', 'brute_force', 'ml_analysis', 'ip_reputation') NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unblock_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    
    UNIQUE KEY unique_active_ip (ip_address, is_active),
    INDEX idx_ip_active (ip_address, is_active),
    INDEX idx_unblock_time (unblock_at)
);

-- Security configuration and thresholds
CREATE TABLE IF NOT EXISTS security_settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default security settings
INSERT INTO security_settings (setting_key, setting_value, description) VALUES
('failed_attempts_threshold', '5', 'Failed attempts before investigation'),
('brute_force_threshold', '10', 'Failed attempts before auto-block'), 
('ml_risk_threshold', '70', 'ML risk score threshold for alerts'),
('ip_reputation_threshold', '60', 'IP reputation score for blocking'),
('block_duration_hours', '24', 'Default block duration in hours'),
('successful_login_alerts', 'true', 'Send alerts for successful logins'),
('failed_login_alerts', 'true', 'Send alerts for failed attempts'),
('geoip_enabled', 'true', 'Enable GeoIP enrichment'),
('ip_health_enabled', 'true', 'Enable IP health checking'),
('ml_analysis_enabled', 'true', 'Enable ML analysis'),
('cleanup_days', '7', 'Days to keep temporary files'),
('notification_frequency', 'immediate', 'Alert frequency: immediate, hourly, daily');

-- Processing queue table (tracks pipeline progress)
CREATE TABLE IF NOT EXISTS processing_queue (
    id INT PRIMARY KEY AUTO_INCREMENT,
    record_type ENUM('successful', 'failed') NOT NULL,
    record_id INT NOT NULL,
    stage ENUM('geoip', 'ip_health', 'ml_analysis') NOT NULL,
    status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
    retry_count INT DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_status_stage (status, stage),
    INDEX idx_record (record_type, record_id)
);