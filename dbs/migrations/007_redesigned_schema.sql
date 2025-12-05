-- ============================================================================
-- SSH Guardian 2.0 - Redesigned Database Schema
-- Version: 3.0
-- Date: 2025-12-04
-- Purpose: Robust, normalized schema with proper constraints and optimization
-- ============================================================================

-- This migration redesigns the database for better performance, data integrity,
-- and maintainability. It addresses all issues in the current schema.

-- ============================================================================
-- STEP 1: Create New Optimized Tables
-- ============================================================================

-- ----------------------------------------------------------------------------
-- IP Geolocation Cache (Normalized GeoIP data)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_geolocation (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARBINARY(16) NOT NULL COMMENT 'IPv4/IPv6 address in binary format',
    ip_address_text VARCHAR(45) NOT NULL COMMENT 'Human-readable IP',
    country_code CHAR(2) NULL COMMENT 'ISO 3166-1 alpha-2 code',
    country_name VARCHAR(100) NULL,
    region VARCHAR(100) NULL,
    city VARCHAR(100) NULL,
    latitude DECIMAL(10,8) NULL,
    longitude DECIMAL(11,8) NULL,
    timezone VARCHAR(50) NULL,
    asn INT NULL COMMENT 'Autonomous System Number',
    asn_org VARCHAR(255) NULL COMMENT 'AS Organization',
    is_proxy BOOLEAN DEFAULT FALSE,
    is_vpn BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,
    is_datacenter BOOLEAN DEFAULT FALSE,
    threat_level ENUM('clean', 'low', 'medium', 'high', 'critical') DEFAULT 'clean',
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    cache_expires_at TIMESTAMP NULL COMMENT 'GeoIP cache expiration',

    UNIQUE KEY idx_ip_binary (ip_address),
    UNIQUE KEY idx_ip_text (ip_address_text),
    KEY idx_country (country_code),
    KEY idx_threat_level (threat_level),
    KEY idx_cache_expires (cache_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Normalized IP geolocation and threat intelligence cache';

-- ----------------------------------------------------------------------------
-- Authentication Events (Unified failed and successful logins)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_uuid CHAR(36) NOT NULL COMMENT 'UUID for event tracking',
    timestamp DATETIME(3) NOT NULL COMMENT 'Event timestamp with milliseconds',
    event_type ENUM('failed', 'successful') NOT NULL,

    -- Source Information
    source_ip VARBINARY(16) NOT NULL COMMENT 'Source IP in binary',
    source_ip_text VARCHAR(45) NOT NULL,
    source_port INT UNSIGNED NULL,
    geo_id INT NULL COMMENT 'FK to ip_geolocation',

    -- Target Information
    target_server VARCHAR(255) NOT NULL COMMENT 'server_hostname',
    target_port INT UNSIGNED DEFAULT 22,
    target_username VARCHAR(255) NOT NULL,

    -- Event Details
    auth_method VARCHAR(50) NULL COMMENT 'password, publickey, keyboard-interactive',
    failure_reason ENUM('invalid_password', 'invalid_user', 'connection_refused',
                        'key_rejected', 'timeout', 'other') NULL,
    session_id VARCHAR(100) NULL COMMENT 'SSH session ID',
    session_duration_sec INT UNSIGNED NULL COMMENT 'For successful logins',

    -- ML & Analysis
    ml_risk_score TINYINT UNSIGNED DEFAULT 0 COMMENT '0-100',
    ml_threat_type VARCHAR(100) NULL COMMENT 'brute_force, credential_stuffing, etc',
    ml_confidence DECIMAL(5,4) NULL COMMENT '0.0000-1.0000',
    is_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_reasons JSON NULL COMMENT 'Array of anomaly indicators',

    -- Processing Flags
    ml_processed BOOLEAN DEFAULT FALSE,
    pipeline_completed BOOLEAN DEFAULT FALSE,

    -- Simulation Tracking
    is_simulation BOOLEAN DEFAULT FALSE,
    simulation_run_id INT NULL COMMENT 'FK to simulation_runs',

    -- Metadata
    raw_log_line TEXT NULL COMMENT 'Original log entry',
    user_agent TEXT NULL COMMENT 'SSH client info if available',
    additional_metadata JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY idx_event_uuid (event_uuid),
    KEY idx_timestamp (timestamp),
    KEY idx_event_type (event_type),
    KEY idx_source_ip (source_ip),
    KEY idx_source_ip_text (source_ip_text),
    KEY idx_target_server (target_server),
    KEY idx_target_username (target_username),
    KEY idx_is_anomaly (is_anomaly),
    KEY idx_is_simulation (is_simulation),
    KEY idx_ml_processed (ml_processed),
    KEY idx_simulation_run (simulation_run_id),
    KEY idx_geo (geo_id),

    -- Composite indexes for common queries
    KEY idx_ip_time (source_ip, timestamp),
    KEY idx_server_time (target_server, timestamp),
    KEY idx_sim_time (is_simulation, timestamp),
    KEY idx_type_time (event_type, timestamp),
    KEY idx_anomaly_time (is_anomaly, timestamp),

    FOREIGN KEY (geo_id) REFERENCES ip_geolocation(id) ON DELETE SET NULL,
    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (YEAR(timestamp)) (
    PARTITION p2024 VALUES LESS THAN (2025),
    PARTITION p2025 VALUES LESS THAN (2026),
    PARTITION p2026 VALUES LESS THAN (2027),
    PARTITION pmax VALUES LESS THAN MAXVALUE
)
COMMENT='Unified authentication events with partitioning for performance';

-- ----------------------------------------------------------------------------
-- IP Blocks (Consolidated and improved)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_blocks_v2 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARBINARY(16) NOT NULL,
    ip_address_text VARCHAR(45) NOT NULL,
    ip_range_cidr VARCHAR(50) NULL COMMENT 'CIDR notation if blocking range',

    block_reason VARCHAR(500) NOT NULL,
    block_source ENUM('manual', 'auto_brute_force', 'auto_ml_analysis',
                      'auto_ip_reputation', 'auto_anomaly_detection') NOT NULL,
    block_rule_id INT NULL COMMENT 'FK to blocking_rules if auto-blocked',

    -- Block Status
    is_active BOOLEAN DEFAULT TRUE,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unblock_at TIMESTAMP NULL COMMENT 'Auto-unblock time',
    manually_unblocked_at TIMESTAMP NULL,
    unblocked_by_user_id INT NULL,

    -- Statistics
    attempts_before_block INT DEFAULT 0,
    failed_auth_events INT DEFAULT 0 COMMENT 'Total failed auths from this IP',

    -- Simulation Tracking
    is_simulation BOOLEAN DEFAULT FALSE,
    simulation_run_id INT NULL,

    -- Metadata
    block_metadata JSON NULL COMMENT 'Additional context',
    created_by_user_id INT NULL COMMENT 'User who manually blocked',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_ip_binary (ip_address),
    KEY idx_ip_text (ip_address_text),
    KEY idx_is_active (is_active),
    KEY idx_unblock_at (unblock_at),
    KEY idx_is_simulation (is_simulation),
    KEY idx_block_source (block_source),
    KEY idx_simulation_run (simulation_run_id),

    -- Composite for active blocks lookup
    KEY idx_active_ip (is_active, ip_address),

    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (unblocked_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='IP blocking with range support and audit trail';

-- ----------------------------------------------------------------------------
-- Blocking Rules (Auto-blocking configuration)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocking_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    rule_type ENUM('brute_force', 'ml_threshold', 'reputation_score',
                   'anomaly_pattern', 'geo_restriction') NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,

    -- Rule Conditions (JSON for flexibility)
    conditions JSON NOT NULL COMMENT 'Rule conditions definition',
    /*
    Example for brute_force:
    {
        "failed_attempts": 5,
        "time_window_minutes": 10,
        "unique_usernames": 3
    }

    Example for ml_threshold:
    {
        "min_risk_score": 80,
        "min_confidence": 0.75,
        "threat_types": ["brute_force", "credential_stuffing"]
    }
    */

    -- Actions
    block_duration_minutes INT DEFAULT 1440 COMMENT '1440 = 24 hours',
    auto_unblock BOOLEAN DEFAULT TRUE,
    notify_on_block BOOLEAN DEFAULT FALSE,

    -- Statistics
    times_triggered INT DEFAULT 0,
    last_triggered_at TIMESTAMP NULL,

    -- Metadata
    description TEXT NULL,
    created_by_user_id INT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_rule_type (rule_type),
    KEY idx_is_enabled (is_enabled),
    KEY idx_last_triggered (last_triggered_at),

    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Configurable rules for automatic IP blocking';

-- ----------------------------------------------------------------------------
-- Simulation Runs (Renamed from simulation_history)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS simulation_runs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    run_uuid CHAR(36) NOT NULL COMMENT 'Unique run identifier',

    -- User Information
    user_id INT NULL,
    user_email VARCHAR(255) NULL,

    -- Template Information
    template_name VARCHAR(100) NOT NULL,
    template_display_name VARCHAR(255) NULL,
    template_version VARCHAR(20) NULL,

    -- Configuration
    config JSON NOT NULL COMMENT 'Simulation parameters',

    -- Status & Progress
    status ENUM('pending', 'initializing', 'running', 'paused',
                'completed', 'failed', 'cancelled') DEFAULT 'pending',
    progress_percent TINYINT UNSIGNED DEFAULT 0,

    -- Statistics
    total_events_planned INT DEFAULT 0,
    events_generated INT DEFAULT 0,
    events_processed INT DEFAULT 0,
    ips_blocked INT DEFAULT 0,
    anomalies_detected INT DEFAULT 0,
    alerts_triggered INT DEFAULT 0,

    -- Timing
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    paused_at TIMESTAMP NULL,
    duration_seconds INT NULL,
    estimated_completion TIMESTAMP NULL,

    -- Error Handling
    error_message TEXT NULL,
    error_details JSON NULL,
    retry_count INT DEFAULT 0,

    -- Cleanup
    data_retention_days INT DEFAULT 7,
    auto_cleanup_enabled BOOLEAN DEFAULT TRUE,
    cleaned_up_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY idx_run_uuid (run_uuid),
    KEY idx_user_id (user_id),
    KEY idx_template (template_name),
    KEY idx_status (status),
    KEY idx_created_at (created_at),
    KEY idx_started_at (started_at),
    KEY idx_cleanup (auto_cleanup_enabled, cleaned_up_at),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Simulation execution tracking with enhanced metadata';

-- ----------------------------------------------------------------------------
-- Simulation Logs (Enhanced)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS simulation_logs_v2 (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    simulation_run_id INT NOT NULL,
    log_uuid CHAR(36) NOT NULL,
    timestamp TIMESTAMP(6) NOT NULL COMMENT 'Microsecond precision',
    sequence_number INT NOT NULL,

    -- Log Details
    stage VARCHAR(50) NOT NULL,
    level ENUM('TRACE', 'DEBUG', 'INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL') DEFAULT 'INFO',
    category VARCHAR(50) NULL COMMENT 'init, event_gen, ml_proc, block, cleanup',
    message TEXT NOT NULL,

    -- Context
    ip_address VARCHAR(45) NULL,
    username VARCHAR(255) NULL,
    event_count INT NULL,

    -- Structured Data
    metadata JSON NULL,
    stack_trace TEXT NULL COMMENT 'For errors',

    -- Performance Metrics
    execution_time_ms INT NULL COMMENT 'Execution time for this step',
    memory_usage_mb DECIMAL(10,2) NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY idx_log_uuid (log_uuid),
    KEY idx_simulation_run (simulation_run_id),
    KEY idx_timestamp (timestamp),
    KEY idx_sequence (simulation_run_id, sequence_number),
    KEY idx_level (level),
    KEY idx_stage (stage),
    KEY idx_category (category),

    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Enhanced simulation logging with performance metrics';

-- ----------------------------------------------------------------------------
-- Agents (Enhanced)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agents_v2 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_uuid CHAR(36) NOT NULL,
    agent_id VARCHAR(100) NOT NULL COMMENT 'Human-readable ID',

    -- Agent Information
    hostname VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NULL,
    agent_type ENUM('primary', 'secondary', 'monitor_only') DEFAULT 'secondary',

    -- Network Information
    ip_address_primary VARCHAR(45) NULL,
    ip_address_internal VARCHAR(45) NULL,
    mac_address VARCHAR(17) NULL,

    -- Location & Environment
    location VARCHAR(255) NULL,
    datacenter VARCHAR(100) NULL,
    environment ENUM('production', 'staging', 'development', 'testing') DEFAULT 'production',

    -- Status
    status ENUM('online', 'offline', 'maintenance', 'error', 'unknown') DEFAULT 'unknown',
    health_status ENUM('healthy', 'degraded', 'critical') DEFAULT 'healthy',
    last_heartbeat TIMESTAMP NULL,
    heartbeat_interval_sec INT DEFAULT 30,
    consecutive_missed_heartbeats INT DEFAULT 0,

    -- Version & Configuration
    version VARCHAR(50) NULL,
    config_version VARCHAR(50) NULL,
    supported_features JSON NULL COMMENT 'Array of supported features',

    -- Capabilities
    max_events_per_sec INT DEFAULT 100,
    max_concurrent_connections INT DEFAULT 1000,

    -- Statistics
    total_events_processed BIGINT DEFAULT 0,
    total_uptime_seconds BIGINT DEFAULT 0,
    last_restart_at TIMESTAMP NULL,
    restart_count INT DEFAULT 0,

    -- Management
    is_active BOOLEAN DEFAULT TRUE,
    is_approved BOOLEAN DEFAULT FALSE COMMENT 'Manual approval required',
    notes TEXT NULL,

    -- Metadata
    system_info JSON NULL COMMENT 'OS, CPU, RAM, Disk',
    custom_metadata JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    approved_at TIMESTAMP NULL,
    approved_by_user_id INT NULL,

    UNIQUE KEY idx_agent_uuid (agent_uuid),
    UNIQUE KEY idx_agent_id (agent_id),
    KEY idx_hostname (hostname),
    KEY idx_status (status),
    KEY idx_last_heartbeat (last_heartbeat),
    KEY idx_is_active (is_active),
    KEY idx_environment (environment),
    KEY idx_agent_type (agent_type),

    FOREIGN KEY (approved_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Enhanced agent management with health monitoring';

-- ----------------------------------------------------------------------------
-- Agent Metrics (Time-series data)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_metrics (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    agent_id INT NOT NULL,
    metric_timestamp TIMESTAMP(3) NOT NULL,

    -- System Metrics
    cpu_usage_percent DECIMAL(5,2) NULL,
    cpu_load_1min DECIMAL(5,2) NULL,
    cpu_load_5min DECIMAL(5,2) NULL,
    memory_usage_percent DECIMAL(5,2) NULL,
    memory_used_mb INT NULL,
    memory_available_mb INT NULL,
    disk_usage_percent DECIMAL(5,2) NULL,
    disk_used_gb DECIMAL(10,2) NULL,
    disk_available_gb DECIMAL(10,2) NULL,

    -- Network Metrics
    network_rx_bytes_per_sec BIGINT NULL,
    network_tx_bytes_per_sec BIGINT NULL,
    active_connections INT NULL,

    -- Application Metrics
    events_processed_last_min INT NULL,
    events_in_queue INT NULL,
    processing_time_avg_ms DECIMAL(10,2) NULL,
    error_rate_percent DECIMAL(5,2) NULL,

    -- Status
    health_status ENUM('healthy', 'warning', 'critical') DEFAULT 'healthy',
    alerts_triggered JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    KEY idx_agent (agent_id),
    KEY idx_timestamp (metric_timestamp),
    KEY idx_health (health_status),
    KEY idx_agent_time (agent_id, metric_timestamp),

    FOREIGN KEY (agent_id) REFERENCES agents_v2(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (UNIX_TIMESTAMP(metric_timestamp)) (
    PARTITION p_recent VALUES LESS THAN (UNIX_TIMESTAMP('2025-01-01')),
    PARTITION p_current VALUES LESS THAN MAXVALUE
)
COMMENT='Time-series metrics for agent health monitoring';

-- ----------------------------------------------------------------------------
-- System Alerts
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_uuid CHAR(36) NOT NULL,
    alert_type ENUM('security', 'performance', 'agent_health',
                    'system_error', 'threshold_breach') NOT NULL,
    severity ENUM('info', 'warning', 'error', 'critical') NOT NULL,

    -- Alert Details
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    source VARCHAR(100) NULL COMMENT 'Component that triggered alert',

    -- Related Entities
    agent_id INT NULL,
    simulation_run_id INT NULL,
    ip_address VARCHAR(45) NULL,

    -- Status
    status ENUM('active', 'acknowledged', 'resolved', 'dismissed') DEFAULT 'active',
    acknowledged_at TIMESTAMP NULL,
    acknowledged_by_user_id INT NULL,
    resolved_at TIMESTAMP NULL,
    resolved_by_user_id INT NULL,
    resolution_notes TEXT NULL,

    -- Notifications
    notification_sent BOOLEAN DEFAULT FALSE,
    notification_sent_at TIMESTAMP NULL,
    notification_channels JSON NULL COMMENT 'email, slack, webhook, etc',

    -- Metadata
    alert_data JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY idx_alert_uuid (alert_uuid),
    KEY idx_alert_type (alert_type),
    KEY idx_severity (severity),
    KEY idx_status (status),
    KEY idx_created_at (created_at),
    KEY idx_agent (agent_id),
    KEY idx_simulation_run (simulation_run_id),

    FOREIGN KEY (agent_id) REFERENCES agents_v2(id) ON DELETE SET NULL,
    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE SET NULL,
    FOREIGN KEY (acknowledged_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (resolved_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='System-wide alerts and notifications';

-- ============================================================================
-- STEP 2: Create Views for Backward Compatibility
-- ============================================================================

-- View for failed_logins (backward compatibility)
CREATE OR REPLACE VIEW failed_logins AS
SELECT
    ae.id,
    ae.timestamp,
    ae.target_server AS server_hostname,
    ae.source_ip_text AS source_ip,
    ae.target_username AS username,
    ae.target_port AS port,
    ae.failure_reason,
    ae.raw_log_line AS raw_event_data,
    ig.country_name AS country,
    ig.city,
    ig.latitude,
    ig.longitude,
    ig.timezone,
    1 AS geoip_processed,
    ae.ml_risk_score * 1.0 AS ip_risk_score,
    CASE
        WHEN ig.threat_level = 'clean' THEN 'clean'
        WHEN ig.threat_level IN ('low', 'medium') THEN 'suspicious'
        ELSE 'malicious'
    END AS ip_reputation,
    ae.additional_metadata AS threat_intel_data,
    1 AS ip_health_processed,
    ae.ml_risk_score,
    ae.ml_threat_type,
    ae.ml_confidence,
    ae.is_anomaly,
    ae.ml_processed,
    ae.pipeline_completed,
    ae.created_at,
    ae.updated_at,
    ae.is_simulation,
    ae.simulation_run_id AS simulation_id
FROM auth_events ae
LEFT JOIN ip_geolocation ig ON ae.geo_id = ig.id
WHERE ae.event_type = 'failed';

-- View for successful_logins (backward compatibility)
CREATE OR REPLACE VIEW successful_logins AS
SELECT
    ae.id,
    ae.timestamp,
    ae.target_server AS server_hostname,
    ae.source_ip_text AS source_ip,
    ae.target_username AS username,
    ae.target_port AS port,
    ae.session_duration_sec AS session_duration,
    ae.raw_log_line AS raw_event_data,
    ig.country_name AS country,
    ig.city,
    ig.latitude,
    ig.longitude,
    ig.timezone,
    1 AS geoip_processed,
    ae.ml_risk_score * 1.0 AS ip_risk_score,
    CASE
        WHEN ig.threat_level = 'clean' THEN 'clean'
        WHEN ig.threat_level IN ('low', 'medium') THEN 'suspicious'
        ELSE 'malicious'
    END AS ip_reputation,
    ae.additional_metadata AS threat_intel_data,
    1 AS ip_health_processed,
    ae.ml_risk_score,
    ae.ml_threat_type,
    ae.ml_confidence,
    ae.is_anomaly,
    ae.ml_processed,
    ae.pipeline_completed,
    ae.created_at,
    ae.updated_at,
    ae.is_simulation,
    ae.simulation_run_id AS simulation_id
FROM auth_events ae
LEFT JOIN ip_geolocation ig ON ae.geo_id = ig.id
WHERE ae.event_type = 'successful';

-- View for ip_blocks (backward compatibility)
CREATE OR REPLACE VIEW ip_blocks AS
SELECT
    id,
    ip_address_text AS ip_address,
    block_reason,
    CASE
        WHEN block_source LIKE 'auto%' THEN 'ml_analysis'
        ELSE 'manual'
    END AS block_source,
    blocked_at,
    unblock_at,
    is_active,
    is_simulation,
    simulation_run_id AS simulation_id
FROM ip_blocks_v2;

-- View for agents (backward compatibility)
CREATE OR REPLACE VIEW agents AS
SELECT
    id,
    agent_id,
    hostname,
    display_name,
    ip_address_primary AS ip_address,
    location,
    CASE
        WHEN status = 'online' THEN 'online'
        WHEN status = 'offline' THEN 'offline'
        ELSE 'unknown'
    END AS status,
    last_heartbeat,
    version,
    custom_metadata AS metadata,
    is_active,
    created_at,
    updated_at
FROM agents_v2;

-- View for simulation_history (backward compatibility)
CREATE OR REPLACE VIEW simulation_history AS
SELECT
    id,
    user_id,
    user_email,
    template_name,
    template_display_name,
    config AS request_json,
    CASE
        WHEN status IN ('running', 'paused', 'initializing') THEN 'running'
        WHEN status = 'completed' THEN 'completed'
        WHEN status = 'failed' THEN 'failed'
        WHEN status = 'cancelled' THEN 'cancelled'
        ELSE 'running'
    END AS status,
    total_events_planned AS total_events,
    events_processed,
    ips_blocked,
    alerts_triggered AS alerts_sent,
    error_message,
    created_at,
    completed_at,
    duration_seconds
FROM simulation_runs;

-- ============================================================================
-- STEP 3: Add Indexes for Performance
-- ============================================================================

-- Additional indexes for common query patterns
ALTER TABLE auth_events ADD INDEX idx_full_lookup (source_ip_text, target_server, timestamp);
ALTER TABLE auth_events ADD INDEX idx_ml_analysis (ml_processed, pipeline_completed);
ALTER TABLE ip_blocks_v2 ADD INDEX idx_active_lookup (is_active, is_simulation, ip_address);

-- ============================================================================
-- STEP 4: Create Stored Procedures for Common Operations
-- ============================================================================

DELIMITER $$

-- Procedure to cleanup old simulation data
CREATE PROCEDURE IF NOT EXISTS cleanup_old_simulations()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE sim_id INT;
    DECLARE cur CURSOR FOR
        SELECT id FROM simulation_runs
        WHERE status = 'completed'
        AND auto_cleanup_enabled = TRUE
        AND cleaned_up_at IS NULL
        AND DATE_ADD(completed_at, INTERVAL data_retention_days DAY) < NOW();

    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    OPEN cur;

    cleanup_loop: LOOP
        FETCH cur INTO sim_id;
        IF done THEN
            LEAVE cleanup_loop;
        END IF;

        -- Delete simulation data
        DELETE FROM auth_events WHERE simulation_run_id = sim_id;
        DELETE FROM ip_blocks_v2 WHERE simulation_run_id = sim_id;
        DELETE FROM simulation_logs_v2 WHERE simulation_run_id = sim_id;

        -- Mark as cleaned
        UPDATE simulation_runs SET cleaned_up_at = NOW() WHERE id = sim_id;
    END LOOP;

    CLOSE cur;
END$$

-- Procedure to archive old auth events
CREATE PROCEDURE IF NOT EXISTS archive_old_auth_events(days_old INT)
BEGIN
    DECLARE cutoff_date DATETIME;
    SET cutoff_date = DATE_SUB(NOW(), INTERVAL days_old DAY);

    -- Archive to separate table (create if needed)
    CREATE TABLE IF NOT EXISTS auth_events_archive LIKE auth_events;

    INSERT INTO auth_events_archive
    SELECT * FROM auth_events
    WHERE timestamp < cutoff_date
    AND is_simulation = FALSE;

    DELETE FROM auth_events
    WHERE timestamp < cutoff_date
    AND is_simulation = FALSE;
END$$

-- Procedure to get IP statistics
CREATE PROCEDURE IF NOT EXISTS get_ip_statistics(IN target_ip VARCHAR(45))
BEGIN
    SELECT
        COUNT(*) as total_attempts,
        SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_attempts,
        SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful_attempts,
        COUNT(DISTINCT target_username) as unique_usernames,
        AVG(ml_risk_score) as avg_risk_score,
        MAX(ml_risk_score) as max_risk_score,
        SUM(CASE WHEN is_anomaly = TRUE THEN 1 ELSE 0 END) as anomaly_count,
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen
    FROM auth_events
    WHERE source_ip_text = target_ip
    AND is_simulation = FALSE;
END$$

DELIMITER ;

-- ============================================================================
-- STEP 5: Create Triggers for Data Integrity
-- ============================================================================

DELIMITER $$

-- Trigger to update agent health status based on metrics
CREATE TRIGGER IF NOT EXISTS update_agent_health
AFTER INSERT ON agent_metrics
FOR EACH ROW
BEGIN
    DECLARE health VARCHAR(20);

    IF NEW.cpu_usage_percent > 90 OR NEW.memory_usage_percent > 90 OR NEW.disk_usage_percent > 95 THEN
        SET health = 'critical';
    ELSEIF NEW.cpu_usage_percent > 75 OR NEW.memory_usage_percent > 75 OR NEW.disk_usage_percent > 85 THEN
        SET health = 'degraded';
    ELSE
        SET health = 'healthy';
    END IF;

    UPDATE agents_v2 SET health_status = health WHERE id = NEW.agent_id;
END$$

-- Trigger to auto-expire IP blocks
CREATE TRIGGER IF NOT EXISTS check_block_expiration
BEFORE UPDATE ON ip_blocks_v2
FOR EACH ROW
BEGIN
    IF NEW.is_active = TRUE AND NEW.unblock_at IS NOT NULL AND NEW.unblock_at <= NOW() THEN
        SET NEW.is_active = FALSE;
    END IF;
END$$

DELIMITER ;

-- ============================================================================
-- STEP 6: Insert Default Data
-- ============================================================================

-- Insert default blocking rules
INSERT INTO blocking_rules (rule_name, rule_type, conditions, description, is_enabled) VALUES
('Brute Force Protection', 'brute_force',
 '{"failed_attempts": 5, "time_window_minutes": 10, "unique_usernames": 3}',
 'Block IPs with 5+ failed attempts in 10 minutes across 3+ usernames', TRUE),

('High ML Risk Score', 'ml_threshold',
 '{"min_risk_score": 85, "min_confidence": 0.80}',
 'Block IPs with ML risk score >= 85 and confidence >= 80%', TRUE),

('Critical Reputation Score', 'reputation_score',
 '{"max_reputation_score": 20, "min_threat_reports": 5}',
 'Block IPs with very poor reputation scores', TRUE);

-- ============================================================================
-- NOTES FOR MIGRATION
-- ============================================================================

/*
MIGRATION STEPS:

1. BACKUP CURRENT DATABASE:
   mysqldump -u root -p123123 ssh_guardian_20 > backup_before_migration.sql

2. RUN THIS SCRIPT:
   mysql -u root -p123123 ssh_guardian_20 < 007_redesigned_schema.sql

3. MIGRATE DATA (separate script - 008_migrate_data.sql):
   - Copy failed_logins -> auth_events (event_type='failed')
   - Copy successful_logins -> auth_events (event_type='successful')
   - Extract GeoIP data -> ip_geolocation
   - Copy ip_blocks -> ip_blocks_v2
   - Copy agents -> agents_v2
   - Copy simulation_history -> simulation_runs

4. UPDATE APPLICATION CODE:
   - Update connection.py if needed
   - Test all queries with new views
   - Gradually migrate to new tables

5. VERIFY BACKWARD COMPATIBILITY:
   - All old queries should work through views
   - Simulation should continue working

6. CLEANUP OLD TABLES (after verification):
   - DROP TABLE failed_logins_old;
   - DROP TABLE successful_logins_old;
   - etc.
*/
