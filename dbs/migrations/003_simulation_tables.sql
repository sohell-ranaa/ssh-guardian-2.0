-- SSH Guardian 2.0 - Simulation Feature Database Schema
-- Migration 003: Attack Simulation and Testing Framework
-- Created: 2025-12-03

USE ssh_guardian_20;

-- Simulation History Table
-- Stores metadata for each simulation run
CREATE TABLE IF NOT EXISTS simulation_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    user_email VARCHAR(255),
    template_name VARCHAR(100) NOT NULL,
    template_display_name VARCHAR(255),
    request_json JSON NOT NULL,
    status ENUM('running', 'completed', 'failed', 'cancelled') DEFAULT 'running',
    total_events INT DEFAULT 0,
    events_processed INT DEFAULT 0,
    ips_blocked INT DEFAULT 0,
    alerts_sent INT DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    duration_seconds INT,

    INDEX idx_user_id (user_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at DESC),
    INDEX idx_template (template_name),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Simulation Logs Table
-- Stores detailed verbose logs for each simulation step
CREATE TABLE IF NOT EXISTS simulation_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    simulation_id INT NOT NULL,
    timestamp TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP(3),
    sequence_number INT NOT NULL,
    stage VARCHAR(50) NOT NULL,
    level ENUM('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'DEBUG') DEFAULT 'INFO',
    message TEXT NOT NULL,
    metadata JSON,

    INDEX idx_simulation_id (simulation_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_stage (stage),
    INDEX idx_sequence (simulation_id, sequence_number),

    FOREIGN KEY (simulation_id) REFERENCES simulation_history(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Simulation IP Pool Table
-- Pre-populated malicious IPs for quick simulation access
CREATE TABLE IF NOT EXISTS simulation_ip_pool (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    pool_type ENUM('malicious', 'trusted', 'random') NOT NULL,
    country VARCHAR(100),
    city VARCHAR(100),
    reputation_score INT,
    source VARCHAR(100),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_pool_type (pool_type),
    INDEX idx_ip (ip_address),
    INDEX idx_reputation (reputation_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add simulation flag to existing log tables
-- This allows filtering real events from simulated ones
ALTER TABLE failed_logins
ADD COLUMN IF NOT EXISTS is_simulation BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS simulation_id INT,
ADD INDEX idx_simulation (is_simulation, simulation_id);

ALTER TABLE successful_logins
ADD COLUMN IF NOT EXISTS is_simulation BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS simulation_id INT,
ADD INDEX idx_simulation (is_simulation, simulation_id);

-- Add simulation flag to ip_blocks table
ALTER TABLE ip_blocks
ADD COLUMN IF NOT EXISTS is_simulation BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS simulation_id INT,
ADD INDEX idx_simulation (is_simulation, simulation_id);

-- Cleanup job for old simulation data (runs manually or via cron)
-- Delete simulation logs older than 30 days
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS cleanup_old_simulations()
BEGIN
    DECLARE deleted_count INT;

    -- Delete old simulation logs
    DELETE FROM simulation_logs
    WHERE simulation_id IN (
        SELECT id FROM simulation_history
        WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
    );

    -- Delete old simulation history
    DELETE FROM simulation_history
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);

    -- Get count
    SET deleted_count = ROW_COUNT();

    SELECT CONCAT('Deleted ', deleted_count, ' old simulation records') AS result;
END //
DELIMITER ;

-- Optional: Create event to auto-cleanup (requires EVENT scheduler enabled)
-- SET GLOBAL event_scheduler = ON;
-- CREATE EVENT IF NOT EXISTS evt_cleanup_simulations
-- ON SCHEDULE EVERY 1 DAY
-- STARTS CURRENT_TIMESTAMP
-- DO CALL cleanup_old_simulations();

COMMIT;
