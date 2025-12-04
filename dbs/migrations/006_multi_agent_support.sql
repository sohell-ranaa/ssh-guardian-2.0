-- Multi-Agent Support Migration
-- Adds agents table for managing multiple SSH Guardian agents

-- Create agents table
CREATE TABLE IF NOT EXISTS agents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(100) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    ip_address VARCHAR(45),
    location VARCHAR(255),
    status ENUM('online', 'offline', 'unknown') DEFAULT 'unknown',
    last_heartbeat TIMESTAMP NULL,
    version VARCHAR(50),
    metadata JSON,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_agent_id (agent_id),
    INDEX idx_hostname (hostname),
    INDEX idx_status (status),
    INDEX idx_last_heartbeat (last_heartbeat)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create agent_heartbeats table for tracking agent health
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cpu_usage DECIMAL(5,2),
    memory_usage DECIMAL(5,2),
    disk_usage DECIMAL(5,2),
    active_connections INT,
    events_processed INT,
    status ENUM('healthy', 'warning', 'critical') DEFAULT 'healthy',
    metadata JSON,
    INDEX idx_agent_id (agent_id),
    INDEX idx_timestamp (timestamp),
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed with current server as default agent
INSERT INTO agents (agent_id, hostname, display_name, status, last_heartbeat)
SELECT
    COALESCE(server_hostname, 'default-agent'),
    COALESCE(server_hostname, @@hostname),
    CONCAT('Agent: ', COALESCE(server_hostname, @@hostname)),
    'online',
    MAX(timestamp)
FROM failed_logins
ON DUPLICATE KEY UPDATE
    last_heartbeat = VALUES(last_heartbeat),
    updated_at = CURRENT_TIMESTAMP;
