# SSH Guardian 2.0 - Database Schema Documentation

**Database Name:** `ssh_guardian_20`
**DBMS:** MySQL 8.0+
**Host:** localhost (via Docker container `mysql_server`)
**Port:** 3306
**Credentials:** root / 123123
**Connection Pool Size:** 20 connections
**Character Set:** utf8mb4

---

## Connection Information

**Connection File:** `/home/rana-workspace/ssh_guardian_2.0/dbs/connection.py`

```python
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "123123",
    "database": "ssh_guardian_20",
    "charset": "utf8mb4"
}
```

**Connection Pool:** `ssh_guardian_pool` (20 connections, pool_reset_session=True)

---

## Current Database Tables (16 tables)

### 1. **agents** - Multi-Agent System
Stores SSH Guardian agent information for distributed monitoring.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| agent_id | varchar(100) | NO | UNI | NULL | |
| hostname | varchar(255) | NO | MUL | NULL | |
| display_name | varchar(255) | YES | | NULL | |
| ip_address | varchar(45) | YES | | NULL | |
| location | varchar(255) | YES | | NULL | |
| status | enum('online','offline','unknown') | YES | MUL | unknown | |
| last_heartbeat | timestamp | YES | MUL | NULL | |
| version | varchar(50) | YES | | NULL | |
| metadata | json | YES | | NULL | |
| is_active | tinyint(1) | YES | | 1 | |
| created_at | timestamp | YES | | CURRENT_TIMESTAMP | |
| updated_at | timestamp | YES | | CURRENT_TIMESTAMP | on update |

**Indexes:** agent_id (UNIQUE), hostname (INDEX), status (INDEX), last_heartbeat (INDEX)

---

### 2. **agent_heartbeats** - Agent Health Monitoring
Stores periodic health metrics from each agent.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| agent_id | varchar(100) | NO | MUL | NULL | |
| timestamp | timestamp | YES | MUL | CURRENT_TIMESTAMP | |
| cpu_usage | decimal(5,2) | YES | | NULL | |
| memory_usage | decimal(5,2) | YES | | NULL | |
| disk_usage | decimal(5,2) | YES | | NULL | |
| active_connections | int | YES | | NULL | |
| events_processed | int | YES | | NULL | |
| status | enum('healthy','warning','critical') | YES | | healthy | |
| metadata | json | YES | | NULL | |

**Indexes:** agent_id (INDEX), timestamp (INDEX)

---

### 3. **failed_logins** - Failed SSH Authentication Events
Core table for failed login attempts with ML analysis.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| timestamp | datetime | NO | MUL | NULL | |
| server_hostname | varchar(255) | NO | MUL | NULL | |
| source_ip | varchar(45) | NO | MUL | NULL | |
| username | varchar(255) | YES | MUL | NULL | |
| port | int | YES | | 22 | |
| failure_reason | enum(...) | NO | | NULL | |
| raw_event_data | json | YES | | NULL | |
| country | varchar(100) | YES | | NULL | |
| city | varchar(100) | YES | | NULL | |
| latitude | decimal(10,8) | YES | | NULL | |
| longitude | decimal(11,8) | YES | | NULL | |
| timezone | varchar(50) | YES | | NULL | |
| geoip_processed | tinyint(1) | YES | MUL | 0 | |
| ip_risk_score | int | YES | | 0 | |
| ip_reputation | enum(...) | YES | | unknown | |
| threat_intel_data | json | YES | | NULL | |
| ip_health_processed | tinyint(1) | YES | | 0 | |
| ml_risk_score | int | YES | | 0 | |
| ml_threat_type | varchar(100) | YES | | NULL | |
| ml_confidence | decimal(4,3) | YES | | NULL | |
| is_anomaly | tinyint(1) | YES | MUL | 0 | |
| ml_processed | tinyint(1) | YES | | 0 | |
| pipeline_completed | tinyint(1) | YES | | 0 | |
| created_at | timestamp | YES | | CURRENT_TIMESTAMP | |
| updated_at | timestamp | YES | | CURRENT_TIMESTAMP | on update |
| is_simulation | tinyint(1) | YES | MUL | 0 | |
| simulation_id | int | YES | | NULL | |

**Indexes:** timestamp, server_hostname, source_ip, username, geoip_processed, is_anomaly, is_simulation (ALL INDEXED)

---

### 4. **successful_logins** - Successful SSH Authentication Events
Mirror of failed_logins for successful authentications.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| (Same structure as failed_logins) |
| session_duration | int | YES | | 0 | (ADDED FIELD) |

**Indexes:** Same as failed_logins

---

### 5. **ip_blocks** - IP Blocking Management
Manages blocked IPs with automatic unblocking.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| ip_address | varchar(45) | NO | MUL | NULL | |
| block_reason | varchar(255) | NO | | NULL | |
| block_source | enum(...) | NO | | NULL | |
| blocked_at | timestamp | YES | | CURRENT_TIMESTAMP | |
| unblock_at | timestamp | NO | MUL | NULL | |
| is_active | tinyint(1) | YES | | 1 | |
| is_simulation | tinyint(1) | YES | MUL | 0 | |
| simulation_id | int | YES | | NULL | |

**Indexes:** ip_address (INDEX), unblock_at (INDEX), is_simulation (INDEX)

---

### 6. **blocked_ips** - Legacy IP Blocking (DEPRECATED)
Legacy table, replaced by ip_blocks.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| ip_address | varchar(45) | NO | UNI | NULL | |
| reason | text | YES | | NULL | |
| blocked_at | timestamp | YES | MUL | CURRENT_TIMESTAMP | |
| threat_level | varchar(20) | YES | | NULL | |
| auto_unblock_at | timestamp | YES | | NULL | |

**Status:** Should be migrated to ip_blocks and removed

---

### 7. **processing_queue** - Pipeline Processing Queue
Tracks GeoIP, IP Health, and ML processing stages.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| record_type | enum('successful','failed') | NO | MUL | NULL | |
| record_id | int | NO | | NULL | |
| stage | enum('geoip','ip_health','ml_analysis') | NO | | NULL | |
| status | enum(...) | YES | MUL | pending | |
| retry_count | int | YES | | 0 | |
| last_error | text | YES | | NULL | |
| created_at | timestamp | YES | | CURRENT_TIMESTAMP | |
| updated_at | timestamp | YES | | CURRENT_TIMESTAMP | on update |

**Indexes:** record_type (INDEX), status (INDEX)

---

### 8. **simulation_history** - Simulation Run Tracking
Tracks simulation executions with detailed metrics.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| user_id | int | YES | MUL | NULL | |
| user_email | varchar(255) | YES | | NULL | |
| template_name | varchar(100) | NO | MUL | NULL | |
| template_display_name | varchar(255) | YES | | NULL | |
| request_json | json | NO | | NULL | |
| status | enum(...) | YES | MUL | running | |
| total_events | int | YES | | 0 | |
| events_processed | int | YES | | 0 | |
| ips_blocked | int | YES | | 0 | |
| alerts_sent | int | YES | | 0 | |
| error_message | text | YES | | NULL | |
| created_at | timestamp | YES | MUL | CURRENT_TIMESTAMP | |
| completed_at | timestamp | YES | | NULL | |
| duration_seconds | int | YES | | NULL | |

**Indexes:** user_id, template_name, status, created_at (ALL INDEXED)

---

### 9. **simulation_logs** - Detailed Simulation Logs
Microsecond-precision logs for simulation events.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| simulation_id | int | NO | MUL | NULL | |
| timestamp | timestamp(3) | YES | MUL | CURRENT_TIMESTAMP(3) | |
| sequence_number | int | NO | | NULL | |
| stage | varchar(50) | NO | MUL | NULL | |
| level | enum(...) | YES | | INFO | |
| message | text | NO | | NULL | |
| metadata | json | YES | | NULL | |

**Indexes:** simulation_id, timestamp, stage (ALL INDEXED)

---

### 10. **simulation_ip_pool** - IP Pool for Simulations
Pre-generated IPs for realistic simulations.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| ip_address | varchar(45) | NO | UNI | NULL | |
| pool_type | enum('malicious','trusted','random') | NO | MUL | NULL | |
| country | varchar(100) | YES | | NULL | |
| city | varchar(100) | YES | | NULL | |
| reputation_score | int | YES | MUL | NULL | |
| source | varchar(100) | YES | | NULL | |
| last_updated | timestamp | YES | | CURRENT_TIMESTAMP | on update |

**Indexes:** ip_address (UNIQUE), pool_type (INDEX), reputation_score (INDEX)

---

### 11. **users** - User Authentication & RBAC
User accounts with role-based access control.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| email | varchar(255) | NO | UNI | NULL | |
| password_hash | varchar(255) | NO | | NULL | |
| full_name | varchar(255) | NO | | NULL | |
| role_id | int | NO | MUL | NULL | |
| is_active | tinyint(1) | YES | MUL | 1 | |
| is_email_verified | tinyint(1) | YES | | 0 | |
| last_login | timestamp | YES | | NULL | |
| failed_login_attempts | int | YES | | 0 | |
| locked_until | timestamp | YES | | NULL | |
| created_at | timestamp | YES | | CURRENT_TIMESTAMP | |
| updated_at | timestamp | YES | | CURRENT_TIMESTAMP | on update |
| created_by | int | YES | MUL | NULL | |

**Indexes:** email (UNIQUE), role_id (INDEX), is_active (INDEX), created_by (INDEX)

---

### 12. **roles** - User Roles & Permissions
Role definitions with JSON permissions.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| name | varchar(50) | NO | UNI | NULL | |
| description | text | YES | | NULL | |
| permissions | json | YES | | NULL | |
| created_at | timestamp | YES | | CURRENT_TIMESTAMP | |

**Indexes:** name (UNIQUE)

---

### 13. **user_sessions** - Active User Sessions
Session token management.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| user_id | int | NO | MUL | NULL | |
| session_token | varchar(255) | NO | UNI | NULL | |
| ip_address | varchar(45) | YES | | NULL | |
| user_agent | text | YES | | NULL | |
| expires_at | timestamp | NO | MUL | NULL | |
| created_at | timestamp | YES | | CURRENT_TIMESTAMP | |
| last_activity | timestamp | YES | | CURRENT_TIMESTAMP | on update |

**Indexes:** user_id (INDEX), session_token (UNIQUE), expires_at (INDEX)

---

### 14. **user_otps** - One-Time Passwords
OTP codes for 2FA and email verification.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| user_id | int | NO | MUL | NULL | |
| otp_code | varchar(6) | NO | | NULL | |
| purpose | enum(...) | YES | MUL | login | |
| expires_at | timestamp | NO | MUL | NULL | |
| is_used | tinyint(1) | YES | | 0 | |
| used_at | timestamp | YES | | NULL | |
| ip_address | varchar(45) | YES | | NULL | |
| created_at | timestamp | YES | | CURRENT_TIMESTAMP | |

**Indexes:** user_id (INDEX), purpose (INDEX), expires_at (INDEX)

---

### 15. **audit_logs** - System Audit Trail
Complete audit trail for all user actions.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | bigint | NO | PRI | NULL | auto_increment |
| user_id | int | YES | MUL | NULL | |
| action | varchar(100) | NO | MUL | NULL | |
| resource_type | varchar(50) | YES | | NULL | |
| resource_id | varchar(100) | YES | | NULL | |
| details | json | YES | | NULL | |
| ip_address | varchar(45) | YES | | NULL | |
| user_agent | text | YES | | NULL | |
| created_at | timestamp | YES | MUL | CURRENT_TIMESTAMP | |

**Indexes:** user_id (INDEX), action (INDEX), created_at (INDEX)

---

### 16. **security_settings** - System Configuration
Key-value store for security settings.

| Column | Type | Nullable | Key | Default | Extra |
|--------|------|----------|-----|---------|-------|
| id | int | NO | PRI | NULL | auto_increment |
| setting_key | varchar(100) | NO | UNI | NULL | |
| setting_value | text | NO | | NULL | |
| description | text | YES | | NULL | |
| updated_at | timestamp | YES | | CURRENT_TIMESTAMP | on update |

**Indexes:** setting_key (UNIQUE)

---

## Issues Identified in Current Schema

### 1. **Table Duplication**
- `blocked_ips` and `ip_blocks` serve the same purpose
- Recommend: Migrate to `ip_blocks` and drop `blocked_ips`

### 2. **Missing Foreign Keys**
- No explicit foreign key constraints defined
- `simulation_id` references should have FK constraints
- `agent_id`, `user_id`, `role_id` should have FK constraints

### 3. **Index Optimization Needed**
- Composite indexes missing for common query patterns
- Example: `(source_ip, timestamp)`, `(server_hostname, timestamp)`

### 4. **Data Type Issues**
- `ip_address` uses varchar(45) - should consider INET6 type or VARBINARY(16)
- `timestamp` inconsistency - some use datetime, others timestamp

### 5. **Normalization Issues**
- GeoIP data repeated in both tables (country, city, lat, lon)
- Should extract to separate `ip_geolocation` table

### 6. **Missing Indexes for Reporting**
- Live Stream queries need: `(is_simulation, timestamp)`
- Analytics need: `(source_ip, timestamp)`

---

## Recommended Next Steps

1. ✅ **Document current schema** (DONE)
2. 🔄 **Design new optimized schema**
3. 📝 **Create migration scripts**
4. 🧪 **Test migrations on backup**
5. 🚀 **Deploy new schema**
6. 🔒 **Add foreign key constraints**
7. 📊 **Optimize indexes for queries**
8. 🗑️ **Remove deprecated tables**

---

**Last Updated:** 2025-12-04
**Version:** 2.0 Current State
