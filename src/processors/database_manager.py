import sys
sys.path.append('/home/rana-workspace/ssh_guardian_2.0')

from dbs.connection import get_connection    # Reuse existing
import json
from datetime import datetime

class DatabaseManager:
    """Manages database operations for SSH security pipeline"""
    
    def __init__(self):
        self.connection = get_connection()
        print("✅ Database manager initialized (reusing existing connection)")
    
    def save_successful_login(self, event):
        """Save successful login to database"""
        cursor = self.connection.cursor()
        
        query = """
        INSERT INTO successful_logins (
            timestamp, server_hostname, source_ip, username, port,
            session_duration, raw_event_data
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat())),
            event.get('hostname', 'unknown'),
            event.get('source_ip', 'unknown'),
            event.get('username', 'unknown'),
            event.get('port', 22),
            event.get('session_duration', 0),
            json.dumps(event)  # Store complete event as requested
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        return cursor.lastrowid
    
    def save_failed_login(self, event):
        """Save failed login to database"""
        cursor = self.connection.cursor()
        
        # Determine failure reason
        event_type = str(event.get('event_type', '')).lower()
        if 'invalid' in event_type and 'user' in event_type:
            failure_reason = 'invalid_user'
        elif 'failed' in event_type:
            failure_reason = 'invalid_password'
        else:
            failure_reason = 'other'
        
        query = """
        INSERT INTO failed_logins (
            timestamp, server_hostname, source_ip, username, port,
            failure_reason, raw_event_data
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat())),
            event.get('hostname', 'unknown'),
            event.get('source_ip', 'unknown'),
            event.get('username', ''),
            event.get('port', 22),
            failure_reason,
            json.dumps(event)  # Store complete event as requested
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        return cursor.lastrowid

if __name__ == "__main__":
    # Test database setup
    db = DatabaseManager()
    print("🧪 Database schema ready for SSH security pipeline!")