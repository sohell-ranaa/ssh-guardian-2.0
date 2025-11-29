"""
Centralized Database Connection Module
Used across entire application
"""
import mysql.connector
from mysql.connector import pooling, Error
import os

# Database Configuration
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "123123",
    "database": "ssh_guardian_20",
    "charset": "utf8mb4"
}

# Connection Pool (reusable connections)
try:
    connection_pool = pooling.MySQLConnectionPool(
        pool_name="ssh_guardian_pool",
        pool_size=10,
        pool_reset_session=True,
        **DB_CONFIG
    )
    print("✅ Database connection pool created successfully")
except Error as e:
    print(f"❌ Error creating connection pool: {e}")
    connection_pool = None


def get_connection():
    """
    Get a connection from the pool
    Returns: mysql.connector connection object
    """
    try:
        if connection_pool:
            return connection_pool.get_connection()
        else:
            # Fallback to direct connection
            return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print(f"❌ Error getting connection: {e}")
        raise


def test_connection():
    """
    Test database connection
    Returns: True if successful, False otherwise
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION(), DATABASE(), USER()")
        result = cursor.fetchone()
        
        print("=" * 60)
        print("📊 DATABASE CONNECTION TEST")
        print("=" * 60)
        print(f"MySQL Version: {result[0]}")
        print(f"Database: {result[1]}")
        print(f"User: {result[2]}")
        print("=" * 60)
        print("✅ Connection successful!")
        
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        print(f"❌ Connection test failed: {e}")
        return False


if __name__ == "__main__":
    # Run test when executed directly
    test_connection()