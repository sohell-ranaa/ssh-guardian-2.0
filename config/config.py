import os
from dotenv import load_dotenv
from pathlib import Path

class Config:
    def __init__(self):
        # Load .env file from project root
        env_path = Path(__file__).parent.parent.parent / '.env'
        load_dotenv(env_path)
        
        # Telegram settings
        self.telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
        
        # Database settings
        self.db_host = os.getenv('DB_HOST', 'localhost')
        self.db_user = os.getenv('DB_USER', 'sshguardian')
        self.db_password = os.getenv('DB_PASSWORD', 'guardian123')
        self.db_name = os.getenv('DB_NAME', 'ssh_guardian_dev')
        
        # Alert thresholds
        self.alert_risk_threshold = int(os.getenv('ALERT_RISK_THRESHOLD', 70))
        self.auto_block_threshold = int(os.getenv('AUTO_BLOCK_THRESHOLD', 85))
        
        # API keys
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        
        # Validate critical settings
        self.validate()
    
    def validate(self):
        """Validate critical configuration"""
        missing = []
        
        if not self.telegram_bot_token:
            missing.append('TELEGRAM_BOT_TOKEN')
        if not self.telegram_chat_id:
            missing.append('TELEGRAM_CHAT_ID')
        
        if missing:
            print(f"⚠️  Missing required environment variables: {missing}")
            print(f"   Please check your .env file")
            return False
        
        print("✅ Configuration loaded successfully")
        return True
    
    def get_telegram_config(self):
        """Get Telegram configuration"""
        return {
            'bot_token': self.telegram_bot_token,
            'chat_id': self.telegram_chat_id
        }

# Global config instance
config = Config()