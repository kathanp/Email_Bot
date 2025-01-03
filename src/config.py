# src/config.py

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    # Email Settings
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SENDER_EMAIL = "your-email@gmail.com"
    SENDER_PASSWORD = "your-app-specific-password"
    
    # File Settings
    INPUT_DIR = "data/input"
    LOG_DIR = "logs"
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    # Processing Settings
    DELAY_BETWEEN_EMAILS = 1  # seconds
    LOG_LEVEL = "INFO"
    
    @classmethod
    def validate_config(cls):
        required_settings = [
            'SMTP_SERVER', 'SMTP_PORT', 'SENDER_EMAIL', 
            'SENDER_PASSWORD', 'INPUT_DIR', 'LOG_DIR'
        ]
        
        for setting in required_settings:
            if not hasattr(cls, setting) or not getattr(cls, setting):
                raise ValueError(f"Missing required configuration: {setting}")