"""
Logging module for the framework
"""

import logging
import sys
from datetime import datetime
import os

def setup_logger(name='attack_defense_framework'):
    """Setup and configure logger"""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '[%(levelname)s] %(message)s'
    )
    
    # File handler
    log_file = f"logs/framework_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

class FrameworkLogger:
    """Custom logger for framework operations"""
    
    def __init__(self):
        self.logger = setup_logger()
        
    def log_scan_start(self, target_ip):
        """Log scan start"""
        self.logger.info(f"Starting reconnaissance scan for {target_ip}")
        
    def log_scan_complete(self, target_ip, results_count):
        """Log scan completion"""
        self.logger.info(f"Scan completed for {target_ip}: {results_count} services found")
        
    def log_exploit_attempt(self, target_ip, exploit_name):
        """Log exploit attempt"""
        self.logger.warning(f"Attempting exploit {exploit_name} on {target_ip}")
        
    def log_exploit_result(self, target_ip, exploit_name, success):
        """Log exploit result"""
        status = "SUCCESS" if success else "FAILED"
        self.logger.warning(f"Exploit {exploit_name} on {target_ip}: {status}")
        
    def log_defense_recommendations(self, count):
        """Log defense recommendations"""
        self.logger.info(f"Generated {count} defense recommendations")
        
    def log_error(self, operation, error):
        """Log error"""
        self.logger.error(f"{operation} error: {error}")
        
    def log_security_event(self, event_type, details):
        """Log security-related event"""
        self.logger.warning(f"SECURITY EVENT: {event_type} - {details}")