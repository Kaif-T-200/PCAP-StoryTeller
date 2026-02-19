"""Logging configuration for PCAP StoryTeller."""
import os
import logging
from datetime import datetime

def setup_logger():
    """Configure logging with session-based log files."""
    # Create logs directory
    logs_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'logs'
    )
    os.makedirs(logs_dir, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger('PCAP_StoryTeller')
    logger.setLevel(logging.DEBUG)
    
    # Session log file format: 18FEB_143025.log (day + month + time)
    now = datetime.now()
    day = now.day
    month = now.strftime('%b').upper()  # Short month (FEB, JAN, MAR)
    time_str = now.strftime('%H%M%S')  # HHMMSS format
    
    log_filename = f"{day}{month}_{time_str}.log"
    log_path = os.path.join(logs_dir, log_filename)
    
    # File handler for this session (no rotation, new file per session)
    file_handler = logging.FileHandler(log_path, mode='w')
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    # Log session start
    logger.info("=" * 70)
    logger.info(f"NEW SESSION STARTED - Log file: {log_filename}")
    logger.info("=" * 70)
    
    return logger

# Initialize logger
logger = setup_logger()
logger = setup_logger()
