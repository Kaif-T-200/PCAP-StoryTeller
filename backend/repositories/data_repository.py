"""Data repository for loading and managing report data."""
import json
import os
from logger import logger


class DataRepository:
    """Repository pattern for data access and management."""
    
    @staticmethod
    def load_report_data():
        """Load report data from events.json."""
        try:
            # events.json is in backend/ folder, not repositories/
            events_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                'events.json'
            )
            
            if not os.path.exists(events_file):
                logger.warning("events.json not found")
                return None
            
            with open(events_file, 'r') as f:
                data = json.load(f)
            
            logger.info(f"Loaded {len(data.get('events', []))} events from repository")
            return data
        
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in events.json: {e}")
            return None
        except Exception as e:
            logger.error(f"Error loading report data: {e}")
            return None
    
    @staticmethod
    def save_report_data(data):
        """Save report data to events.json."""
        try:
            # events.json is in backend/ folder, not repositories/
            events_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                'events.json'
            )
            
            with open(events_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {len(data.get('events', []))} events to repository")
            return True
        
        except Exception as e:
            logger.error(f"Error saving report data: {e}")
            return False
    
    @staticmethod
    def get_all_ips(data):
        """Extract all unique IPs from events."""
        ips = set()
        for event in data.get('events', []):
            src = event.get('source_ip')
            dst = event.get('dest_ip')
            if src:
                ips.add(src)
            if dst:
                ips.add(dst)
        
        logger.info(f"Extracted {len(ips)} unique IPs")
        return ips
