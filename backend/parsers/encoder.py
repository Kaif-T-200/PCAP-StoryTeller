"""Custom JSON encoder for PCAP data."""
import json
import decimal


class EnhancedJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles bytes, decimals, and datetime objects."""
    
    def default(self, o):
        """Convert non-serializable objects to serializable format."""
        if isinstance(o, bytes):
            return o.decode('utf-8', errors='ignore')
        if hasattr(o, 'isoformat'):
            return o.isoformat()
        if isinstance(o, decimal.Decimal):
            return float(o)
        return super().default(o)
