"""Validation service for input validation."""
from logger import logger


class ValidationService:
    """Service for validating various inputs."""
    
    @staticmethod
    def is_allowed_file(filename, allowed_extensions):
        """Check if file extension is allowed."""
        logger.debug(f"Validating file: {filename}")
        
        if '.' not in filename:
            logger.warning(f"File has no extension: {filename}")
            return False
        
        ext = filename.rsplit('.', 1)[1].lower()
        is_valid = ext in allowed_extensions
        
        logger.debug(f"File validation result for {filename}: {is_valid}")
        return is_valid
    
    @staticmethod
    def validate_ip(ip):
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return False
    
    @staticmethod
    def validate_search_query(query, max_length=500):
        """Validate search query."""
        if not query or len(query) == 0:
            logger.warning("Empty search query")
            return False, "Query cannot be empty"
        
        if len(query) > max_length:
            logger.warning(f"Search query too long: {len(query)}")
            return False, f"Query cannot exceed {max_length} characters"
        
        return True, "Valid"
    
    @staticmethod
    def validate_port(port):
        """Validate port number."""
        try:
            port_num = int(port)
            if 0 <= port_num <= 65535:
                return True
            logger.warning(f"Port out of range: {port_num}")
            return False
        except (ValueError, TypeError):
            logger.warning(f"Invalid port: {port}")
            return False
