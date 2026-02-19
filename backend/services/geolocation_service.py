"""Geolocation service for IP location analysis."""
import requests
import ipaddress
import time
from logger import logger


class GeolocationService:
    """Service for geolocation lookups and IP analysis."""
    
    def __init__(self):
        self.cache = {}
        self.api_timeout = 5
        self.rate_limit_delay = 0.2
    
    def analyze_ip(self, ip):
        """Analyze a single IP address for geolocation."""
        logger.debug(f"Analyzing IP: {ip}")
        
        if ip in self.cache:
            logger.debug(f"Cache hit for IP: {ip}")
            return self.cache[ip]
        
        # Check if private IP
        if self._is_private_ip(ip):
            result = self._create_private_ip_result(ip)
            self.cache[ip] = result
            return result
        
        # Try geolocation APIs
        result = self._lookup_ipinfo(ip)
        if result:
            self.cache[ip] = result
            return result
        
        result = self._lookup_ip_api(ip)
        if result:
            self.cache[ip] = result
            return result
        
        # Return unknown if all APIs fail
        result = self._create_unknown_result(ip)
        self.cache[ip] = result
        return result
    
    def analyze_all_ips(self, ips, limit=50):
        """Analyze multiple IPs for geolocation."""
        logger.info(f"Analyzing {min(len(ips), limit)} IPs for geolocation")
        results = []
        
        for ip in list(ips)[:limit]:
            result = self.analyze_ip(ip)
            results.append(result)
        
        logger.info(f"Geolocation analysis complete: {len(results)} IPs processed")
        return results
    
    def _lookup_ipinfo(self, ip):
        """Lookup IP using ipinfo.io API."""
        try:
            logger.debug(f"Querying ipinfo.io for {ip}")
            response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=self.api_timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'loc' in data:
                    lat, lon = data['loc'].split(',')
                    result = {
                        'ip': ip,
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': float(lat),
                        'longitude': float(lon),
                        'isp': data.get('org', 'Unknown'),
                        'type': 'external',
                        'timezone': data.get('timezone', ''),
                        'asn': data.get('org', '').split()[0] if data.get('org') else '',
                        'reverse_dns': data.get('hostname', '')
                    }
                    logger.debug(f"ipinfo.io success for {ip}: {result['country']}")
                    return result
        except Exception as e:
            logger.debug(f"ipinfo.io lookup failed for {ip}: {str(e)}")
        
        return None
    
    def _lookup_ip_api(self, ip):
        """Lookup IP using ip-api.com (fallback)."""
        try:
            time.sleep(self.rate_limit_delay)
            logger.debug(f"Querying ip-api.com for {ip}")
            response = requests.get(f'https://ip-api.com/json/{ip}', timeout=self.api_timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result = {
                        'ip': ip,
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp', 'Unknown'),
                        'type': 'external',
                        'timezone': data.get('timezone', ''),
                        'asn': data.get('as', '').split()[0] if data.get('as') else '',
                        'reverse_dns': data.get('reverse', '')
                    }
                    logger.debug(f"ip-api.com success for {ip}: {result['country']}")
                    return result
        except Exception as e:
            logger.debug(f"ip-api.com lookup failed for {ip}: {str(e)}")
        
        return None
    
    def _is_private_ip(self, ip):
        """Check if IP is private."""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def _create_private_ip_result(self, ip):
        """Create result object for private IP."""
        return {
            'ip': ip,
            'country': 'Private',
            'city': 'Internal Network',
            'latitude': None,
            'longitude': None,
            'isp': 'Private/Internal',
            'type': 'private',
            'timezone': '',
            'asn': '',
            'reverse_dns': ''
        }
    
    def _create_unknown_result(self, ip):
        """Create result object for unknown IP."""
        return {
            'ip': ip,
            'country': 'Unknown',
            'city': 'Unable to Determine',
            'latitude': None,
            'longitude': None,
            'isp': 'Unknown',
            'type': 'external',
            'timezone': '',
            'asn': '',
            'reverse_dns': ''
        }
