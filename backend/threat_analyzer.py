import json
from collections import defaultdict
import requests
import ipaddress
import time

SUSPICIOUS_PORTS = {
    445: 'SMB',
    139: 'NetBIOS',
    3389: 'RDP',
    22: 'SSH',
    23: 'Telnet',
    21: 'FTP',
    5900: 'VNC',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    9200: 'Elasticsearch'
}

SCAN_PORTS = {80, 443, 8080, 8443, 22, 3389, 445, 139, 21, 25, 53, 123}

class ThreatAnalyzer:
    def __init__(self, events, links):
        self.events = events
        self.links = links
        self.ip_reputation = {}
        self.attack_patterns = []
        self.threat_scores = {}
        self.geoip_cache = {}

    def get_threat_score(self, event_id):
        if event_id in self.threat_scores:
            return self.threat_scores[event_id]
        
        event = next((e for e in self.events if e['id'] == event_id), None)
        if not event:
            return 0
        
        score = 0
        event_type = event.get('type', '')
        details = event.get('details', {})
        src = event.get('source_ip', '')
        dst = event.get('dest_ip', '')

        if event_type == 'TCP Connection':
            dport = details.get('dport', 0)
            if dport in SUSPICIOUS_PORTS:
                score += 30
            if dport < 1024:
                score += 15
            if dport in SCAN_PORTS:
                score += 10

        elif event_type == 'DNS Query':
            query = details.get('query', '').lower()
            if any(x in query for x in ['malware', 'phishing', 'c2', 'exploit']):
                score += 40
            if len(query) > 50:
                score += 15

        elif event_type == 'HTTP Request':
            method = details.get('method', '').upper()
            if method in ['POST', 'PUT']:
                score += 15
            if 'user_agent' in details and not details['user_agent']:
                score += 10

        elif event_type == 'TLS SNI':
            sni = details.get('sni', '').lower()
            if any(x in sni for x in ['dynamic', 'pastebin', 'webhook']):
                score += 25

        elif event_type == 'ICMP':
            score += 5

        if src and not self._is_private_ip(src):
            score += 10

        self.threat_scores[event_id] = min(score, 100)
        return self.threat_scores[event_id]

    def detect_patterns(self):
        patterns = []

        tcp_conns = [e for e in self.events if e['type'] == 'TCP Connection']
        if len(tcp_conns) > 5:
            src_ips = defaultdict(set)
            for event in tcp_conns:
                src = event.get('source_ip')
                dst = event.get('dest_ip')
                dport = event.get('details', {}).get('dport')
                if src and dport:
                    src_ips[src].add(dport)
            
            for src, ports in src_ips.items():
                if len(ports) > 10:
                    patterns.append({
                        'type': 'port_scanning',
                        'severity': 'HIGH',
                        'source': src,
                        'description': f'Port scanning detected from {src} ({len(ports)} unique ports)',
                        'indicators': list(ports)[:5]
                    })

        dns_queries = {e['id']: e for e in self.events if e['type'] == 'DNS Query'}
        for dns_event in dns_queries.values():
            domain = dns_event['details'].get('query', '')
            child_links = [l for l in self.links if l['source'] == dns_event['id']]
            if child_links:
                patterns.append({
                    'type': 'dns_to_connection',
                    'severity': 'MEDIUM',
                    'domain': domain,
                    'description': f'DNS query for {domain} followed by network connection',
                    'dns_id': dns_event['id']
                })

        http_requests = [e for e in self.events if e['type'] == 'HTTP Request']
        if len(http_requests) > 3:
            patterns.append({
                'type': 'data_exfil_risk',
                'severity': 'MEDIUM',
                'description': f'Multiple HTTP requests detected ({len(http_requests)}). Possible data exfiltration.',
                'indicators': len(http_requests)
            })

        self.attack_patterns = patterns
        return patterns

    def analyze_geoip(self, ip):
        """GeoIP lookup with better error handling and retry logic."""
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]
        
        # Skip private IPs
        if self._is_private_ip(ip):
            result = {
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
            self.geoip_cache[ip] = result
            return result
        
        # Try ipinfo.io first (better free tier)
        try:
            response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
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
                    self.geoip_cache[ip] = result
                    return result
        except Exception as e:
            print(f"ipinfo.io lookup failed for {ip}: {str(e)}")
        
        # Fallback to ip-api.com with delay to avoid rate limit
        try:
            time.sleep(0.2)  # Add small delay
            response = requests.get(f'https://ip-api.com/json/{ip}', timeout=5)
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
                    self.geoip_cache[ip] = result
                    return result
        except Exception as e:
            print(f"ip-api.com lookup failed for {ip}: {str(e)}")
        
        # Return unknown if all APIs fail
        result = {
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
        self.geoip_cache[ip] = result
        return result

    def get_threat_summary(self):
        if not self.attack_patterns:
            self.detect_patterns()

        scores = [self.get_threat_score(e['id']) for e in self.events]
        avg_score = sum(scores) / len(scores) if scores else 0

        pattern_score = self._get_pattern_score()
        overall_score = min(100, max(avg_score, pattern_score))

        high_threat_events = [e for e in self.events if self.get_threat_score(e['id']) >= 60]

        return {
            'overall_score': round(overall_score, 1),
            'threat_level': self._score_to_level(overall_score),
            'high_threat_count': len(high_threat_events),
            'pattern_count': len(self.attack_patterns),
            'patterns': self.attack_patterns[:5]
        }

    def _get_pattern_score(self):
        severity_weights = {
            'CRITICAL': 40,
            'HIGH': 25,
            'MEDIUM': 12,
            'LOW': 5
        }

        total = 0
        for pattern in self.attack_patterns:
            sev = str(pattern.get('severity', '')).upper()
            total += severity_weights.get(sev, 5)

        return min(total, 100)

    def _score_to_level(self, score):
        if score >= 70:
            return 'CRITICAL'
        if score >= 50:
            return 'HIGH'
        if score >= 30:
            return 'MEDIUM'
        return 'LOW'

    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
