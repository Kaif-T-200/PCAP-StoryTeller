import json
from collections import defaultdict
import requests
import ipaddress

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
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]

        if self._is_private_ip(ip):
            return {'ip': ip, 'type': 'private', 'country': 'Internal'}

        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=2)
            if response.status_code == 200:
                data = response.json()
                geo_data = {
                    'ip': ip,
                    'country': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'latitude': float(data.get('latitude', 0)),
                    'longitude': float(data.get('longitude', 0)),
                    'asn': data.get('asn', 'Unknown'),
                    'org': data.get('org', 'Unknown')
                }
                self.geoip_cache[ip] = geo_data
                return geo_data
        except:
            pass

        return {'ip': ip, 'country': 'Unknown', 'type': 'external'}

    def get_threat_summary(self):
        scores = [self.get_threat_score(e['id']) for e in self.events]
        avg_score = sum(scores) / len(scores) if scores else 0

        high_threat_events = [e for e in self.events if self.get_threat_score(e['id']) >= 60]

        return {
            'overall_score': round(avg_score, 1),
            'threat_level': self._score_to_level(avg_score),
            'high_threat_count': len(high_threat_events),
            'pattern_count': len(self.attack_patterns),
            'patterns': self.attack_patterns[:5]
        }

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
