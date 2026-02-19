"""Main PCAP parser - coordinates all packet parsing (under 101 lines)."""
import sys
import os
import json
import ipaddress
from collections import defaultdict
from scapy.all import rdpcap
from parsers.encoder import EnhancedJSONEncoder
from parsers.network_parser import parse_tcp_connection, parse_icmp, parse_arp
from parsers.dns_parser import parse_dns_query, parse_dns_response
from parsers.http_parser import parse_http_request, parse_http_response
from parsers.tls_parser import parse_tls_client_hello

# Protocol support check
HAS_HTTP = HAS_TLS = False
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAS_HTTP = True
except ImportError:
    pass
try:
    from scapy.layers.tls.all import TLS, TLSClientHello
    HAS_TLS = True
except ImportError:
    try:
        from scapy.layers.ssl_tls import TLS, TLSClientHello
        HAS_TLS = True
    except ImportError:
        pass


class PCAPParser:
    """Orchestrates packet parsing using specialized parsers."""
    
    def __init__(self, pcap_file):
        print(f"[*] Loading: {pcap_file}")
        self.packets = rdpcap(pcap_file)
        print(f"[+] Loaded {len(self.packets)} packets")
        self.events, self.links, self.flows = [], [], {}
        self.dns_map, self.ip_to_domain = defaultdict(list), {}
        self.event_counter = 1

    def _get_flow_key(self, pkt):
        if pkt.haslayer('IP'):
            ip = pkt['IP']
            if pkt.haslayer('TCP'):
                return (ip.src, pkt['TCP'].sport, ip.dst, pkt['TCP'].dport, ip.proto)
            elif pkt.haslayer('UDP'):
                return (ip.src, pkt['UDP'].sport, ip.dst, pkt['UDP'].dport, ip.proto)
        return None

    def _add_event(self, event_type, ts, src, dst, details, desc):
        event = {'id': self.event_counter, 'timestamp': float(ts), 'type': event_type,
                 'source_ip': src, 'dest_ip': dst, 'details': details, 'description': desc}
        self.events.append(event)
        self.event_counter += 1
        return event['id']

    def _add_link(self, source_id, target_id, label):
        self.links.append({'source': source_id, 'target': target_id, 'label': label})

    def parse(self):
        """Parse all packets."""
        for pkt in self.packets:
            parse_tcp_connection(pkt, self)
        
        for pkt in self.packets:
            if not pkt.haslayer('IP'):
                continue
            ts, src, dst = float(pkt.time), pkt['IP'].src, pkt['IP'].dst
            
            if pkt.haslayer('DNSQR') and not pkt.haslayer('DNSRR'):
                parse_dns_query(pkt, self, ts, src, dst)
            elif pkt.haslayer('DNSRR'):
                parse_dns_response(pkt, self, ts, src, dst)
            
            if HAS_HTTP:
                if pkt.haslayer('HTTPRequest'):
                    parse_http_request(pkt, self, ts, src, dst)
                elif pkt.haslayer('HTTPResponse'):
                    parse_http_response(pkt, self, ts, src, dst)
            
            if HAS_TLS and pkt.haslayer('TLS') and pkt.haslayer('TLSClientHello'):
                parse_tls_client_hello(pkt, self, ts, src, dst)
            
            if pkt.haslayer('ICMP'):
                parse_icmp(pkt, self, ts, src, dst)
            if pkt.haslayer('ARP'):
                parse_arp(pkt, self, ts)
        
        return self.events, self.links


def main(pcap_file):
    """Entry point."""
    parser = PCAPParser(pcap_file)
    events, links = parser.parse()
    output_path = os.path.join(os.path.dirname(__file__), 'events.json')
    with open(output_path, 'w') as f:
        json.dump({'events': events, 'links': links}, f, indent=4, cls=EnhancedJSONEncoder)
    print(f"[+] Wrote {len(events)} events, {len(links)} links")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("Usage: python pcap_parser.py <pcap_file>")
    main(sys.argv[1])
