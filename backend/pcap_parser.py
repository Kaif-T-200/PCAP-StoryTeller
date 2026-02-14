import sys
import os
import json
import decimal
import ipaddress
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
from scapy.layers.inet6 import IPv6

try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False
    print("[!] HTTP layer not available. Install with: pip install scapy-http", file=sys.stderr)

try:
    from scapy.layers.tls.all import TLS, TLSClientHello
    HAS_TLS = True
except ImportError:
    try:
        from scapy.layers.ssl_tls import TLS, TLSClientHello
        HAS_TLS = True
    except ImportError:
        HAS_TLS = False
        print("[!] TLS layer not available in Scapy. For TLS analysis, a compatible version of Scapy with TLS support is needed.", file=sys.stderr)


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode('utf-8', errors='ignore')
        if hasattr(o, 'isoformat'):
            return o.isoformat()
        if isinstance(o, decimal.Decimal):
            return float(o)
        return super().default(o)


class PCAPParser:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
        self.events = []
        self.links = []
        self.flows = {}
        self.dns_map = defaultdict(list)
        self.ip_to_domain = {}
        self.event_counter = 1

    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False

    def _get_flow_key(self, pkt):
        if pkt.haslayer(IP):
            ip = pkt[IP]
            proto = ip.proto
            if pkt.haslayer(TCP):
                return (ip.src, pkt[TCP].sport, ip.dst, pkt[TCP].dport, proto)
            elif pkt.haslayer(UDP):
                return (ip.src, pkt[UDP].sport, ip.dst, pkt[UDP].dport, proto)
        return None

    def _add_event(self, event_type, timestamp, src, dst, details, description):
        event = {
            'id': self.event_counter,
            'timestamp': float(timestamp),
            'type': event_type,
            'source_ip': src,
            'dest_ip': dst,
            'details': details,
            'description': description
        }
        self.events.append(event)
        self.event_counter += 1
        return event['id']

    def _add_link(self, source_id, target_id, label):
        self.links.append({'source': source_id, 'target': target_id, 'label': label})

    def parse(self):
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
                key = self._get_flow_key(pkt)
                if key and key not in self.flows:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    event_id = self._add_event(
                        'TCP Connection',
                        pkt.time,
                        src_ip,
                        dst_ip,
                        {'sport': sport, 'dport': dport, 'flags': 'SYN', 'bytes': len(pkt)},
                        f"TCP connection from {src_ip}:{sport} to {dst_ip}:{dport}"
                    )
                    self.flows[key] = event_id

        for pkt in self.packets:
            ts = float(pkt.time)
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst

            if pkt.haslayer(DNSQR) and not pkt.haslayer(DNSRR):
                if pkt.haslayer(DNS):
                    qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    dns_id = self._add_event(
                        'DNS Query',
                        ts,
                        src,
                        dst,
                        {'query': qname, 'id': pkt[DNS].id},
                        f"DNS query for '{qname}' from {src}"
                    )
                    self.dns_map[qname].append((dns_id, None))

            if pkt.haslayer(DNSRR):
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        if rr.type == 1:
                            domain = rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                            ip_addr = rr.rdata
                            if isinstance(ip_addr, bytes):
                                ip_addr = ipaddress.ip_address(ip_addr).compressed
                            else:
                                ip_addr = str(ip_addr)
                            resp_id = self._add_event(
                                'DNS Response',
                                ts,
                                src,
                                dst,
                                {'domain': domain, 'ip': ip_addr},
                                f"DNS response: {domain} -> {ip_addr}"
                            )
                            if domain in self.dns_map:
                                for qid, _ in reversed(self.dns_map[domain]):
                                    self._add_link(qid, resp_id, 'answers')
                                    break
                            self.ip_to_domain[ip_addr] = domain
                            self.dns_map[domain].append((resp_id, ip_addr))

            if HAS_HTTP and pkt.haslayer(HTTPRequest):
                http = pkt[HTTPRequest]
                method = http.Method.decode('utf-8', errors='ignore') if http.Method else ''
                uri = http.Path.decode('utf-8', errors='ignore') if http.Path else ''
                host = None
                user_agent = None
                for f in http.fields:
                    if f.startswith('Host'):
                        val = http.getfieldval(f)
                        if val:
                            host = val.decode('utf-8', errors='ignore')
                    elif f.startswith('User_Agent'):
                        val = http.getfieldval(f)
                        if val:
                            user_agent = val.decode('utf-8', errors='ignore')
                if host and ':' in host:
                    host = host.split(':')[0]

                event_id = self._add_event(
                    'HTTP Request',
                    ts,
                    src,
                    dst,
                    {'method': method, 'uri': uri, 'host': host, 'user_agent': user_agent},
                    f"HTTP {method} {uri} (Host: {host}) from {src}"
                )
                key = self._get_flow_key(pkt)
                if key in self.flows:
                    self._add_link(self.flows[key], event_id, 'carries')
                if host and host in self.dns_map:
                    for dns_id, ip_addr in self.dns_map[host]:
                        if ip_addr == dst:
                            self._add_link(dns_id, event_id, 'resolves to')
                            break
                if dst in self.ip_to_domain:
                    domain = self.ip_to_domain[dst]
                    for dns_id, ip_addr in self.dns_map.get(domain, []):
                        if ip_addr == dst:
                            self._add_link(dns_id, event_id, 'resolves to')
                            break

            if HAS_HTTP and pkt.haslayer(HTTPResponse):
                http = pkt[HTTPResponse]
                status = http.Status_Code if http.Status_Code else ''
                reason = http.Reason_Phrase.decode('utf-8', errors='ignore') if http.Reason_Phrase else ''
                event_id = self._add_event(
                    'HTTP Response',
                    ts,
                    src,
                    dst,
                    {'status': status, 'reason': reason},
                    f"HTTP {status} {reason} from {src}"
                )
                key = self._get_flow_key(pkt)
                if key in self.flows:
                    self._add_link(self.flows[key], event_id, 'carries')

            if HAS_TLS and pkt.haslayer(TLS) and pkt.haslayer(TLSClientHello):
                tls = pkt[TLSClientHello]
                if tls.ext:
                    for ext in tls.ext:
                        if ext.type == 0:
                            sni = ext.server_names[0].decode('utf-8', errors='ignore')
                            event_id = self._add_event(
                                'TLS SNI',
                                ts,
                                src,
                                dst,
                                {'sni': sni},
                                f"TLS Client Hello with SNI: {sni} from {src}"
                            )
                            key = self._get_flow_key(pkt)
                            if key in self.flows:
                                self._add_link(self.flows[key], event_id, 'carries')
                            if sni in self.dns_map:
                                for dns_id, ip_addr in self.dns_map[sni]:
                                    if ip_addr == dst:
                                        self._add_link(dns_id, event_id, 'resolves to')
                                        break
                            if dst in self.ip_to_domain:
                                domain = self.ip_to_domain[dst]
                                for dns_id, ip_addr in self.dns_map.get(domain, []):
                                    if ip_addr == dst:
                                        self._add_link(dns_id, event_id, 'resolves to')
                                        break

            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                event_id = self._add_event(
                    'ICMP',
                    ts,
                    src,
                    dst,
                    {'type': icmp.type, 'code': icmp.code},
                    f"ICMP type={icmp.type} code={icmp.code} from {src} to {dst}"
                )

            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                op = 'request' if arp.op == 1 else 'reply' if arp.op == 2 else str(arp.op)
                event_id = self._add_event(
                    'ARP',
                    ts,
                    arp.psrc,
                    arp.pdst,
                    {'operation': op, 'hw_src': arp.hwsrc, 'hw_dst': arp.hwdst},
                    f"ARP {op}: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}"
                )

        return self.events, self.links

    def get_output(self):
        return {'events': self.events, 'links': self.links}


def main(pcap_file):
    parser = PCAPParser(pcap_file)
    events, links = parser.parse()
    output = {'events': events, 'links': links}

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, 'events.json')

    try:
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=4, cls=EnhancedJSONEncoder)
        print(f"[*] Successfully wrote {len(events)} events and {len(links)} links to {output_path}")
    except Exception as e:
        print(f"[!] Error writing JSON file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python pcap_parser.py <pcap_file>", file=sys.stderr)
        sys.exit(1)
    try:
        main(sys.argv[1])
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)
