"""DNS packet parser for extracting DNS events."""
import ipaddress


def parse_dns_query(pkt, parser, ts, src, dst):
    """Parse DNS query packet and add event."""
    if not pkt.haslayer('DNS'):
        return
    
    qname = pkt['DNSQR'].qname.decode('utf-8', errors='ignore').rstrip('.')
    dns_id = parser._add_event(
        'DNS Query',
        ts,
        src,
        dst,
        {'query': qname, 'id': pkt['DNS'].id},
        f"DNS query for '{qname}' from {src}"
    )
    parser.dns_map[qname].append((dns_id, None))


def parse_dns_response(pkt, parser, ts, src, dst):
    """Parse DNS response packet and add event."""
    if not pkt.haslayer('DNS'):
        return
    
    dns = pkt['DNS']
    for i in range(dns.ancount):
        rr = dns.an[i]
        if rr.type == 1:  # A record
            domain = rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
            ip_addr = rr.rdata
            
            if isinstance(ip_addr, bytes):
                ip_addr = ipaddress.ip_address(ip_addr).compressed
            else:
                ip_addr = str(ip_addr)
            
            resp_id = parser._add_event(
                'DNS Response',
                ts,
                src,
                dst,
                {'domain': domain, 'ip': ip_addr},
                f"DNS response: {domain} -> {ip_addr}"
            )
            
            # Link to query
            if domain in parser.dns_map:
                for qid, _ in reversed(parser.dns_map[domain]):
                    parser._add_link(qid, resp_id, 'answers')
                    break
            
            parser.ip_to_domain[ip_addr] = domain
            parser.dns_map[domain].append((resp_id, ip_addr))
