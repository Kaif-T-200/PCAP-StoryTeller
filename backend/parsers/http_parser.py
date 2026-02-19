"""HTTP packet parser for extracting HTTP events."""
import sys


def parse_http_request(pkt, parser, ts, src, dst):
    """Parse HTTP request packet and add event."""
    http = pkt['HTTPRequest']
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

    event_id = parser._add_event(
        'HTTP Request',
        ts,
        src,
        dst,
        {'method': method, 'uri': uri, 'host': host, 'user_agent': user_agent},
        f"HTTP {method} {uri} (Host: {host}) from {src}"
    )
    
    # Link to TCP flow
    key = parser._get_flow_key(pkt)
    if key in parser.flows:
        parser._add_link(parser.flows[key], event_id, 'carries')
    
    # Link to DNS
    if host and host in parser.dns_map:
        for dns_id, ip_addr in parser.dns_map[host]:
            if ip_addr == dst:
                parser._add_link(dns_id, event_id, 'resolves to')
                break
    
    if dst in parser.ip_to_domain:
        domain = parser.ip_to_domain[dst]
        for dns_id, ip_addr in parser.dns_map.get(domain, []):
            if ip_addr == dst:
                parser._add_link(dns_id, event_id, 'resolves to')
                break


def parse_http_response(pkt, parser, ts, src, dst):
    """Parse HTTP response packet and add event."""
    http = pkt['HTTPResponse']
    status = http.Status_Code if http.Status_Code else ''
    reason = http.Reason_Phrase.decode('utf-8', errors='ignore') if http.Reason_Phrase else ''
    
    event_id = parser._add_event(
        'HTTP Response',
        ts,
        src,
        dst,
        {'status': status, 'reason': reason},
        f"HTTP {status} {reason} from {src}"
    )
    
    # Link to TCP flow
    key = parser._get_flow_key(pkt)
    if key in parser.flows:
        parser._add_link(parser.flows[key], event_id, 'carries')
