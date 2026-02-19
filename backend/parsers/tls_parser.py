"""TLS packet parser for extracting TLS/SNI events."""


def parse_tls_client_hello(pkt, parser, ts, src, dst):
    """Parse TLS ClientHello packet and extract SNI."""
    try:
        if not pkt.haslayer('TLSClientHello'):
            return
        
        tls = pkt['TLSClientHello']
        
        # Check if extensions exist
        if not hasattr(tls, 'ext') or not tls.ext:
            return
        
        for ext in tls.ext:
            if not hasattr(ext, 'type'):
                continue
            if ext.type == 0:  # SNI extension
                if not hasattr(ext, 'server_names') or not ext.server_names:
                    continue
                sni = ext.server_names[0].decode('utf-8', errors='ignore')
                
                event_id = parser._add_event(
                    'TLS SNI',
                    ts,
                    src,
                    dst,
                    {'sni': sni},
                    f"TLS Client Hello with SNI: {sni} from {src}"
                )
                
                # Link to TCP flow
                key = parser._get_flow_key(pkt)
                if key in parser.flows:
                    parser._add_link(parser.flows[key], event_id, 'carries')
                
                # Link to DNS
                if sni in parser.dns_map:
                    for dns_id, ip_addr in parser.dns_map[sni]:
                        if ip_addr == dst:
                            parser._add_link(dns_id, event_id, 'resolves to')
                            break
                
                if dst in parser.ip_to_domain:
                    domain = parser.ip_to_domain[dst]
                    for dns_id, ip_addr in parser.dns_map.get(domain, []):
                        if ip_addr == dst:
                            parser._add_link(dns_id, event_id, 'resolves to')
    
    except Exception:
        # Silently skip malformed TLS packets
        pass
