"""Network packet parser for basic protocols (TCP, ICMP, ARP)."""


def parse_tcp_connection(pkt, parser):
    """Parse TCP SYN packets and create connection events."""
    if not pkt.haslayer('TCP') or not (pkt['TCP'].flags & 0x02):
        return
    
    key = parser._get_flow_key(pkt)
    if key and key not in parser.flows:
        src_ip = pkt['IP'].src
        dst_ip = pkt['IP'].dst
        sport = pkt['TCP'].sport
        dport = pkt['TCP'].dport
        
        event_id = parser._add_event(
            'TCP Connection',
            pkt.time,
            src_ip,
            dst_ip,
            {'sport': sport, 'dport': dport, 'flags': 'SYN', 'bytes': len(pkt)},
            f"TCP connection from {src_ip}:{sport} to {dst_ip}:{dport}"
        )
        parser.flows[key] = event_id


def parse_icmp(pkt, parser, ts, src, dst):
    """Parse ICMP packet and add event."""
    icmp = pkt['ICMP']
    parser._add_event(
        'ICMP',
        ts,
        src,
        dst,
        {'type': icmp.type, 'code': icmp.code},
        f"ICMP type={icmp.type} code={icmp.code} from {src} to {dst}"
    )


def parse_arp(pkt, parser, ts):
    """Parse ARP packet and add event."""
    arp = pkt['ARP']
    op = 'request' if arp.op == 1 else 'reply' if arp.op == 2 else str(arp.op)
    
    parser._add_event(
        'ARP',
        ts,
        arp.psrc,
        arp.pdst,
        {'operation': op, 'hw_src': arp.hwsrc, 'hw_dst': arp.hwdst},
        f"ARP {op}: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}"
    )
