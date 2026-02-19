"""Utility functions for data processing and formatting."""
import json
import os
from datetime import datetime


def load_report_data():
    """Load report data from events.json file."""
    events_path = os.path.join(os.path.dirname(__file__), 'events.json')
    if not os.path.exists(events_path):
        return None
    try:
        with open(events_path, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def format_timestamp(ts):
    """Convert timestamp to readable format."""
    try:
        return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


def summarize_event(event):
    """Generate a summary string for an event based on its type."""
    event_type = event.get('type', '')
    details = event.get('details') or {}
    
    if event_type == 'HTTP Request':
        method = details.get('method') or ''
        uri = details.get('uri') or ''
        host = details.get('host') or ''
        return f"{method} {host}{uri}".strip()
    if event_type == 'HTTP Response':
        status = details.get('status') or ''
        reason = details.get('reason') or ''
        return f"{status} {reason}".strip()
    if event_type == 'DNS Query':
        return details.get('query') or details.get('qname') or ''
    if event_type == 'DNS Response':
        domain = details.get('domain') or details.get('name') or ''
        ip_addr = details.get('ip') or ''
        return f"{domain} -> {ip_addr}".strip()
    if event_type == 'TLS SNI':
        return details.get('sni') or ''
    if event_type == 'TCP Connection':
        sport = details.get('sport') or ''
        dport = details.get('dport') or ''
        return f"{sport} -> {dport}".strip()
    if event_type == 'ICMP':
        icmp_type = details.get('type')
        code = details.get('code')
        return f"type={icmp_type} code={code}".strip()
    if event_type == 'ARP':
        return details.get('operation') or ''
    return event.get('description') or ''


def build_report_rows(events):
    """
    Transform events into report table rows and calculate event type counts.
    
    Returns:
        tuple: (rows list, counts dict)
    """
    rows = []
    counts = {}
    for event in events:
        event_type = event.get('type', 'Unknown')
        counts[event_type] = counts.get(event_type, 0) + 1
        details = event.get('details') or {}
        rows.append({
            'time': format_timestamp(event.get('timestamp')),
            'type': event_type,
            'src': event.get('source_ip') or '',
            'dst': event.get('dest_ip') or '',
            'message': summarize_event(event),
            'details': json.dumps(details, indent=2, ensure_ascii=True)
        })
    return rows, counts


def allowed_file(filename, allowed_extensions):
    """Check if file has PCAP extension (.pcap, .pcapng, .cap)."""
    if not filename or '.' not in filename:
        return False
    
    filename_lower = filename.lower()
    
    # Check if any PCAP extension appears in the filename
    for ext in allowed_extensions:
        if f'.{ext}' in filename_lower:
            return True
    
    return False
