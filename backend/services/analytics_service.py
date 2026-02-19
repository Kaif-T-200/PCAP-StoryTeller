"""Analytics service for data analysis and aggregation."""
from collections import defaultdict
from logger import logger


class AnalyticsService:
    """Service for analytics data aggregation and calculations."""
    
    @staticmethod
    def analyze_events(events):
        """Analyze events and generate analytics."""
        logger.info(f"Analyzing {len(events)} events")
        
        event_counts = {}
        top_ips_src = defaultdict(int)
        top_ips_dst = defaultdict(int)
        port_dist = defaultdict(int)
        protocol_dist = defaultdict(int)
        
        for event in events:
            # Count event types
            event_type = event.get('type')
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            # Count IPs
            src = event.get('source_ip')
            dst = event.get('dest_ip')
            if src:
                top_ips_src[src] += 1
            if dst:
                top_ips_dst[dst] += 1
            
            # Count ports
            details = event.get('details', {})
            dport = details.get('dport')
            if dport:
                port_dist[str(dport)] += 1
            
            # Count protocols
            protocol = details.get('protocol', 'Unknown')
            protocol_dist[protocol] += 1
        
        logger.info(f"Analytics complete: {len(event_counts)} event types analyzed")
        
        return {
            'event_counts': event_counts,
            'top_sources': sorted(top_ips_src.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_destinations': sorted(top_ips_dst.items(), key=lambda x: x[1], reverse=True)[:10],
            'port_distribution': dict(sorted(port_dist.items(), key=lambda x: x[1], reverse=True)[:15]),
            'protocol_distribution': dict(sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True)),
            'total_events': len(events)
        }
    
    @staticmethod
    def get_timeline_events(events):
        """Get events sorted by timestamp for timeline."""
        logger.debug(f"Creating timeline for {len(events)} events")
        
        timeline = sorted(
            events,
            key=lambda x: x.get('timestamp', ''),
            reverse=False
        )
        
        return timeline
    
    @staticmethod
    def get_event_summary(events):
        """Get summary statistics of events."""
        logger.debug(f"Generating summary for {len(events)} events")
        
        return {
            'total_events': len(events),
            'unique_sources': len(set(e.get('source_ip') for e in events if e.get('source_ip'))),
            'unique_destinations': len(set(e.get('dest_ip') for e in events if e.get('dest_ip'))),
            'event_types': len(set(e.get('type') for e in events))
        }
