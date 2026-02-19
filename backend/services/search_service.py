"""Search service for event searching and filtering."""
from logger import logger


class SearchService:
    """Service for searching and filtering events."""
    
    def __init__(self, events):
        self.events = events
        logger.info(f"SearchService initialized with {len(events)} events")
    
    def search(self, query, field='all'):
        """Search events with optional field filtering."""
        logger.info(f"Searching: query='{query}', field='{field}'")
        
        query = query.lower()
        results = []
        
        for event in self.events:
            match = False
            
            if field == 'all':
                match = self._match_all_fields(event, query)
            elif field == 'ip':
                match = self._match_ip(event, query)
            elif field == 'domain':
                match = self._match_domain(event, query)
            elif field == 'type':
                match = self._match_type(event, query)
            elif field == 'port':
                match = self._match_port(event, query)
            
            if match:
                results.append(self._format_result(event))
        
        logger.info(f"Search complete: {len(results)} results found")
        return results
    
    def filter_by_type(self, event_type):
        """Filter events by type."""
        logger.debug(f"Filtering by type: {event_type}")
        
        results = [
            self._format_result(e) for e in self.events 
            if e.get('type', '').lower() == event_type.lower()
        ]
        
        logger.info(f"Filter complete: {len(results)} events of type {event_type}")
        return results
    
    def filter_by_ip(self, ip):
        """Filter events by IP address."""
        logger.debug(f"Filtering by IP: {ip}")
        
        results = [
            self._format_result(e) for e in self.events 
            if ip in [e.get('source_ip'), e.get('dest_ip')]
        ]
        
        logger.info(f"Filter complete: {len(results)} events involving {ip}")
        return results
    
    def filter_by_port(self, port):
        """Filter events by port."""
        logger.debug(f"Filtering by port: {port}")
        
        port_str = str(port)
        results = [
            self._format_result(e) for e in self.events 
            if e.get('details', {}).get('dport') == port or str(e.get('details', {}).get('sport')) == port_str
        ]
        
        logger.info(f"Filter complete: {len(results)} events on port {port}")
        return results
    
    def _match_all_fields(self, event, query):
        """Check if query matches any field in event."""
        return query in str(event).lower()
    
    def _match_ip(self, event, query):
        """Check if query matches IP fields."""
        src = event.get('source_ip', '')
        dst = event.get('dest_ip', '')
        return query in src.lower() or query in dst.lower()
    
    def _match_domain(self, event, query):
        """Check if query matches domain fields."""
        details = event.get('details', {})
        domain_query = details.get('query', '')
        sni = details.get('sni', '')
        return query in domain_query.lower() or query in sni.lower()
    
    def _match_type(self, event, query):
        """Check if query matches event type."""
        return query in event.get('type', '').lower()
    
    def _match_port(self, event, query):
        """Check if query matches port."""
        details = event.get('details', {})
        sport = str(details.get('sport', ''))
        dport = str(details.get('dport', ''))
        return query == sport or query == dport
    
    def _format_result(self, event):
        """Format search result."""
        return {
            'id': event['id'],
            'type': event.get('type'),
            'timestamp': event.get('timestamp'),
            'source': event.get('source_ip'),
            'destination': event.get('dest_ip'),
            'description': event.get('description')
        }
