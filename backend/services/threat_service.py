"""Threat analysis service for security analysis."""
from threat_analyzer import ThreatAnalyzer
from logger import logger


class ThreatService:
    """Service for threat analysis and detection."""
    
    def __init__(self, events, links):
        self.events = events
        self.links = links
        self.analyzer = ThreatAnalyzer(events, links)
        logger.info(f"ThreatService initialized with {len(events)} events")
    
    def analyze_threats(self):
        """Analyze all events for threats."""
        logger.info("Starting threat analysis")
        
        self.analyzer.detect_patterns()
        
        threat_scores = {}
        for event in self.events:
            threat_scores[event['id']] = self.analyzer.get_threat_score(event['id'])
        
        summary = self.analyzer.get_threat_summary()
        
        logger.info(f"Threat analysis complete: {summary['threat_level']} threat level")
        
        return {
            'summary': summary,
            'threat_scores': threat_scores,
            'patterns': self.analyzer.attack_patterns
        }
    
    def get_high_threat_events(self, threshold=60):
        """Get events above threat threshold."""
        logger.debug(f"Filtering events above threat threshold: {threshold}")
        
        high_threat = []
        for event in self.events:
            score = self.analyzer.get_threat_score(event['id'])
            if score >= threshold:
                high_threat.append({
                    'id': event['id'],
                    'type': event.get('type'),
                    'threat_score': score,
                    'source': event.get('source_ip'),
                    'destination': event.get('dest_ip')
                })
        
        logger.info(f"Found {len(high_threat)} high-threat events")
        return high_threat
    
    def get_threat_patterns(self):
        """Get detected attack patterns."""
        logger.debug("Retrieving threat patterns")
        return self.analyzer.attack_patterns
    
    def get_threat_summary(self):
        """Get threat summary."""
        logger.debug("Retrieving threat summary")
        return self.analyzer.get_threat_summary()
