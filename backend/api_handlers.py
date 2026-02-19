"""API handlers for analytics, threats, search, and geolocation."""
from flask import jsonify
from repositories.data_repository import DataRepository
from services.analytics_service import AnalyticsService
from services.threat_service import ThreatService
from services.search_service import SearchService
from services.geolocation_service import GeolocationService
from services.folium_map_service import FoliumMapService
from logger import logger


def handle_analytics():
    """Handle analytics data aggregation and calculations."""
    logger.info("Analytics handler called")
    
    data = DataRepository.load_report_data()
    if not data:
        logger.warning("No data available for analytics")
        return jsonify({'error': 'No data'}), 400

    events = data.get('events', [])
    logger.info(f"Processing {len(events)} events for analytics")
    
    analytics = AnalyticsService.analyze_events(events)
    
    return jsonify(analytics)


def handle_threats():
    """Handle threat analysis based on events."""
    logger.info("Threats handler called")
    
    data = DataRepository.load_report_data()
    if not data:
        logger.warning("No data available for threat analysis")
        return jsonify({'error': 'No data'}), 400

    events = data.get('events', [])
    links = data.get('links', [])
    
    logger.info(f"Analyzing {len(events)} events for threats")
    threat_service = ThreatService(events, links)
    result = threat_service.analyze_threats()
    
    return jsonify(result)


def handle_search(query, field):
    """Handle search across events with optional field filtering."""
    logger.info(f"Search handler called: query='{query}', field='{field}'")
    
    data = DataRepository.load_report_data()
    if not data:
        logger.warning("No data available for search")
        return jsonify({'error': 'No data'}), 400

    events = data.get('events', [])
    search_service = SearchService(events)
    results = search_service.search(query, field)
    
    return jsonify({'results': results, 'count': len(results)})


def handle_geoip(ip):
    """Handle GeoIP lookup for a single IP."""
    logger.info(f"GeoIP lookup for: {ip}")
    
    geo_service = GeolocationService()
    geo_data = geo_service.analyze_ip(ip)
    
    logger.info(f"GeoIP lookup complete for {ip}: {geo_data.get('country', 'Unknown')}")
    return jsonify(geo_data)


def handle_geoips():
    """Handle GeoIP lookup for all IPs in the report."""
    logger.info("GeoIPs lookup for all IPs")
    
    data = DataRepository.load_report_data()
    if not data:
        logger.warning("No data available for geoips lookup")
        return jsonify({'error': 'No data'}), 400
    
    all_ips = DataRepository.get_all_ips(data)
    logger.info(f"Processing {len(all_ips)} unique IPs for geolocation")
    
    geo_service = GeolocationService()
    geoips = geo_service.analyze_all_ips(all_ips, limit=50)
    
    logger.info(f"GeoIPs lookup complete: {len(geoips)} IPs processed")
    return jsonify({'locations': geoips})


def handle_geomap():
    """Handle Folium map generation for all geolocated IPs."""
    logger.info("Folium map generation requested")
    
    data = DataRepository.load_report_data()
    if not data:
        logger.warning("No data available for map generation")
        return jsonify({'error': 'No data'}), 400
    
    all_ips = DataRepository.get_all_ips(data)
    logger.info(f"Generating map for {len(all_ips)} unique IPs")
    
    geo_service = GeolocationService()
    geoips = geo_service.analyze_all_ips(all_ips, limit=50)
    
    map_service = FoliumMapService()
    map_html = map_service.generate_map_html(geoips)
    
    logger.info("Folium map generated successfully")
    return map_html
