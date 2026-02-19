"""Folium map generation service for geolocation visualization."""
import folium
from folium import plugins
from logger import logger


class FoliumMapService:
    """Service for generating interactive maps using Folium."""
    
    def __init__(self):
        self.default_zoom = 2
        self.default_center = [20, 0]
    
    def create_geolocation_map(self, locations):
        """Create interactive map with IP locations."""
        logger.info(f"Creating Folium map with {len(locations)} locations")
        
        # Filter valid external IPs with coordinates
        valid_locations = [
            loc for loc in locations
            if loc.get('type') == 'external' 
            and loc.get('latitude') 
            and loc.get('longitude')
        ]
        
        logger.info(f"Rendering {len(valid_locations)} valid locations on map")
        
        # Create base map
        map_obj = folium.Map(
            location=self.default_center,
            zoom_start=self.default_zoom,
            tiles='OpenStreetMap',
            control_scale=True
        )
        
        # Add marker cluster for better performance
        marker_cluster = plugins.MarkerCluster().add_to(map_obj)
        
        # Add markers for each location
        for loc in valid_locations:
            self._add_marker(marker_cluster, loc)
        
        # Auto-fit bounds if we have locations
        if valid_locations:
            coords = [[loc['latitude'], loc['longitude']] for loc in valid_locations]
            map_obj.fit_bounds(coords)
        
        logger.info("Folium map created successfully")
        return map_obj
    
    def _add_marker(self, cluster, loc):
        """Add marker to map for a location."""
        lat = float(loc['latitude'])
        lon = float(loc['longitude'])
        
        # Determine marker color based on threat level
        color = 'red'
        if loc.get('is_proxy'):
            color = 'darkred'
        elif loc.get('is_hosting'):
            color = 'orange'
        
        # Create popup content
        popup_html = self._create_popup_html(loc)
        
        # Add marker
        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(popup_html, max_width=300),
            tooltip=f"{loc['ip']} - {loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}",
            icon=folium.Icon(color=color, icon='info-sign')
        ).add_to(cluster)
    
    def _create_popup_html(self, loc):
        """Create HTML content for marker popup."""
        html = f"""
        <div style="font-family: Arial, sans-serif; font-size: 12px;">
            <h4 style="margin: 5px 0; color: #e74c3c;">{loc['ip']}</h4>
            <p style="margin: 3px 0;"><strong>{loc.get('city', 'N/A')}, {loc.get('country', 'Unknown')}</strong></p>
            <hr style="margin: 5px 0;">
            <p style="margin: 2px 0;"><b>ISP:</b> {loc.get('isp', 'Unknown')}</p>
            <p style="margin: 2px 0;"><b>ASN:</b> {loc.get('asn', 'N/A')}</p>
            <p style="margin: 2px 0;"><b>Timezone:</b> {loc.get('timezone', 'N/A')}</p>
            <p style="margin: 2px 0;"><b>Coordinates:</b> {loc.get('latitude'):.4f}, {loc.get('longitude'):.4f}</p>
        """
        
        if loc.get('reverse_dns'):
            html += f'<p style="margin: 2px 0;"><b>Hostname:</b> {loc["reverse_dns"]}</p>'
        
        if loc.get('is_proxy'):
            html += '<p style="margin: 5px 0; color: #ff0000;"><b>⚠️ PROXY/VPN DETECTED</b></p>'
        
        html += '</div>'
        return html
    
    def generate_map_html(self, locations):
        """Generate complete HTML for the map."""
        map_obj = self.create_geolocation_map(locations)
        return map_obj._repr_html_()
