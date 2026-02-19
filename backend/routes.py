"""Flask routes for template rendering and API endpoints."""
from flask import render_template, request, jsonify, send_from_directory
import os
from api_handlers import (
    handle_analytics, handle_threats, handle_search,
    handle_geoip, handle_geoips, handle_geomap
)
from file_handler import handle_file_upload
from report_generator import generate_pdf_report, generate_docx_report
from config import ALLOWED_EXTENSIONS, UPLOAD_FOLDER
from logger import logger


def register_routes(app):
    """Register all routes for the Flask application."""
    logger.info("Registering routes...")
    
    # Template Routes
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/timeline')
    def timeline():
        return render_template('timeline.html')

    @app.route('/report')
    def report():
        return render_template('report.html')

    @app.route('/analytics')
    def analytics():
        return render_template('analytics.html')

    @app.route('/threats')
    def threats():
        return render_template('threats.html')

    @app.route('/search')
    def search_page():
        return render_template('search.html')

    @app.route('/geolocation')
    def geolocation():
        return render_template('geolocation.html')

    # API Routes
    @app.route('/api/analytics')
    def api_analytics():
        return handle_analytics()

    @app.route('/api/threats')
    def api_threats():
        return handle_threats()

    @app.route('/api/search')
    def api_search():
        query = request.args.get('q', '')
        field = request.args.get('field', 'all')
        return handle_search(query, field)

    @app.route('/api/geoip/<ip>')
    def api_geoip(ip):
        return handle_geoip(ip)

    @app.route('/api/geoips')
    def api_geoips():
        return handle_geoips()

    @app.route('/api/geomap')
    def api_geomap():
        return handle_geomap()

    # Report Generation Routes
    @app.route('/report/pdf')
    def report_pdf():
        return generate_pdf_report()

    @app.route('/report/docx')
    def report_docx():
        return generate_docx_report()

    # File Upload Route
    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'file' not in request.files:
            logger.warning("Upload attempt without file")
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        logger.info(f"File upload received: {file.filename}")
        result, status_code = handle_file_upload(file, ALLOWED_EXTENSIONS)
        
        if isinstance(result, dict) and status_code == 200:
            logger.info(f"File upload successful: {file.filename}")
            return jsonify(result), status_code
        logger.error(f"File upload failed: {file.filename}")
        return result, status_code

    # Events Data Route
    @app.route('/events.json')
    def get_events():
        logger.info("GET /events.json - Fetching events data")
        return send_from_directory(os.path.dirname(__file__), 'events.json')
    
    logger.info(f"✓ Registered {len(app.url_map._rules)} routes")
