"""PCAP StoryTeller - Main Flask Application

This is the entry point for the PCAP StoryTeller web application.
It initializes the Flask app and registers all routes.
"""
from flask import Flask
from config import STATIC_FOLDER, TEMPLATE_FOLDER, UPLOAD_FOLDER
from routes import register_routes
from logger import logger
import tempfile


def create_app():
    """Create and configure the Flask application."""
    logger.info("=" * 60)
    logger.info("PCAP StoryTeller - Starting Application")
    logger.info("=" * 60)
    
    app = Flask(__name__, static_folder=STATIC_FOLDER, template_folder=TEMPLATE_FOLDER)
    
    # Configure for large file uploads (1GB max)
    app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 * 1024  # 1GB
    logger.info("File upload limit: 1GB")
    
    # Use custom upload folder for temp files
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    logger.info(f"Upload folder: {UPLOAD_FOLDER}")
    
    # Disable default static file caching
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    logger.info("Static file caching disabled")
    
    # Register all routes
    register_routes(app)
    logger.info("Routes registered successfully")
    
    return app


if __name__ == '__main__':
    app = create_app()
    logger.info("Flask app created, starting server...")
    logger.info("Server running on http://0.0.0.0:5000")
    # Run with increased timeout for large files
    # Use threaded mode to handle concurrent requests
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True, use_reloader=False)
