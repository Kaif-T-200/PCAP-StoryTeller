"""File upload and PCAP parsing handlers."""
import os
import json
import uuid
import sys
import subprocess
from flask import jsonify
from werkzeug.utils import secure_filename
from config import UPLOAD_FOLDER, SCAPY_OK
from repositories.data_repository import DataRepository
from services.validation_service import ValidationService
from logger import logger


def _detect_file_type(filename):
    """PCAP files are the only supported format."""
    logger.info(f"Detecting file type: {filename}")
    return 'pcap'


def handle_file_upload(file, allowed_extensions):
    """
    Handle file upload with support for PCAP format.
    
    Args:
        file: File object from request.files
        allowed_extensions: Set of allowed file extensions
    
    Returns:
        Tuple of (response dict/jsonify, status_code)
    """
    if not SCAPY_OK:
        logger.error("Scapy is not installed on the server")
        return jsonify({'error': 'Scapy is not installed on the server', 'details': 'Run: pip install scapy'}), 500

    if file.filename == '':
        logger.warning("Upload attempt with empty filename")
        return jsonify({'error': 'No selected file'}), 400
    
    logger.info(f"Upload attempt: filename='{file.filename}', allowed_extensions={allowed_extensions}")
    
    if not ValidationService.is_allowed_file(file.filename, allowed_extensions):
        logger.warning(f"File rejected: {file.filename}")
        return jsonify({'error': 'Invalid file type. Supported: PCAP (.pcap, .pcapng, .cap)'}), 400

    logger.info(f"File validated: {file.filename}")
    filename = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_name)
    file.save(filepath)
    logger.info(f"Saved uploaded file to {filepath}")

    try:
        # Parse PCAP file directly (only PCAP format is supported now)
        parser_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pcap_parser.py')
        
        logger.info(f"Running PCAP parser: {sys.executable} {parser_script}")
        
        # Use sys.executable to ensure we use the same Python environment
        # Timeout: 5 minutes (300 seconds) for large file parsing
        try:
            result = subprocess.run(
                [sys.executable, parser_script, filepath],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                timeout=300  # 5 minutes timeout for large files
            )
        except subprocess.TimeoutExpired:
            logger.error(f"Parser timeout for file: {filepath}")
            return jsonify({'error': 'Parser timeout', 'details': 'File is too large or parsing is taking too long. Try with a smaller file.'}), 500
        
        logger.info(f"Parser return code: {result.returncode}")
        if result.stdout:
            logger.info(f"Parser output: {result.stdout[:200]}")
        if result.stderr:
            logger.warning(f"Parser errors: {result.stderr[:200]}")

        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Parser failed: {error_msg}")
            return jsonify({'error': 'Parser failed', 'details': error_msg}), 500

        events_path = os.path.join(os.path.dirname(__file__), 'events.json')
        try:
            with open(events_path, 'r') as f:
                data = json.load(f)
            logger.info(f"Successfully parsed PCAP file, generated {len(data.get('events', []))} events")
            # Save to repository
            DataRepository.save_report_data(data)
            return data, 200
        except FileNotFoundError:
            logger.error(f"Parser did not generate events.json")
            return jsonify({'error': 'Parser failed', 'details': 'No output generated - check server logs'}), 500
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in events.json")
            return jsonify({'error': 'Parser failed', 'details': 'Invalid JSON output - file may be corrupted'}), 500

    except Exception as e:
        logger.error(f"Exception in upload: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"[*] Deleted uploaded file {filepath}")
