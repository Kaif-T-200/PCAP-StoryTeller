"""Configuration settings for the Flask application."""
import os
import sys

# File upload settings - PCAP format only
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

# Upload folder settings
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Flask folder paths
TEMPLATE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'templates')
STATIC_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static')

# Check if Scapy is available (needed for PCAP parsing)
try:
    import scapy
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("❌ Scapy not installed. Run: pip install scapy", file=sys.stderr)
