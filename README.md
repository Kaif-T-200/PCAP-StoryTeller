<h1 align="center"> 🛡️ PCAP Storyteller </h1>

**The Cyber Attack Storyteller**

Transform PCAP network traffic into an interactive, visual storyboard of cyber attacks. Analyze network events, visualize attack patterns, detect threats, and generate professional reports—all with a modular, production-ready architecture.

---

## 🚀 Features

### Core Analysis
- 📊 **Advanced PCAP Parser** - Extracts TCP, UDP, DNS, HTTP, TLS, ICMP, ARP events with full protocol support
- 🔗 **Intelligent Causal Linking** - Automatically correlates DNS queries with HTTP requests and TLS handshakes
- 📈 **Interactive Attack Graph** - Dynamic visualization of network events and their relationships
- ⏱️ **Chronological Event Timeline** - Time-series view of all network events with filtering capabilities

### Advanced Intelligence
- ⚠️ **Threat Detection Engine** - Identifies port scanning, data exfiltration, suspicious DNS patterns, and C2 activity
- 🎯 **Risk Scoring System** - Assigns threat scores (0-100) to each event based on multi-factor analysis
- 🌍 **Geolocation Intelligence** - Maps IP addresses to geographic locations with interactive Leaflet maps
- 📊 **Analytics Dashboard** - Statistical insights: top IPs, ports, protocols, traffic heatmaps, and traffic distribution

### Reporting & Export
- 📄 **PDF Reports** - Professional multi-page reports with summaries, statistics, and detailed tables
- 📝 **Word Documents** - DOCX format for easy editing and stakeholder sharing
- 📅 **Timestamp Breakdown** - Clean event details with source/destination analysis
- 💾 **JSON Export** - Raw event data for further analysis and integration

---

## � Screenshots

<p align="center">
  <img src="Media/1.jpg" width="45%" />
  <img src="Media/2.jpg" width="45%" />
</p>
<p align="center">
  <img src="Media/3.jpg" width="45%" />
  <img src="Media/4.jpg" width="45%" />
</p>

---

## �📋 Requirements

- **Python 3.7+**
- **Flask** - Web framework
- **Scapy** - Packet parsing and analysis
- **ReportLab** - PDF generation
- **python-docx** - Word document generation
- **requests** - HTTP library for GeoIP lookups
- **folium** - Interactive map generation
- **chart-studio** - Advanced charting capabilities
- **geoip2** - GeoIP database support

All dependencies are listed in `requirements.txt`

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```
The application will start on **http://localhost:5000**

### 3. Upload & Analyze
- Open your browser to http://localhost:5000
- Click **"Analyze PCAP"** and select your PCAP/PCAPng file
- Wait for analysis to complete
- Explore results using the navigation dashboard

---

## 🎯 Usage Guide

### Dashboard Navigation
After analyzing a PCAP, use these tabs for different analytical views:

| Button | Purpose | Details |
|--------|---------|---------|
| 📊 **Report** | Download professional reports | PDF or Word formats with summaries |
| 📈 **Analytics** | View aggregated statistics | Event distribution, top IPs, ports, protocols |
| ⚠️ **Threats** | Threat intelligence view | Detected attack patterns, risk scores, severity levels |
| 🔍 **Search** | Advanced filtering | IP, domain, event type, port searches |
| 🌍 **Geolocation** | Interactive IP mapping | Global view of traffic origins and destinations |
| ⏱️ **Timeline** | Dedicated timeline view | Chronological event progression (opens in new tab) |

### Keyboard Shortcuts
- `Ctrl+F` or `Ctrl+K` - Open search in new tab
- `Ctrl+S` - Download current report

---

## 📁 Project Architecture

The project follows a **modular, layered architecture** for maintainability and scalability:

```
PCAP-StoryTeller/
│
├── frontend/
│   ├── templates/                # HTML templates for all views
│   │   ├── index.html           # Main dashboard
│   │   ├── analytics.html       # Analytics & statistics view
│   │   ├── threats.html         # Threat intelligence page
│   │   ├── search.html          # Search & filter interface
│   │   ├── geolocation.html     # Interactive map visualization
│   │   ├── timeline.html        # Dedicated timeline view
│   │   └── report.html          # Report download page
│   │
│   └── static/                   # Frontend assets
│       ├── script.js            # Main dashboard logic
│       ├── timeline.js          # Timeline page logic
│       ├── shared.js            # Shared utilities & helpers
│       └── style.css            # Dark theme styling
│
└── backend/                      # Flask API & Core Analysis Engine
    │
    ├── app.py                   # Flask application entry point
    ├── config.py                # Configuration settings
    ├── routes.py                # Route definitions & handlers
    ├── logger.py                # Logging configuration
    │
    ├── parsers/                 # Protocol-specific packet parsers
    │   ├── network_parser.py    # TCP/UDP connection parsing
    │   ├── dns_parser.py        # DNS query/response parsing
    │   ├── http_parser.py       # HTTP request/response parsing
    │   ├── tls_parser.py        # TLS/SSL handshake parsing
    │   └── encoder.py           # Custom JSON encoding
    │
    ├── services/                # Business logic & analysis services
    │   ├── threat_service.py    # Threat detection & scoring
    │   ├── analytics_service.py # Statistical analysis & aggregation
    │   ├── search_service.py    # Search & filtering capabilities
    │   ├── geolocation_service.py # GeoIP lookups & mapping
    │   ├── folium_map_service.py # Interactive map generation
    │   └── validation_service.py # Input validation & sanitization
    │
    ├── repositories/            # Data access layer
    │   ├── data_repository.py   # Event data persistence
    │   └── models/              # Data models & schemas
    │
    ├── api_handlers.py          # API endpoint handler functions
    ├── file_handler.py          # PCAP file upload & validation
    ├── pcap_parser.py           # Main PCAP parsing orchestrator
    ├── threat_analyzer.py       # Threat analysis engine
    ├── report_generator.py      # PDF/DOCX report generation
    ├── utils.py                 # Utility functions
    ├── requirements.txt         # Python dependencies
    │
    ├── uploads/                 # Temporary PCAP upload directory
    ├── models/                  # Data models
    └── __pycache__/             # Python cache directory

```

### Architecture Highlights

**Modular Design**: Each parser and service handles a specific responsibility
- **Parsers**: Extract protocol-specific information from packets
- **Services**: Apply business logic (threat detection, analytics, search)
- **Repositories**: Manage data access and persistence
- **API Handlers**: Bridge between routes and services

**Separation of Concerns**: Frontend and backend are cleanly separated
- **Frontend**: Vanilla JavaScript with interactive visualizations
- **Backend**: Flask API with Python-based analysis engines

---

## 🔧 API Endpoints

### Template Routes (HTML Views)
```
GET  /                    # Main dashboard
GET  /timeline            # Dedicated timeline view
GET  /report              # Report generation page
GET  /analytics           # Analytics dashboard
GET  /threats             # Threat intelligence page
GET  /search              # Advanced search interface
GET  /geolocation         # Geolocation mapping page
```

### PCAP Upload & Processing
```
POST /upload              # Upload and analyze PCAP file
GET  /events.json         # Retrieve parsed events as JSON
```

### Analytics & Intelligence APIs
```
GET  /api/analytics       # Statistical data (events, distribution, top IPs)
GET  /api/threats         # Threat scores and detected patterns
GET  /api/search          # Search events (query: q, field: ['all'|'ip'|'domain'|'type'])
GET  /api/geoips          # GeoIP data for all identified IPs
GET  /api/geoip/<ip>      # GeoIP data for specific IP
GET  /api/geomap          # Summarized geolocation data
```

### Report Generation
```
GET  /report/pdf          # Download PDF report
GET  /report/docx         # Download Word document report
```

---

## 📊 Supported Protocols & Event Types

### Packet Protocol Support
| Protocol | Support | Details |
|----------|---------|---------|
| **TCP** | ✅ Full | Connection establishment, flags, ports |
| **UDP** | ✅ Full | Port information, datagram analysis |
| **DNS** | ✅ Full | Queries, responses, domain resolution |
| **HTTP** | ✅ Full | Methods, URIs, headers, user agents |
| **HTTPS/TLS** | ✅ Full | SNI, certificate chains, handshakes |
| **ICMP** | ✅ Full | Ping, unreachables, type/code analysis |
| **ARP** | ✅ Full | Requests, replies, MAC/IP mappings |

### File Format Support
| Format | Status | Notes |
|--------|--------|-------|
| **.pcap** | ✅ Supported | Standard packet capture format |
| **.pcapng** | ✅ Supported | PCAP Next Generation format |
| **.cap** | ✅ Supported | Alternative capture format |

All formats are automatically detected and parsed.

---

## 🎨 Threat Detection & Risk Scoring

### Detected Threat Patterns

| Pattern | Severity | Indicators |
|---------|----------|------------|
| 🔴 **Port Scanning** | CRITICAL | Multiple unique ports from single source |
| 🔴 **Data Exfiltration** | CRITICAL | Unusual HTTP traffic volumes, large payloads |
| 🟡 **Suspicious DNS** | HIGH | Domains containing "malware", "c2", "exploit" |
| 🟡 **C2 Communication** | HIGH | Suspicious TLS SNI or dynamic domains |
| 🟡 **External Connection** | MEDIUM | Non-private IPs initiating connections |
| 🟢 **Suspicious User-Agent** | LOW | Missing or obfuscated user agents |

### Risk Scoring Algorithm

Events are scored 0-100 based on multiple factors:

**Scoring Factors**:
- **Port Suspiciousness**: Raw ports (0-10 points), privileged ports (15 points), scan ports (10 points)
- **Protocol Analysis**: POST/PUT methods (15 points), missing user-agent (10 points)
- **Domain Keywords**: Malware indicators (40 points), length anomalies (15 points)
- **IP Reputation**: External IPs (10 points), geolocation analysis
- **Payload Indicators**: Suspicious patterns, encoding signatures

**Risk Levels**:
- 🔴 **CRITICAL**: Score ≥ 70
- 🟠 **HIGH**: Score ≥ 50
- 🟡 **MEDIUM**: Score ≥ 30
- 🟢 **LOW**: Score < 30

---

## 💡 Analysis Examples

### Example 1: Analyze a Malware Attack
```bash
# 1. Start the server
python backend/app.py

# 2. Upload a suspicious PCAP file via the web interface
# 3. System automatically:
#    ✓ Parses all packets into events
#    ✓ Links related events (DNS → HTTP → TLS)
#    ✓ Calculates risk scores for each event
#    ✓ Identifies attack patterns
#    ✓ Geolocates involved IPs

# 4. View Results:
# - Attack Graph: Visual relationship between network events
# - Timeline: Chronological progression of the attack
# - Threats: Risk scores and patterns identified
# - Analytics: Event distribution, top IPs, suspicious protocols
# - Reports: Download professional PDF/Word reports
```

### Example 2: Hunt Suspicious IPs
```
# In the Search tab:
1. Enter IP address in search field
2. Filter by "Source IP" or "Destination IP"
3. View all related events and their risk scores
4. Check geolocation to identify origin
5. Review timeline to understand activity pattern
```

---

## 🔒 Security & Privacy

- 🔐 **Local Processing**: All analysis runs locally—no data sent externally (except GeoIP lookups)
- ✋ **Automatic Cleanup**: PCAP files are automatically deleted after processing
- 📋 **Payload Filtering**: Generated reports contain no raw payloads by default
- 🌐 **GeoIP API**: Uses free public API (ipapi.co) for location lookups
- 🔒 **No Logging**: Sensitive network data is not logged to disk

---

## ⚙️ Performance Characteristics

| PCAP Size | Event Count | Processing Time |
|-----------|-------------|-----------------|
| Small | < 100 | Instant |
| Medium | 100-1000 | 1-5 seconds |
| Large | 1000-5000 | 5-30 seconds |
| Very Large | > 5000 | 30+ seconds |

**Optimization Tips**:
- Filter PCAP by time range before analysis
- Extract specific protocols using tcpdump before processing
- Enable multithreading for concurrent request handling (default enabled)
- Use smaller PCAPs for faster feedback during investigation

---

## 🛠️ Troubleshooting

### Issue: "Scapy not installed"
```bash
Solution: pip install scapy
```

### Issue: "Module not found" or "Import error"
```bash
Solution: 
1. Ensure you're using the correct Python environment
2. Run: pip install -r requirements.txt
3. In VS Code, configure Python interpreter to use your venv
```

### Issue: GeoIP lookups not working
```bash
Solution:
- Ensure you have an active internet connection
- Check firewall/proxy settings
- Verify ipapi.co is accessible from your network
```

### Issue: PCAP file upload fails
```bash
Solution:
- Confirm file is valid PCAP/PCAPng format
- Check file size (default max: 1GB)
- Verify file permissions
- Try with a smaller test PCAP first
```

### Issue: Large PCAP causes 500 error or timeout
```bash
Solution:
1. Process in smaller time windows
2. Filter protocols before analysis: tcpdump -r big.pcap -w filtered.pcap "tcp.port == 80"
3. Split PCAP with editcap: editcap -c 10000 big.pcap chunk.pcap
4. Enable verbose logging: Check the logs/ directory
```

### Issue: Web interface not loading
```bash
Solution:
- Clear browser cache (Ctrl+Shift+Delete)
- Check if Flask server is running on port 5000
- Try accessing http://127.0.0.1:5000 instead of localhost
- Check browser console for JavaScript errors
```

---

## 📈 Roadmap

### Planned Features
- ✨ **Live Packet Capture** - Real-time network monitoring mode
- 🦠 **YARA Rule Integration** - Malware detection using signature rules
- 🤖 **Machine Learning** - Anomaly detection and threat prediction
- 📊 **Multi-File Comparison** - Compare PCAPs for attack pattern clustering
- 📈 **Baseline Detection** - Network baseline anomaly detection
- 🔄 **MISP/STIX Export** - Threat intelligence framework integration
- 💾 **Database Backend** - SQLite/PostgreSQL storage for large datasets
- 👥 **Collaborative Analysis** - Multi-user analysis sessions
- 📱 **Mobile Interface** - Responsive design for tablets/mobile devices
- 🔌 **Plugin System** - User-defined custom parsers and services

---

## 📚 Technology Stack

### Frontend
- **HTML5** - Semantic markup
- **CSS3** - Dark theme with responsive design
- **Vanilla JavaScript** - No frameworks required
- **vis.js** - Network graph visualization
- **Chart.js** - Statistical charts and graphs
- **Leaflet** - Interactive mapping

### Backend
- **Flask** - Lightweight Python web framework
- **Scapy** - Packet manipulation and analysis
- **ReportLab** - PDF generation
- **python-docx** - Word document creation
- **Folium** - Interactive map generation
- **geoip2** - Geolocation lookups

### Architecture
- **Modular Parsers** - Protocol-specific packet parsing
- **Service Layer** - Business logic separation
- **Repository Pattern** - Data access abstraction
- **REST API** - JSON-based communication

---

## 🙏 Acknowledgments

Built with 🔧 using these amazing open-source projects:

- [**vis.js**](http://visjs.org/) - Network visualization
- [**Scapy**](https://scapy.readthedocs.io/) - Packet manipulation
- [**Leaflet**](https://leafletjs.com/) - Interactive map visualization
- [**Chart.js**](https://www.chartjs.org/) - Data visualization
- [**Flask**](https://flask.palletsprojects.com/) - Web framework
- [**ReportLab**](https://www.reportlab.com/) - PDF generation
- [**Folium**](https://python-visualization.github.io/folium/) - Map generation

---

## 👤 Connect with Author

<h1 align="center"> Kaif Tarasgar </h1>

<p align="center">
<a href="https://www.linkedin.com/in/kaif-tarasgar-0b5425326/"><img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white"></a>
&nbsp;<b></b>&nbsp;
<a href="https://github.com/Kaif-T-200"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white"></a>
&nbsp;<b></b>&nbsp;
<a href="https://x.com/Kaif_T_200"><img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white"></a>
&nbsp;<b></b>&nbsp;
<a href="https://kaif-t-200.github.io/Portfolio/"><img src="https://img.shields.io/badge/Portfolio-FF5722?style=for-the-badge&logo=todoist&logoColor=white"></a>
&nbsp;<b></b>&nbsp;
<a href="https://pcap-storyteller.onrender.com/"><img src="https://img.shields.io/badge/Live_Demo-Visit_Now-000000?style=for-the-badge&logo=render&logoColor=white"></a>
</p>

---

**Made with ❤️ by Kaif Tarasgar**
