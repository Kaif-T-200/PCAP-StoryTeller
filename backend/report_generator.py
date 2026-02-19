"""Report generation module for PDF, DOCX, and text reports."""
from flask import jsonify, send_file
from repositories.data_repository import DataRepository
from services.analytics_service import AnalyticsService
from services.threat_service import ThreatService
from logger import logger
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os


def generate_pdf_report():
    """Generate PDF report from analyzed PCAP data."""
    logger.info("PDF report generation requested")
    
    data = DataRepository.load_report_data()
    if not data:
        logger.warning("No data available for PDF report")
        return jsonify({'error': 'No data available'}), 400
    
    events = data.get('events', [])
    links = data.get('links', [])
    analytics = AnalyticsService.analyze_events(events)
    threat_service = ThreatService(events, links)
    threats = threat_service.analyze_threats()
    
    # Generate PDF file
    pdf_filename = f"pcap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path = os.path.join('uploads', pdf_filename)
    
    try:
        create_pdf_report(pdf_path, events, analytics, threats)
        logger.info(f"PDF report generated successfully: {pdf_filename}")
        return send_file(pdf_path, as_attachment=True, download_name=pdf_filename)
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        return jsonify({'error': f'Failed to generate PDF: {str(e)}'}), 500


def create_pdf_report(filename, events, analytics, threats):
    """Create the actual PDF report with ReportLab."""
    doc = SimpleDocTemplate(filename, pagesize=letter,
                           topMargin=0.75*inch, bottomMargin=0.75*inch,
                           leftMargin=0.75*inch, rightMargin=0.75*inch)
    
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.HexColor('#2980b9'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#16a085'),
        spaceAfter=10,
        spaceBefore=10
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        alignment=TA_JUSTIFY
    )
    
    # Cover Page
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("🛡️ PCAP STORYTELLER", title_style))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("Network Traffic Analysis Report", styles['Heading2']))
    story.append(Spacer(1, 1*inch))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}", 
                          ParagraphStyle('center', parent=styles['Normal'], alignment=TA_CENTER)))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(f"Total Events Analyzed: {analytics['total_events']}", 
                          ParagraphStyle('center', parent=styles['Normal'], alignment=TA_CENTER, fontSize=12)))
    story.append(PageBreak())
    
    # Table of Contents (simplified)
    story.append(Paragraph("Table of Contents", heading1_style))
    toc_items = [
        "1. About PCAP StoryTeller",
        "2. Executive Summary",
        "3. Threat Analysis",
        "4. Network Statistics",
        "5. Detailed Findings"
    ]
    for item in toc_items:
        story.append(Paragraph(item, body_style))
        story.append(Spacer(1, 0.1*inch))
    story.append(PageBreak())
    
    # Section 1: About PCAP StoryTeller (Wireshark Comparison)
    story.append(Paragraph("1. About PCAP StoryTeller", heading1_style))
    story.append(Spacer(1, 0.2*inch))
    
    story.append(Paragraph("Wireshark vs PCAP StoryTeller", heading2_style))
    
    comparison_text = """
    While Wireshark is a powerful desktop application for deep packet inspection and real-time network 
    analysis focused on microscopic examination of individual packets, <b>PCAP StoryTeller</b> takes a 
    different approach by focusing on storytelling and attack investigation.
    """
    story.append(Paragraph(comparison_text, body_style))
    story.append(Spacer(1, 0.15*inch))
    
    # Comparison table
    comparison_data = [
        ['Feature', 'Wireshark', 'PCAP StoryTeller'],
        ['Purpose', 'Packet-level inspection', 'Attack narrative & investigation'],
        ['Interface', 'Desktop application', 'Web-based application'],
        ['Analysis Focus', 'Protocol dissection', 'Threat detection & storytelling'],
        ['Visualization', 'Packet trees & graphs', 'Interactive timelines & maps'],
        ['Threat Detection', 'Manual analysis', 'Automated threat scoring'],
        ['Reporting', 'Manual export', 'Auto-generated PDF/DOCX reports'],
        ['Geolocation', 'Not included', 'Interactive IP mapping'],
        ['Link Analysis', 'Not included', 'Causal event relationships'],
        ['Target Users', 'Network engineers', 'SOC analysts, IR teams'],
    ]
    
    comparison_table = Table(comparison_data, colWidths=[2*inch, 2*inch, 2.5*inch])
    comparison_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ]))
    
    story.append(comparison_table)
    story.append(Spacer(1, 0.2*inch))
    
    key_features = """
    <b>Key Features of PCAP StoryTeller:</b><br/>
    • <b>Attack Narrative:</b> Automatically builds causal chains (DNS → HTTP → TLS connections)<br/>
    • <b>Threat Intelligence:</b> Built-in detection for port scans, data exfiltration, and suspicious patterns<br/>
    • <b>Risk Scoring:</b> Assigns threat scores (0-100) to each event<br/>
    • <b>Visual Analytics:</b> Interactive graphs and timeline views of network events<br/>
    • <b>Geolocation Mapping:</b> Maps IP addresses on interactive maps<br/>
    • <b>Automated Reporting:</b> Generates professional PDF and DOCX reports
    """
    story.append(Paragraph(key_features, body_style))
    story.append(PageBreak())
    
    # Section 2: Executive Summary
    story.append(Paragraph("2. Executive Summary", heading1_style))
    story.append(Spacer(1, 0.15*inch))
    
    summary_data = [
        ['Metric', 'Value'],
        ['Total Events Analyzed', str(analytics['total_events'])],
        ['Unique Source IPs', str(len(analytics.get('top_src_ips', [])))],
        ['Unique Destination IPs', str(len(analytics.get('top_dst_ips', [])))],
        ['Event Types', ', '.join(analytics.get('event_types', {}).keys())],
        ['Threats Detected', str(len(threats))],
        ['High-Risk Events', str(sum(1 for t in threats if t.get('severity') == 'high'))],
    ]
    
    summary_table = Table(summary_data, colWidths=[3*inch, 3.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    
    story.append(summary_table)
    story.append(PageBreak())
    
    # Section 3: Threat Analysis
    story.append(Paragraph("3. Threat Analysis", heading1_style))
    story.append(Spacer(1, 0.15*inch))
    
    if threats:
        threat_data = [['Type', 'Description', 'Severity', 'Risk Score']]
        for threat in threats[:20]:  # Limit to top 20 threats
            threat_data.append([
                threat.get('type', 'Unknown')[:30],
                threat.get('description', 'N/A')[:50],
                threat.get('severity', 'low'),
                str(threat.get('risk_score', 0))
            ])
        
        threat_table = Table(threat_data, colWidths=[1.5*inch, 2.8*inch, 1*inch, 1*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(1, 0.95, 0.95)]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(threat_table)
    else:
        story.append(Paragraph("No significant threats detected.", body_style))
    
    story.append(PageBreak())
    
    # Section 4: Network Statistics
    story.append(Paragraph("4. Network Statistics", heading1_style))
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Top Source IP Addresses", heading2_style))
    top_src_data = [['Rank', 'IP Address', 'Event Count']]
    for idx, (ip, count) in enumerate(analytics.get('top_src_ips', [])[:10], 1):
        top_src_data.append([str(idx), ip, str(count)])
    
    src_table = Table(top_src_data, colWidths=[0.8*inch, 3*inch, 2.5*inch])
    src_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16a085')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightblue]),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(src_table)
    story.append(Spacer(1, 0.3*inch))
    
    story.append(Paragraph("Top Destination IP Addresses", heading2_style))
    top_dst_data = [['Rank', 'IP Address', 'Event Count']]
    for idx, (ip, count) in enumerate(analytics.get('top_dst_ips', [])[:10], 1):
        top_dst_data.append([str(idx), ip, str(count)])
    
    dst_table = Table(top_dst_data, colWidths=[0.8*inch, 3*inch, 2.5*inch])
    dst_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16a085')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightblue]),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(dst_table)
    story.append(PageBreak())
    
    # Section 5: Detailed Findings
    story.append(Paragraph("5. Detailed Findings", heading1_style))
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph(f"Event Type Distribution", heading2_style))
    event_type_data = [['Event Type', 'Count', 'Percentage']]
    total = analytics['total_events']
    for event_type, count in analytics.get('event_types', {}).items():
        percentage = (count / total * 100) if total > 0 else 0
        event_type_data.append([event_type, str(count), f"{percentage:.1f}%"])
    
    event_table = Table(event_type_data, colWidths=[2.5*inch, 2*inch, 2*inch])
    event_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2980b9')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightcyan]),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(event_table)
    
    # Build PDF
    doc.build(story)
    logger.info("PDF document built successfully")


def generate_docx_report():
    """Generate DOCX report from analyzed PCAP data."""
    logger.info("DOCX report generation requested")
    
    data = DataRepository.load_report_data()
    if not data:
        logger.warning("No data available for DOCX report")
        return jsonify({'error': 'No data available'}), 400
    
    events = data.get('events', [])
    analytics = AnalyticsService.analyze_events(events)
    
    # TODO: Implement DOCX generation using python-docx
    logger.info("DOCX generation placeholder - not yet implemented")
    return jsonify({
        'message': 'DOCX generation coming soon',
        'event_count': len(events),
        'analytics': analytics
    })


def generate_text_report():
    """Generate simple text report from analyzed PCAP data."""
    logger.info("Text report generation requested")
    
    data = DataRepository.load_report_data()
    if not data:
        logger.warning("No data available for text report")
        return "No data available", 400
    
    events = data.get('events', [])
    links = data.get('links', [])
    
    analytics = AnalyticsService.analyze_events(events)
    threat_service = ThreatService(events, links)
    threats = threat_service.analyze_threats()
    
    report = []
    report.append("=" * 60)
    report.append("PCAP ANALYSIS REPORT")
    report.append("=" * 60)
    report.append(f"\nTotal Events: {analytics['total_events']}")
    report.append(f"Event Types: {', '.join(analytics['event_types'].keys())}")
    report.append(f"\nTop Source IPs: {analytics['top_src_ips'][:5]}")
    report.append(f"Top Destination IPs: {analytics['top_dst_ips'][:5]}")
    
    logger.info("Text report generated successfully")
    return "\n".join(report), 200
