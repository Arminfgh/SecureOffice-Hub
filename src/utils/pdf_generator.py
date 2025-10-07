"""
PDF Report Generator for ThreatScope Analysis
Creates professional PDF reports with all analysis results
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.platypus import Image as RLImage
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import io


def generate_analysis_pdf(analysis_data):
    """
    Generate PDF report from analysis data
    
    Args:
        analysis_data: Dictionary containing all analysis results
        
    Returns:
        BytesIO buffer containing PDF data
    """
    buffer = io.BytesIO()
    
    # Create PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50
    )
    
    # Container for PDF elements
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#000000'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor('#666666'),
        spaceAfter=20,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#000000'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    # Header
    elements.append(Paragraph("🛡️ ThreatScope", title_style))
    elements.append(Paragraph("AI-Powered Threat Intelligence Analysis Report", subtitle_style))
    elements.append(Paragraph("⚫🟡 Directed by Armin Foroughi 🟡⚫", subtitle_style))
    elements.append(Spacer(1, 0.3*inch))
    
    # Analysis Info
    elements.append(Paragraph("Analysis Information", heading_style))
    
    info_data = [
        ['Analyzed URL:', analysis_data.get('url', 'N/A')],
        ['Analysis Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Threat Level:', analysis_data.get('threat_level', 'UNKNOWN')],
        ['Confidence:', f"{analysis_data.get('confidence', 0) * 100:.0f}%"],
        ['Threat Type:', analysis_data.get('threat_type', 'Unknown')]
    ]
    
    info_table = Table(info_data, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    
    elements.append(info_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Step Results
    if 'steps' in analysis_data:
        elements.append(Paragraph("Analysis Steps", heading_style))
        
        steps = analysis_data['steps']
        
        # Step 1: VirusTotal
        if 'vt_result' in steps:
            vt = steps['vt_result']
            step_data = [
                ['Step 1: VirusTotal Check', ''],
                ['Status:', 'Found' if vt.get('found') else 'Clean'],
                ['Detections:', f"{vt.get('positives', 0)}/{vt.get('total', 0)}"]
            ]
            add_step_table(elements, step_data)
        
        # Step 2: DNS
        if 'dns_result' in steps:
            dns = steps['dns_result']
            step_data = [
                ['Step 2: DNS Resolution', ''],
                ['IP Address:', dns.get('ip', 'N/A')],
                ['Country:', dns.get('country', 'Unknown')],
                ['ISP:', dns.get('isp', 'Unknown')],
                ['Status:', 'Suspicious' if dns.get('suspicious') else 'Normal']
            ]
            add_step_table(elements, step_data)
        
        # Step 3: WHOIS
        if 'whois_result' in steps:
            whois = steps['whois_result']
            step_data = [
                ['Step 3: WHOIS Lookup', ''],
                ['Domain Age:', whois.get('age', 'Unknown')],
                ['Registrar:', whois.get('registrar', 'Unknown')],
                ['TLD:', whois.get('tld', 'Unknown')],
                ['Typosquatting:', 'YES' if whois.get('typosquatting') else 'NO']
            ]
            if whois.get('typosquatting'):
                step_data.append(['Similar to:', whois.get('similar_to', 'N/A')])
            add_step_table(elements, step_data)
        
        # Step 4: IP Reputation
        if 'ip_rep_result' in steps:
            ip_rep = steps['ip_rep_result']
            step_data = [
                ['Step 4: IP Reputation', ''],
                ['Reputation Score:', f"{ip_rep.get('score', 0)}/100"],
                ['Detections:', f"{ip_rep.get('positives', 0)}/{ip_rep.get('total', 0)}"],
                ['Status:', 'Malicious' if ip_rep.get('malicious') else 'Clean']
            ]
            add_step_table(elements, step_data)
        
        # Step 5: SSL
        if 'ssl_result' in steps:
            ssl = steps['ssl_result']
            step_data = [
                ['Step 5: SSL Certificate', ''],
                ['Valid:', 'YES' if ssl.get('valid') else 'NO'],
                ['Issuer:', ssl.get('issuer', 'Unknown')],
                ['Status:', ssl.get('status', 'Unknown')]
            ]
            add_step_table(elements, step_data)
        
        # Step 6: Patterns
        if 'patterns' in steps:
            patterns = steps['patterns']
            keywords = patterns.get('keywords', [])
            step_data = [
                ['Step 6: Pattern Recognition', ''],
                ['Suspicious Keywords:', ', '.join(keywords) if keywords else 'None']
            ]
            add_step_table(elements, step_data)
    
    elements.append(Spacer(1, 0.2*inch))
    
    # IOCs
    if 'iocs' in analysis_data and analysis_data['iocs']:
        elements.append(Paragraph("Indicators of Compromise (IOCs)", heading_style))
        
        ioc_data = [['Type', 'Value', 'Threat Level']]
        for ioc in analysis_data['iocs']:
            ioc_data.append([
                ioc.get('type', '').replace('_', ' ').title(),
                ioc.get('value', 'N/A'),
                ioc.get('threat_level', 'MEDIUM')
            ])
        
        ioc_table = Table(ioc_data, colWidths=[1.5*inch, 3*inch, 1.5*inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#333333')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 9)
        ]))
        
        elements.append(ioc_table)
        elements.append(Spacer(1, 0.2*inch))
    
    # Recommendations
    if 'recommendations' in analysis_data and analysis_data['recommendations']:
        elements.append(Paragraph("Recommendations", heading_style))
        
        rec_text = "<br/>".join([f"• {rec}" for rec in analysis_data['recommendations']])
        elements.append(Paragraph(rec_text, styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
    
    # Footer
    elements.append(Spacer(1, 0.5*inch))
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.grey,
        alignment=TA_CENTER
    )
    elements.append(Paragraph("Generated by ThreatScope - AI-Powered Threat Intelligence Platform", footer_style))
    elements.append(Paragraph("⚫🟡 Borussia Dortmund Interview Project 🟡⚫", footer_style))
    elements.append(Paragraph(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))
    
    # Build PDF
    doc.build(elements)
    
    buffer.seek(0)
    return buffer


def add_step_table(elements, data):
    """Add a step result table to the PDF"""
    table = Table(data, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a90e2')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.15*inch))