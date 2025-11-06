"""
Vulnmap Report Generator
Creates professional security assessment reports
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Template
from utils.logger import get_logger
logger = get_logger(__name__)
class ReportGenerator:
    """Generate professional security reports."""
    def __init__(self, config: Dict):
        """Initialize report generator."""
        self.config = config
        self.report_config = config.get('reporting', {})
        self.template_dir = Path(__file__).parent.parent.parent / 'templates'
    def generate(self, results: Dict, output_path: str, format: str = 'html'):
        """
        Generate security report.
        Args:
            results: Scan results
            output_path: Output file path
            format: Report format (html, pdf, json)
        """
        if format == 'json':
            self._generate_json(results, output_path)
        elif format == 'html':
            self._generate_html(results, output_path)
        elif format == 'pdf':
            self._generate_pdf(results, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
    def _generate_json(self, results: Dict, output_path: str):
        """Generate JSON report."""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"JSON report generated: {output_path}")
    def _generate_html(self, results: Dict, output_path: str):
        """Generate HTML report."""
        template_content = self._get_html_template_content() # Changed function name to reflect content return
        template = Template(template_content)
        report_data = {
            'title': 'Vulnmap Security Assessment Report', # Changed
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target': results.get('target'),
            'scan_duration': results.get('duration'),
            'summary': self._generate_summary(results),
            'vulnerabilities': self._sort_vulnerabilities(results.get('vulnerabilities', [])),
            'severity_counts': results.get('severity_summary', {}),
            'urls_scanned': results.get('urls_crawled', 0),
            'reconnaissance': results.get('reconnaissance', {}),
        }
        html_content = template.render(**report_data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"HTML report generated: {output_path}")
    def _generate_pdf(self, results: Dict, output_path: str):
        """Generate PDF report using ReportLab (Windows-friendly)."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
            from xml.sax.saxutils import escape
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=12,
                spaceBefore=12
            )
            story.append(Paragraph("Vulnmap Security Assessment Report", title_style)) # Changed
            story.append(Spacer(1, 0.2*inch))
            metadata = [
                ['Target:', results.get('target', 'N/A')],
                ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Scan Duration:', str(results.get('duration', 'N/A'))],
                ['URLs Scanned:', str(results.get('urls_crawled', 0))]
            ]
            metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
            metadata_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(metadata_table)
            story.append(Spacer(1, 0.3*inch))
            recon_data = results.get('reconnaissance', {})
            if recon_data:
                story.append(Paragraph("Reconnaissance & OSINT Intelligence", heading_style))
                dns_info = recon_data.get('dns', {})
                if dns_info:
                    story.append(Paragraph("<b>DNS Records:</b>", styles['Heading4']))
                    dns_records = []
                    for record_type, records in dns_info.items():
                        if records:
                            dns_records.append([record_type.upper(), ', '.join(str(r) for r in records[:3])])
                    if dns_records:
                        dns_table = Table([[heading, data] for heading, data in dns_records], colWidths=[1.5*inch, 4.5*inch])
                        dns_table.setStyle(TableStyle([
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ]))
                        story.append(dns_table)
                        story.append(Spacer(1, 0.15*inch))
                osint_data = recon_data.get('osint', {})
                if osint_data:
                    story.append(Paragraph("<b>OSINT Findings:</b>", styles['Heading4']))
                    emails = osint_data.get('emails', [])
                    if emails:
                        story.append(Paragraph(f"Emails found: {len(emails)}", styles['BodyText']))
                        safe_emails = [escape(str(e)) for e in emails[:5]]
                        story.append(Paragraph(', '.join(safe_emails), styles['BodyText']))
                        story.append(Spacer(1, 0.1*inch))
                    subdomains = osint_data.get('subdomains', [])
                    if subdomains:
                        story.append(Paragraph(f"Subdomains discovered: {len(subdomains)}", styles['BodyText']))
                        safe_subdomains = [escape(str(s)) for s in subdomains[:10]]
                        story.append(Paragraph(', '.join(safe_subdomains), styles['BodyText']))
                        story.append(Spacer(1, 0.1*inch))
                    technologies = recon_data.get('technologies', [])
                    if technologies:
                        safe_techs = [escape(str(t)) for t in technologies]
                        story.append(Paragraph(f"Technologies detected: {', '.join(safe_techs)}", styles['BodyText']))
                        story.append(Spacer(1, 0.1*inch))
                story.append(PageBreak())
            severity_counts = results.get('severity_summary', {})
            severity_data = [
                ['Severity', 'Count'],
                ['Critical', str(severity_counts.get('critical', 0))],
                ['High', str(severity_counts.get('high', 0))],
                ['Medium', str(severity_counts.get('medium', 0))],
                ['Low', str(severity_counts.get('low', 0))]
            ]
            severity_table = Table(severity_data, colWidths=[3*inch, 3*inch])
            severity_colors = {
                1: colors.HexColor('#ff0000'),  # Critical (Used the HTML critical color for consistency)
                2: colors.HexColor('#ff4444'),  # High
                3: colors.HexColor('#ff9500'),  # Medium
                4: colors.HexColor('#ffd700')   # Low
            }
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ] + [
                ('BACKGROUND', (0, i), (0, i), severity_colors[i])
                for i in severity_colors.keys()
            ]))
            story.append(severity_table)
            story.append(Spacer(1, 0.3*inch))
            story.append(Paragraph("Executive Summary", heading_style))
            summary_text = self._generate_summary(results)
            story.append(Paragraph(summary_text.replace('\n', '<br/>'), styles['BodyText']))
            story.append(Spacer(1, 0.3*inch))
            story.append(Paragraph("Vulnerabilities", heading_style))
            vulnerabilities = self._sort_vulnerabilities(results.get('vulnerabilities', []))
            if vulnerabilities:
                for vuln in vulnerabilities:
                    vuln_type = escape(str(vuln.get('type', 'Unknown')))
                    vuln_severity = escape(str(vuln.get('severity', 'info').upper()))
                    vuln_title = f"<b>{vuln_type}</b> - {vuln_severity}"
                    story.append(Paragraph(vuln_title, styles['Heading3']))
                    vuln_url = escape(str(vuln.get('url', 'N/A')))
                    vuln_param = escape(str(vuln.get('parameter', 'N/A')))
                    vuln_desc = escape(str(vuln.get('description', 'N/A')))
                    vuln_evidence = escape(str(vuln.get('evidence', 'N/A'))[:200])  # Limit evidence length
                    vuln_remediation = escape(str(vuln.get('remediation', 'N/A')))
                    vuln_details = f"""
                    <b>URL:</b> {vuln_url}<br/>
                    <b>Parameter:</b> {vuln_param}<br/>
                    <b>Description:</b> {vuln_desc}<br/>
                    <b>Evidence:</b> {vuln_evidence}<br/>
                    <b>Remediation:</b> {vuln_remediation}
                    """
                    story.append(Paragraph(vuln_details, styles['BodyText']))
                    story.append(Spacer(1, 0.2*inch))
            else:
                story.append(Paragraph("No vulnerabilities detected.", styles['BodyText']))
            doc.build(story)
            logger.info(f"PDF report generated: {output_path}")
        except ImportError as e:
            logger.error(f"ReportLab not available: {e}")
            logger.info("Falling back to HTML report...")
            html_path = output_path.replace('.pdf', '.html')
            self._generate_html(results, html_path)
            logger.info(f"HTML report available at: {html_path}")
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            logger.info("Falling back to HTML report...")
            html_path = output_path.replace('.pdf', '.html')
            self._generate_html(results, html_path)
            logger.info(f"HTML report available at: {html_path}")
    def _generate_summary(self, results: Dict) -> str:
        """Generate executive summary."""
        total_vulns = len(results.get('vulnerabilities', []))
        severity_counts = results.get('severity_summary', {})
        summary = f"""
        This security assessment identified {total_vulns} potential security issues on the target system.
        Critical vulnerabilities require immediate attention as they pose significant risk to the organization.
        High and medium severity issues should be addressed in order of priority.
        Risk Distribution:
        - Critical: {severity_counts.get('critical', 0)} issues
        - High: {severity_counts.get('high', 0)} issues
        - Medium: {severity_counts.get('medium', 0)} issues
        - Low: {severity_counts.get('low', 0)} issues
        """
        return summary.strip()
    def _sort_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Sort vulnerabilities by severity."""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        return sorted(
            vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )
    def _get_html_template_content(self) -> str:
        """Get HTML report template content (using the new dark theme)."""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #ffffff;
            background: #000000;
            position: relative;
            min-width: 1200px;
        }
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image:
                repeating-linear-gradient(0deg, transparent, transparent 49px, rgba(255, 255, 255, 0.1) 49px, rgba(255, 255, 255, 0.1) 50px),
                repeating-linear-gradient(90deg, transparent, transparent 49px, rgba(255, 255, 255, 0.1) 49px, rgba(255, 255, 255, 0.1) 50px);
            pointer-events: none;
            z-index: 0;
        }
        .container {
            max-width: 1300px;
            margin: 0 auto;
            padding: 50px 40px;
            position: relative;
            z-index: 1;
        }
        .header {
            background: #1a1a1a;
            border: 1px solid rgba(100, 100, 100, 0.4);
            border-radius: 8px;
            padding: 45px 40px;
            margin-bottom: 35px;
        }
        .header h1 {
            font-size: 2.4em;
            font-weight: 700;
            margin-bottom: 10px;
            color: #ffffff;
        }
        .header p {
            color: #cccccc;
            font-size: 1em;
        }
        .metadata {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 35px;
        }
        .metadata-card {
            background: #1a1a1a;
            border: 1px solid rgba(100, 100, 100, 0.4);
            border-radius: 8px;
            padding: 25px 22px;
        }
        .metadata-card h3 {
            color: #ffffff;
            margin-bottom: 10px;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        .metadata-card p {
            font-size: 1.3em;
            font-weight: 600;
            color: #ffffff;
        }
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 35px;
            grid-auto-rows: 1fr;
            align-items: stretch;
        }
        .severity-card {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: #1a1a1a;
            border: 1px solid rgba(100, 100, 100, 0.4);
            border-radius: 8px;
            padding: 28px 20px;
            text-align: center;
            min-height: 140px;
            box-shadow: none;
            overflow: hidden;
        }
        .severity-card h3 {
            font-size: clamp(28px, 4.6vw, 48px);
            line-height: 1;
            margin: 0 0 8px;
            font-weight: 800;
            text-align: center;
            word-break: break-word;
            letter-spacing: -0.02em;
            display: block;
        }
        .severity-card p {
            color: #ffffff;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.95em;
            font-weight: 700;
            margin: 0;
        }
        .severity-critical h3 {
            color: #ff0000;
            text-shadow: 0 0 10px rgba(255, 0, 0, 0.18);
        }
        .severity-high h3 {
            color: #ff4444;
            text-shadow: 0 0 10px rgba(255, 68, 68, 0.16);
        }
        .severity-medium h3 {
            color: #ff9500;
            text-shadow: 0 0 10px rgba(255, 149, 0, 0.14);
        }
        .severity-low h3 {
            color: #ffd700;
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.14);
        }
        .severity-card h3, .severity-card p {
            hyphens: auto;
            overflow-wrap: break-word;
        }
        @media (max-width: 900px) {
            .severity-grid { grid-template-columns: repeat(2, 1fr); }
            .severity-card { min-height: 120px; }
        }
        @media (max-width: 480px) {
            .severity-grid { grid-template-columns: 1fr; }
            .severity-card { min-height: 100px; padding: 20px; }
        }
        .section {
            background: #1a1a1a;
            border: 1px solid rgba(100, 100, 100, 0.4);
            border-radius: 8px;
            padding: 35px 32px;
            margin-bottom: 30px;
        }
        .section h2 {
            color: #ffffff;
            margin-bottom: 25px;
            font-size: 1.6em;
            font-weight: 700;
            text-transform: uppercase;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(100, 100, 100, 0.3);
        }
        .section > p {
            color: #ffffff;
            font-size: 1em;
            line-height: 1.7;
        }
        .vulnerability {
            border: 1px solid rgba(100, 100, 100, 0.4);
            border-left-width: 4px;
            border-radius: 6px;
            padding: 25px;
            margin-bottom: 22px;
            background: #1a1a1a;
        }
        .vulnerability.critical { border-left-color: #ff0000; }
        .vulnerability.high { border-left-color: #ff4444; }
        .vulnerability.medium { border-left-color: #ff9500; }
        .vulnerability.low { border-left-color: #ffd700; }
        .vulnerability h3 {
            color: #ffffff;
            margin-bottom: 16px;
            font-size: 1.2em;
            font-weight: 700;
        }
        .vulnerability-meta {
            display: flex;
            gap: 15px;
            margin: 16px 0;
            flex-wrap: wrap;
        }
        .vulnerability-meta span {
            background: #1a1a1a;
            border: 1px solid rgba(100, 100, 100, 0.4);
            border-radius: 4px;
            padding: 8px 14px;
            font-size: 0.85em;
            color: #ffffff;
        }
        .vulnerability-meta span strong {
            color: #ffffff;
            margin-right: 6px;
            font-weight: 700;
        }
        .vulnerability p {
            margin: 12px 0;
            color: #ffffff;
            line-height: 1.6;
            font-size: 0.95em;
        }
        .vulnerability p strong {
            color: #ffffff;
            font-weight: 700;
            margin-right: 8px;
        }
        .code {
            background: #1a1a1a;
            border: 1px solid rgba(100, 100, 100, 0.4);
            border-radius: 6px;
            color: #ffffff;
            padding: 18px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin: 15px 0;
            font-size: 0.9em;
            line-height: 1.5;
        }
        .recon-subsection {
            margin: 22px 0;
            padding: 25px;
            background: #1a1a1a;
            border: 1px solid rgba(100, 100, 100, 0.4);
            border-radius: 6px;
        }
        .recon-subsection h3 {
            color: #ffffff;
            margin-bottom: 15px;
            font-size: 1.1em;
            font-weight: 700;
            text-transform: uppercase;
        }
        .recon-data p {
            margin: 12px 0;
            color: #ffffff;
            font-size: 0.95em;
            line-height: 1.6;
        }
        .recon-data p strong {
            color: #ffffff;
            margin-right: 8px;
            font-weight: 700;
        }
        .footer {
            text-align: center;
            padding: 35px 20px;
            color: #ffffff;
            margin-top: 40px;
            border-top: 1px solid rgba(100, 100, 100, 0.3);
        }
        .footer p {
            margin: 8px 0;
            font-size: 0.95em;
        }
        .footer p:first-child {
            font-weight: 700;
            font-size: 1em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ title }}</h1>
            <p>Generated: {{ generated_date }}</p>
        </div>
        <div class="metadata">
            <div class="metadata-card">
                <h3>Target</h3>
                <p>{{ target }}</p>
            </div>
            <div class="metadata-card">
                <h3>Scan Duration</h3>
                <p>{{ scan_duration }}</p>
            </div>
            <div class="metadata-card">
                <h3>URLs Scanned</h3>
                <p>{{ urls_scanned }}</p>
            </div>
        </div>
        <div class="severity-grid">
            <div class="severity-card severity-critical">
                <h3>{{ severity_counts.critical }}</h3>
                <p>Critical</p>
            </div>
            <div class="severity-card severity-high">
                <h3>{{ severity_counts.high }}</h3>
                <p>High</p>
            </div>
            <div class="severity-card severity-medium">
                <h3>{{ severity_counts.medium }}</h3>
                <p>Medium</p>
            </div>
            <div class="severity-card severity-low">
                <h3>{{ severity_counts.low }}</h3>
                <p>Low</p>
            </div>
        </div>
        {% if reconnaissance %}
        <div class="section">
            <h2>Reconnaissance & OSINT Intelligence</h2>
            {% if reconnaissance.dns %}
            <div class="recon-subsection">
                <h3>DNS Records</h3>
                <div class="recon-data">
                    {% for record_type, records in reconnaissance.dns.items() %}
                        {% if records %}
                        <p><strong>{{ record_type|upper }}:</strong> {{ records|join(', ') }}</p>
                        {% endif %}
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            {% if reconnaissance.osint %}
            <div class="recon-subsection">
                <h3>OSINT Findings</h3>
                <div class="recon-data">
                    {% if reconnaissance.osint.emails %}
                    <p><strong>Emails Found:</strong> {{ reconnaissance.osint.emails|length }}</p>
                    <div class="code">{{ reconnaissance.osint.emails|join(', ') }}</div>
                    {% endif %}
                    {% if reconnaissance.osint.subdomains %}
                    <p><strong>Subdomains Discovered:</strong> {{ reconnaissance.osint.subdomains|length }}</p>
                    <div class="code">{{ reconnaissance.osint.subdomains[:10]|join(', ') }}</div>
                    {% endif %}
                    {% if reconnaissance.osint.github_leaks %}
                    <p><strong>GitHub Potential Leaks:</strong> {{ reconnaissance.osint.github_leaks|length }}</p>
                    {% endif %}
                    {% if reconnaissance.osint.breaches %}
                    <p><strong>Breach Database Results:</strong></p>
                    <div class="code">{{ reconnaissance.osint.breaches|join(', ') }}</div>
                    {% endif %}
                </div>
            </div>
            {% endif %}
            {% if reconnaissance.technologies %}
            <div class="recon-subsection">
                <h3>Technologies Detected</h3>
                <div class="recon-data">
                    <p>{{ reconnaissance.technologies|join(', ') }}</p>
                </div>
            </div>
            {% endif %}
        </div>
        {% endif %}
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{{ summary }}</p>
        </div>
        <div class="section">
            <h2>Vulnerabilities</h2>
            {% if vulnerabilities %}
                {% for vuln in vulnerabilities %}
                <div class="vulnerability {{ vuln.severity }}">
                    <h3>{{ vuln.type }}</h3>
                    <div class="vulnerability-meta">
                        <span><strong>Severity:</strong> {{ vuln.severity|upper }}</span>
                        <span><strong>URL:</strong> {{ vuln.url }}</span>
                        {% if vuln.parameter %}
                        <span><strong>Parameter:</strong> {{ vuln.parameter }}</span>
                        {% endif %}
                    </div>
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    {% if vuln.payload %}
                    <p><strong>Payload:</strong></p>
                    <div class="code">{{ vuln.payload }}</div>
                    {% endif %}
                    <p><strong>Evidence:</strong> {{ vuln.evidence }}</p>
                    <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
                </div>
                {% endfor %}
            {% else %}
                <p>No vulnerabilities detected.</p>
            {% endif %}
        </div>
        <div class="footer">
            <p>Vulnmap - Advanced AI-Driven Penetration Testing Platform</p>
            <p>This report contains sensitive security information. Handle with appropriate discretion.</p>
        </div>
    </div>
</body>
</html>
'''
