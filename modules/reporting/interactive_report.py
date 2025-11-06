"""
Interactive HTML Report Generator
Generates interactive, feature-rich HTML reports with charts and filtering
"""
import json
from typing import Dict, List
from datetime import datetime
from utils.logger import get_logger
logger = get_logger(__name__)
class InteractiveReportGenerator:
    """Generate interactive HTML reports with JavaScript functionality."""
    def __init__(self, config: Dict):
        """Initialize interactive report generator."""
        self.config = config
    def generate_interactive_report(self, scan_results: Dict, output_file: str) -> str:
        """
        Generate interactive HTML report.
        Args:
            scan_results: Scan results dictionary
            output_file: Output file path
        Returns:
            Path to generated report
        """
        html_content = self._build_interactive_html(scan_results)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"Interactive report generated: {output_file}")
        return output_file
    def _build_interactive_html(self, results: Dict) -> str:
        """Build interactive HTML report."""
        vulnerabilities = results.get('vulnerabilities', [])
        target = results.get('target', 'Unknown')
        scan_time = results.get('scan_time', datetime.now().isoformat())
        vuln_data_json = json.dumps(vulnerabilities)
        severity_stats = self._calculate_severity_stats(vulnerabilities)
        type_stats = self._calculate_type_stats(vulnerabilities)
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnmap Security Report - {target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .stats-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }}
        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .stat-card .label {{
            color: #666;
            font-size: 1.1em;
        }}
        .critical {{ color: #e74c3c; }}
        .high {{ color: #e67e22; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #3498db; }}
        .info {{ color: #95a5a6; }}
        .controls {{
            padding: 30px;
            background: white;
            border-bottom: 2px solid #ecf0f1;
        }}
        .controls h2 {{
            margin-bottom: 20px;
            color: #2c3e50;
        }}
        .filter-group {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }}
        .filter-btn {{
            padding: 10px 20px;
            border: 2px solid #3498db;
            background: white;
            color: #3498db;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 1em;
        }}
        .filter-btn:hover {{
            background: #3498db;
            color: white;
        }}
        .filter-btn.active {{
            background: #3498db;
            color: white;
        }}
        .search-box {{
            width: 100%;
            padding: 15px;
            border: 2px solid #ecf0f1;
            border-radius: 5px;
            font-size: 1em;
        }}
        .charts-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            padding: 30px;
            background: white;
        }}
        .chart-card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .chart-card h3 {{
            margin-bottom: 20px;
            color: #2c3e50;
            text-align: center;
        }}
        .vulnerabilities {{
            padding: 30px;
        }}
        .vuln-card {{
            background: white;
            border-left: 5px solid;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: all 0.3s;
        }}
        .vuln-card:hover {{
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
            transform: translateX(5px);
        }}
        .vuln-card.critical {{ border-left-color: #e74c3c; }}
        .vuln-card.high {{ border-left-color: #e67e22; }}
        .vuln-card.medium {{ border-left-color: #f39c12; }}
        .vuln-card.low {{ border-left-color: #3498db; }}
        .vuln-card.info {{ border-left-color: #95a5a6; }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .vuln-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.85em;
        }}
        .severity-badge.critical {{ background: #e74c3c; }}
        .severity-badge.high {{ background: #e67e22; }}
        .severity-badge.medium {{ background: #f39c12; }}
        .severity-badge.low {{ background: #3498db; }}
        .severity-badge.info {{ background: #95a5a6; }}
        .vuln-url {{
            color: #7f8c8d;
            font-size: 0.95em;
            margin-bottom: 10px;
            word-break: break-all;
        }}
        .vuln-description {{
            margin-bottom: 15px;
            line-height: 1.6;
        }}
        .vuln-evidence {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-bottom: 15px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .vuln-remediation {{
            background: #e8f5e9;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #4caf50;
        }}
        .vuln-remediation strong {{
            color: #2e7d32;
        }}
        .footer {{
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
        }}
        .hidden {{
            display: none !important;
        }}
        @media print {{
            .controls, .charts-container {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Vulnmap Security Report</h1>
            <div class="subtitle">
                Target: {target}<br>
                Scan Date: {scan_time}
            </div>
        </div>
        <div class="stats-container">
            <div class="stat-card">
                <div class="number critical">{severity_stats.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number high">{severity_stats.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number medium">{severity_stats.get('medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="number low">{severity_stats.get('low', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card">
                <div class="number info">{severity_stats.get('info', 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>
        <div class="controls">
            <h2>Filters & Search</h2>
            <div class="filter-group">
                <button class="filter-btn active" onclick="filterBySeverity('all')">All</button>
                <button class="filter-btn" onclick="filterBySeverity('critical')">Critical</button>
                <button class="filter-btn" onclick="filterBySeverity('high')">High</button>
                <button class="filter-btn" onclick="filterBySeverity('medium')">Medium</button>
                <button class="filter-btn" onclick="filterBySeverity('low')">Low</button>
                <button class="filter-btn" onclick="filterBySeverity('info')">Info</button>
            </div>
            <input type="text" class="search-box" id="searchBox" placeholder="Search vulnerabilities..." onkeyup="searchVulnerabilities()">
        </div>
        <div class="charts-container">
            <div class="chart-card">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Vulnerability Types</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>
        <div class="vulnerabilities" id="vulnerabilitiesContainer">
            {self._generate_vulnerability_cards(vulnerabilities)}
        </div>
        <div class="footer">
            <p>Generated by Vulnmap v1.1.0 | &copy; 2025 | For authorized testing only</p>
        </div>
    </div>
    <script>
        const vulnerabilities = {vuln_data_json};
        let currentFilter = 'all';
        // Initialize charts
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{severity_stats.get('critical', 0)}, {severity_stats.get('high', 0)}, {severity_stats.get('medium', 0)}, {severity_stats.get('low', 0)}, {severity_stats.get('info', 0)}],
                    backgroundColor: ['#e74c3c', '#e67e22', '#f39c12', '#3498db', '#95a5a6']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
        const typeCtx = document.getElementById('typeChart').getContext('2d');
        const typeData = {json.dumps(type_stats)};
        const typeChart = new Chart(typeCtx, {{
            type: 'bar',
            data: {{
                labels: Object.keys(typeData),
                datasets: [{{
                    label: 'Count',
                    data: Object.values(typeData),
                    backgroundColor: '#3498db'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        function filterBySeverity(severity) {{
            currentFilter = severity;
            const cards = document.querySelectorAll('.vuln-card');
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            cards.forEach(card => {{
                if (severity === 'all' || card.classList.contains(severity)) {{
                    card.classList.remove('hidden');
                }} else {{
                    card.classList.add('hidden');
                }}
            }});
        }}
        function searchVulnerabilities() {{
            const searchTerm = document.getElementById('searchBox').value.toLowerCase();
            const cards = document.querySelectorAll('.vuln-card');
            cards.forEach(card => {{
                const text = card.textContent.toLowerCase();
                if (text.includes(searchTerm)) {{
                    if (currentFilter === 'all' || card.classList.contains(currentFilter)) {{
                        card.classList.remove('hidden');
                    }}
                }} else {{
                    card.classList.add('hidden');
                }}
            }});
        }}
    </script>
</body>
</html>'''
        return html
    def _generate_vulnerability_cards(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML cards for vulnerabilities."""
        if not vulnerabilities:
            return '<div class="vuln-card info"><p>No vulnerabilities found!</p></div>'
        cards_html = []
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            vuln_type = vuln.get('type', 'Unknown')
            url = vuln.get('url', 'N/A')
            description = vuln.get('description', 'No description available')
            evidence = vuln.get('evidence', 'No evidence available')
            remediation = vuln.get('remediation', 'No remediation available')
            card = f'''
            <div class="vuln-card {severity}">
                <div class="vuln-header">
                    <div class="vuln-title">{vuln_type}</div>
                    <div class="severity-badge {severity}">{severity}</div>
                </div>
                <div class="vuln-url"><strong>URL:</strong> {url}</div>
                <div class="vuln-description">{description}</div>
                <div class="vuln-evidence"><strong>Evidence:</strong><br>{evidence}</div>
                <div class="vuln-remediation"><strong>Remediation:</strong><br>{remediation}</div>
            </div>
            '''
            cards_html.append(card)
        return ''.join(cards_html)
    def _calculate_severity_stats(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate severity statistics."""
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in stats:
                stats[severity] += 1
        return stats
    def _calculate_type_stats(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability type statistics."""
        stats = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_type = vuln_type[:30] + '...' if len(vuln_type) > 30 else vuln_type
            stats[vuln_type] = stats.get(vuln_type, 0) + 1
        sorted_stats = dict(sorted(stats.items(), key=lambda x: x[1], reverse=True)[:10])
        return sorted_stats
