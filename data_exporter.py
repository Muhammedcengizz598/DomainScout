"""
DomainScout Pro - Data Export Module
Export analysis results to multiple formats
"""
import json
import csv
import datetime
from pathlib import Path
from typing import Dict, Any
from tabulate import tabulate
import pandas as pd


class DataExporter:
    """Handle all data export operations"""
    
    def __init__(self, base_path: str = None):
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = Path(__file__).parent / "data"
        
        self.json_path = self.base_path / "json_exports"
        self.csv_path = self.base_path / "csv_exports"
        self.html_path = self.base_path / "html_reports"
        
        # Create directories
        for path in [self.json_path, self.csv_path, self.html_path]:
            path.mkdir(parents=True, exist_ok=True)
    
    def export_to_json(self, data: Dict, domain: str) -> str:
        """Export complete data to JSON"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain}_{timestamp}.json"
        filepath = self.json_path / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False, default=str)
        
        return str(filepath)
    
    def export_to_csv(self, data: Dict, domain: str) -> Dict[str, str]:
        """Export data to multiple CSV files"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        exported_files = {}
        
        # Basic Info CSV
        basic_info = self._flatten_dict(data.get('basic_info', {}))
        if basic_info:
            filename = f"{domain}_basic_info_{timestamp}.csv"
            filepath = self.csv_path / filename
            self._write_dict_to_csv(basic_info, filepath)
            exported_files['basic_info'] = str(filepath)
        
        # WHOIS CSV
        whois_info = self._flatten_dict(data.get('whois_data', {}))
        if whois_info:
            filename = f"{domain}_whois_{timestamp}.csv"
            filepath = self.csv_path / filename
            self._write_dict_to_csv(whois_info, filepath)
            exported_files['whois'] = str(filepath)
        
        # DNS Records CSV
        dns_records = data.get('dns_records', {})
        if dns_records:
            filename = f"{domain}_dns_{timestamp}.csv"
            filepath = self.csv_path / filename
            self._write_dns_to_csv(dns_records, filepath)
            exported_files['dns'] = str(filepath)
        
        # Security Headers CSV
        security = data.get('security_headers', {})
        if security:
            filename = f"{domain}_security_{timestamp}.csv"
            filepath = self.csv_path / filename
            self._write_security_to_csv(security, filepath)
            exported_files['security'] = str(filepath)
        
        # Ports CSV
        ports = data.get('ports_scan', {})
        if ports and 'open_ports' in ports:
            filename = f"{domain}_ports_{timestamp}.csv"
            filepath = self.csv_path / filename
            self._write_ports_to_csv(ports['open_ports'], filepath)
            exported_files['ports'] = str(filepath)
        
        return exported_files
    
    def export_to_html(self, data: Dict, domain: str) -> str:
        """Export comprehensive HTML report"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain}_report_{timestamp}.html"
        filepath = self.html_path / filename
        
        html_content = self._generate_html_report(data, domain)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, ', '.join(map(str, v))))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _write_dict_to_csv(self, data: Dict, filepath: Path):
        """Write dictionary to CSV"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Field', 'Value'])
            for key, value in data.items():
                writer.writerow([key, value])
    
    def _write_dns_to_csv(self, dns_data: Dict, filepath: Path):
        """Write DNS records to CSV"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Record Type', 'Values'])
            for record_type, values in dns_data.items():
                if isinstance(values, list):
                    for value in values:
                        writer.writerow([record_type, value])
                else:
                    writer.writerow([record_type, values])
    
    def _write_security_to_csv(self, security_data: Dict, filepath: Path):
        """Write security headers to CSV"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Header', 'Present', 'Value'])
            
            headers_detail = security_data.get('headers_detail', {})
            for header, info in headers_detail.items():
                if isinstance(info, dict):
                    present = info.get('present', False)
                    value = info.get('value', 'Not set')
                    writer.writerow([header, present, value])
    
    def _write_ports_to_csv(self, ports_data: list, filepath: Path):
        """Write open ports to CSV"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Service', 'Status'])
            for port_info in ports_data:
                writer.writerow([
                    port_info.get('port'),
                    port_info.get('service'),
                    port_info.get('status')
                ])
    
    def _generate_html_report(self, data: Dict, domain: str) -> str:
        """Generate comprehensive HTML report"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DomainScout Pro - {domain} Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
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
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .domain {{
            font-size: 1.5em;
            opacity: 0.9;
            margin: 10px 0;
        }}
        
        .header .timestamp {{
            opacity: 0.7;
            font-size: 0.9em;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            border-left: 5px solid #667eea;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
        }}
        
        .risk-score {{
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        
        .risk-score h3 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .risk-score .score {{
            font-size: 4em;
            font-weight: bold;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        
        tr:hover {{
            background: #f5f5f5;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .badge-success {{
            background: #4caf50;
            color: white;
        }}
        
        .badge-danger {{
            background: #f44336;
            color: white;
        }}
        
        .badge-warning {{
            background: #ff9800;
            color: white;
        }}
        
        .badge-info {{
            background: #2196f3;
            color: white;
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }}
        
        .card h4 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.8em;
            }}
            .content {{
                padding: 20px;
            }}
            .grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DomainScout Pro</h1>
            <div class="domain">{domain}</div>
            <div class="timestamp">Generated: {timestamp}</div>
        </div>
        
        <div class="content">
"""
        
        # Risk Score
        risk_score = data.get('risk_score', {})
        if risk_score:
            score = risk_score.get('score', 0)
            rating = risk_score.get('rating', 'Unknown')
            
            html += f"""
            <div class="risk-score">
                <h3>Security Risk Assessment</h3>
                <div class="score">{score}/100</div>
                <div style="font-size: 1.5em; margin-top: 10px;">{rating}</div>
            </div>
"""
        
        # Basic Info
        basic_info = data.get('basic_info', {})
        if basic_info:
            html += """
            <div class="section">
                <h2>Basic Information</h2>
                <table>
                    <tr><th>Property</th><th>Value</th></tr>
"""
            for key, value in basic_info.items():
                html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
            html += "</table></div>"
        
        # WHOIS
        whois_data = data.get('whois_data', {})
        if whois_data and 'error' not in whois_data:
            html += """
            <div class="section">
                <h2>WHOIS Information</h2>
                <table>
                    <tr><th>Property</th><th>Value</th></tr>
"""
            for key, value in whois_data.items():
                if isinstance(value, list):
                    value = '<br>'.join(map(str, value))
                html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
            html += "</table></div>"
        
        # DNS Records
        dns_records = data.get('dns_records', {})
        if dns_records:
            html += """
            <div class="section">
                <h2>DNS Records</h2>
                <table>
                    <tr><th>Type</th><th>Records</th></tr>
"""
            for record_type, values in dns_records.items():
                if isinstance(values, list) and values:
                    records = '<br>'.join(map(str, values))
                    html += f"<tr><td><strong>{record_type}</strong></td><td>{records}</td></tr>"
            html += "</table></div>"
        
        # Security Headers
        security = data.get('security_headers', {})
        if security:
            html += f"""
            <div class="section">
                <h2>Security Headers Analysis</h2>
                <p><strong>Security Score:</strong> {security.get('security_score', 0)}%</p>
                <table>
                    <tr><th>Header</th><th>Status</th><th>Value</th></tr>
"""
            headers_detail = security.get('headers_detail', {})
            for header, info in headers_detail.items():
                if isinstance(info, dict):
                    present = info.get('present', False)
                    value = info.get('value', 'Not set')
                    badge = 'badge-success' if present else 'badge-danger'
                    status = 'Present' if present else 'Missing'
                    html += f"""
                    <tr>
                        <td>{header}</td>
                        <td><span class="badge {badge}">{status}</span></td>
                        <td>{value}</td>
                    </tr>
"""
            html += "</table></div>"
        
        # SSL Certificate
        ssl_info = data.get('ssl_certificate', {})
        if ssl_info and ssl_info.get('has_ssl'):
            html += """
            <div class="section">
                <h2>SSL Certificate</h2>
                <table>
                    <tr><th>Property</th><th>Value</th></tr>
"""
            for key, value in ssl_info.items():
                if key != 'san_names':
                    html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
            html += "</table></div>"
        
        # Open Ports
        ports = data.get('ports_scan', {})
        if ports and 'open_ports' in ports:
            open_ports = ports['open_ports']
            if open_ports:
                html += """
            <div class="section">
                <h2>Open Ports</h2>
                <table>
                    <tr><th>Port</th><th>Service</th><th>Status</th></tr>
"""
                for port in open_ports:
                    html += f"""
                    <tr>
                        <td>{port['port']}</td>
                        <td>{port['service']}</td>
                        <td><span class="badge badge-success">{port['status']}</span></td>
                    </tr>
"""
                html += "</table></div>"
        
        # Technologies
        tech = data.get('technologies', {})
        if tech:
            html += """
            <div class="section">
                <h2>Detected Technologies</h2>
                <div class="grid">
"""
            for tech_type, items in tech.items():
                if isinstance(items, list) and items and tech_type != 'error':
                    html += f"""
                <div class="card">
                    <h4>{tech_type.replace('_', ' ').title()}</h4>
                    <ul>
"""
                    for item in items:
                        html += f"<li>{item}</li>"
                    html += "</ul></div>"
            html += "</div></div>"
        
        # Close HTML
        html += """
        </div>
        <div class="footer">
            Generated by DomainScout Pro - Premium Domain Intelligence Platform
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def export_all(self, data: Dict, domain: str) -> Dict[str, Any]:
        """Export to all formats"""
        results = {
            'json': self.export_to_json(data, domain),
            'csv': self.export_to_csv(data, domain),
            'html': self.export_to_html(data, domain),
            'timestamp': datetime.datetime.now().isoformat()
        }
        return results
