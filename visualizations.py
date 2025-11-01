"""
DomainScout Pro - Visualization Module
Create charts and visual representations of analysis data
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import pandas as pd
from typing import Dict, Any, List
from pathlib import Path
import datetime


class DataVisualizer:
    """Create visualizations for domain analysis data"""
    
    def __init__(self, output_dir: str = None):
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path(__file__).parent / "data" / "visualizations"
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8-darkgrid')
    
    def create_security_score_chart(self, data: Dict, domain: str) -> str:
        """Create security score visualization"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Overall risk score
        risk_score = data.get('risk_score', {})
        score = risk_score.get('score', 0)
        
        # Gauge chart
        colors = ['#f44336' if score < 40 else '#ff9800' if score < 60 else '#4caf50']
        ax1.barh([0], [score], color=colors[0], height=0.5)
        ax1.set_xlim(0, 100)
        ax1.set_ylim(-0.5, 0.5)
        ax1.set_xlabel('Security Score', fontsize=12, fontweight='bold')
        ax1.set_title(f'Overall Security Score: {score}/100', fontsize=14, fontweight='bold')
        ax1.set_yticks([])
        
        # Security headers breakdown
        sec_headers = data.get('security_headers', {})
        if sec_headers and 'headers_detail' in sec_headers:
            headers_detail = sec_headers['headers_detail']
            
            header_names = []
            header_status = []
            
            for name, info in headers_detail.items():
                if isinstance(info, dict):
                    header_names.append(name)
                    header_status.append(1 if info.get('present') else 0)
            
            colors_bars = ['#4caf50' if status else '#f44336' for status in header_status]
            ax2.barh(header_names, header_status, color=colors_bars)
            ax2.set_xlabel('Status', fontsize=12, fontweight='bold')
            ax2.set_title('Security Headers Status', fontsize=14, fontweight='bold')
            ax2.set_xlim(0, 1.2)
            ax2.set_xticks([0, 1])
            ax2.set_xticklabels(['Missing', 'Present'])
        
        plt.tight_layout()
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain}_security_chart_{timestamp}.png"
        filepath = self.output_dir / filename
        
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_dns_records_chart(self, data: Dict, domain: str) -> str:
        """Create DNS records visualization"""
        dns_records = data.get('dns_records', {})
        
        if not dns_records:
            return None
        
        # Count records
        record_counts = {}
        for record_type, values in dns_records.items():
            if isinstance(values, list):
                count = len([v for v in values if v and 'Error' not in str(v)])
                if count > 0:
                    record_counts[record_type] = count
        
        if not record_counts:
            return None
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        colors = plt.cm.Set3(range(len(record_counts)))
        wedges, texts, autotexts = ax.pie(
            record_counts.values(),
            labels=record_counts.keys(),
            autopct='%1.1f%%',
            colors=colors,
            startangle=90
        )
        
        ax.set_title(f'DNS Records Distribution - {domain}', fontsize=16, fontweight='bold', pad=20)
        
        # Make percentage text bold
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(10)
        
        plt.tight_layout()
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain}_dns_chart_{timestamp}.png"
        filepath = self.output_dir / filename
        
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_ports_chart(self, data: Dict, domain: str) -> str:
        """Create port scan visualization"""
        ports_data = data.get('ports_scan', {})
        
        if not ports_data or 'open_ports' not in ports_data:
            return None
        
        open_count = ports_data.get('open_count', 0)
        total_scanned = ports_data.get('total_scanned', 0)
        closed_count = total_scanned - open_count
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Pie chart
        sizes = [open_count, closed_count]
        labels = [f'Open ({open_count})', f'Closed ({closed_count})']
        colors = ['#f44336', '#4caf50']
        explode = (0.1, 0)
        
        ax1.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True, startangle=90)
        ax1.set_title('Port Status Distribution', fontsize=14, fontweight='bold')
        
        # Bar chart of open ports
        open_ports = ports_data.get('open_ports', [])
        if open_ports:
            ports = [str(p['port']) for p in open_ports]
            services = [p['service'] for p in open_ports]
            
            ax2.barh(services, [1]*len(services), color='#2196f3')
            ax2.set_xlabel('Open Status', fontsize=12, fontweight='bold')
            ax2.set_title('Open Ports & Services', fontsize=14, fontweight='bold')
            ax2.set_xlim(0, 1.2)
            
            # Add port numbers as labels
            for i, (port, service) in enumerate(zip(ports, services)):
                ax2.text(1.05, i, f'Port {port}', va='center', fontsize=9)
        
        plt.tight_layout()
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain}_ports_chart_{timestamp}.png"
        filepath = self.output_dir / filename
        
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_technologies_chart(self, data: Dict, domain: str) -> str:
        """Create detected technologies visualization"""
        tech_data = data.get('technologies', {})
        
        if not tech_data:
            return None
        
        # Count technologies by category
        tech_counts = {}
        for category, items in tech_data.items():
            if isinstance(items, list) and items and category != 'error':
                tech_counts[category.replace('_', ' ').title()] = len(items)
        
        if not tech_counts:
            return None
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        categories = list(tech_counts.keys())
        counts = list(tech_counts.values())
        
        colors = plt.cm.Paired(range(len(categories)))
        bars = ax.bar(categories, counts, color=colors, edgecolor='black', linewidth=1.5)
        
        ax.set_ylabel('Count', fontsize=12, fontweight='bold')
        ax.set_title(f'Detected Technologies - {domain}', fontsize=16, fontweight='bold', pad=20)
        ax.set_xlabel('Technology Category', fontsize=12, fontweight='bold')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontweight='bold')
        
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain}_technologies_chart_{timestamp}.png"
        filepath = self.output_dir / filename
        
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_performance_chart(self, data: Dict, domain: str) -> str:
        """Create performance metrics visualization"""
        performance = data.get('performance', {})
        
        if not performance or 'error' in performance:
            return None
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Load time gauge
        load_time = performance.get('load_time_seconds', 0)
        response_time = performance.get('response_time_ms', 0) / 1000
        
        metrics = ['Load Time', 'Response Time']
        values = [load_time, response_time]
        colors_perf = ['#4caf50' if v < 2 else '#ff9800' if v < 4 else '#f44336' for v in values]
        
        bars = ax1.barh(metrics, values, color=colors_perf, edgecolor='black', linewidth=1.5)
        ax1.set_xlabel('Time (seconds)', fontsize=12, fontweight='bold')
        ax1.set_title('Performance Metrics', fontsize=14, fontweight='bold')
        
        # Add values
        for i, (bar, value) in enumerate(zip(bars, values)):
            ax1.text(value + 0.1, i, f'{value:.2f}s', va='center', fontweight='bold')
        
        # Page size
        page_size_kb = performance.get('page_size_kb', 0)
        
        ax2.bar(['Page Size'], [page_size_kb], color='#2196f3', edgecolor='black', linewidth=1.5)
        ax2.set_ylabel('Size (KB)', fontsize=12, fontweight='bold')
        ax2.set_title('Page Size', fontsize=14, fontweight='bold')
        ax2.text(0, page_size_kb + 5, f'{page_size_kb:.2f} KB', ha='center', fontweight='bold')
        
        plt.tight_layout()
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain}_performance_chart_{timestamp}.png"
        filepath = self.output_dir / filename
        
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_all_visualizations(self, data: Dict, domain: str) -> Dict[str, str]:
        """Create all visualizations"""
        visualizations = {}
        
        try:
            chart = self.create_security_score_chart(data, domain)
            if chart:
                visualizations['security'] = chart
        except Exception as e:
            print(f"Security chart error: {e}")
        
        try:
            chart = self.create_dns_records_chart(data, domain)
            if chart:
                visualizations['dns'] = chart
        except Exception as e:
            print(f"DNS chart error: {e}")
        
        try:
            chart = self.create_ports_chart(data, domain)
            if chart:
                visualizations['ports'] = chart
        except Exception as e:
            print(f"Ports chart error: {e}")
        
        try:
            chart = self.create_technologies_chart(data, domain)
            if chart:
                visualizations['technologies'] = chart
        except Exception as e:
            print(f"Technologies chart error: {e}")
        
        try:
            chart = self.create_performance_chart(data, domain)
            if chart:
                visualizations['performance'] = chart
        except Exception as e:
            print(f"Performance chart error: {e}")
        
        return visualizations
