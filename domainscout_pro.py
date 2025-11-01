"""
DomainScout Pro - Premium Domain İstihbarat Platformu
Modern ve Duyarlı Tasarımlı Arayüz
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
from typing import Dict, Any, Optional
import threading
import json
import webbrowser
from pathlib import Path
import datetime

from domain_engine import DomainAnalyzer
from data_exporter import DataExporter


class DomainScoutPro:
    """Modern arayüzlü ana uygulama sınıfı"""
    
    def __init__(self):
        # Set appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize main window
        self.root = ctk.CTk()
        self.root.title("DomainScout Pro - Premium Domain İstihbaratı")
        self.root.geometry("1600x1000")
        
        # Set minimum size
        self.root.minsize(1200, 800)
        
        # Center window
        self._center_window()
        
        # Initialize components
        self.analyzer = DomainAnalyzer()
        self.exporter = DataExporter()
        self.current_results = None
        self.analysis_in_progress = False
        
        # Build UI
        self._create_ui()
        
        # Bind resize
        self.root.bind('<Configure>', self._on_resize)
        
    def _center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def _on_resize(self, event):
        """Handle window resize for responsiveness"""
        pass
    
    def _create_ui(self):
        """Create the complete user interface"""
        # Main container
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create sections
        self._create_header()
        self._create_input_section()
        self._create_tabs()
        self._create_status_bar()
    
    def _create_header(self):
        """Create header section"""
        header_frame = ctk.CTkFrame(
            self.main_container, 
            fg_color=("#1a1a2e", "#16213e"),
            height=150
        )
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Create gradient effect with multiple frames
        top_accent = ctk.CTkFrame(header_frame, fg_color="#0f3460", height=3)
        top_accent.pack(fill="x")
        
        # Logo and title container
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.pack(expand=True, fill="both", padx=40, pady=20)
        
        # Title with shadow effect
        title_label = ctk.CTkLabel(
            title_container,
            text="DOMAINSCOUT PRO",
            font=ctk.CTkFont(size=48, weight="bold", family="Segoe UI"),
            text_color="#00d4ff"
        )
        title_label.pack(pady=(10, 0))
        
        # Subtitle with glow effect
        subtitle_label = ctk.CTkLabel(
            title_container,
            text="Gelişmiş Domain İstihbaratı & Güvenlik Analiz Platformu",
            font=ctk.CTkFont(size=18, family="Segoe UI"),
            text_color="#a8dadc"
        )
        subtitle_label.pack(pady=(5, 0))
        
        # Version and status
        info_label = ctk.CTkLabel(
            title_container,
            text="v2.0 Professional Edition | Gerçek Zamanlı Analiz | Çok Katmanlı Güvenlik Taraması",
            font=ctk.CTkFont(size=11),
            text_color="#778da9"
        )
        info_label.pack(pady=(5, 0))
        
        # Bottom accent
        bottom_accent = ctk.CTkFrame(header_frame, fg_color="#e63946", height=2)
        bottom_accent.pack(fill="x", side="bottom")
    
    def _create_input_section(self):
        """Create domain input section"""
        input_frame = ctk.CTkFrame(
            self.main_container,
            fg_color=("#0f3460", "#1a1a2e"),
            corner_radius=15
        )
        input_frame.pack(fill="x", padx=15, pady=15)
        
        # Main input area
        main_input = ctk.CTkFrame(input_frame, fg_color="transparent")
        main_input.pack(padx=30, pady=25)
        
        # Input row
        input_row = ctk.CTkFrame(main_input, fg_color="transparent")
        input_row.pack(fill="x", pady=(0, 15))
        
        # Label with icon
        label_frame = ctk.CTkFrame(input_row, fg_color="transparent")
        label_frame.pack(side="left", padx=(0, 15))
        
        label = ctk.CTkLabel(
            label_frame,
            text="HEDEF DOMAIN",
            font=ctk.CTkFont(size=13, weight="bold", family="Segoe UI"),
            text_color="#00d4ff"
        )
        label.pack()
        
        sublabel = ctk.CTkLabel(
            label_frame,
            text="Analiz edilecek domain girin",
            font=ctk.CTkFont(size=10),
            text_color="#778da9"
        )
        sublabel.pack()
        
        # Entry with enhanced styling
        self.domain_entry = ctk.CTkEntry(
            input_row,
            width=500,
            height=50,
            placeholder_text="ornek.com veya altdomain.ornek.com",
            font=ctk.CTkFont(size=16, family="Consolas"),
            border_width=2,
            border_color="#00d4ff",
            fg_color="#16213e",
            text_color="#ffffff",
            placeholder_text_color="#778da9"
        )
        self.domain_entry.pack(side="left", padx=10)
        self.domain_entry.bind('<Return>', lambda e: self._start_analysis())
        
        # Analyze button with gradient effect
        self.analyze_btn = ctk.CTkButton(
            input_row,
            text="ANALİZİ BAŞLAT",
            command=self._start_analysis,
            width=180,
            height=50,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="#e63946",
            hover_color="#d62828",
            border_width=2,
            border_color="#ff6b6b",
            corner_radius=10
        )
        self.analyze_btn.pack(side="left", padx=5)
        
        # Quick scan button
        self.quick_scan_btn = ctk.CTkButton(
            input_row,
            text="HIZLI TARAMA",
            command=self._quick_scan,
            width=140,
            height=50,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#06d6a0",
            hover_color="#05b389",
            corner_radius=10
        )
        self.quick_scan_btn.pack(side="left", padx=5)
        
        # Export section with cards
        export_section = ctk.CTkFrame(main_input, fg_color="transparent")
        export_section.pack(fill="x", pady=(10, 0))
        
        # Export label
        export_label = ctk.CTkLabel(
            export_section,
            text="DIŞA AKTARMA SEÇENEKLERİ",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#778da9"
        )
        export_label.pack(anchor="w", pady=(0, 8))
        
        # Export buttons container
        export_container = ctk.CTkFrame(export_section, fg_color="transparent")
        export_container.pack()
        
        # Export buttons with modern styling
        btn_configs = [
            ("JSON", "json", "#4361ee"),
            ("CSV", "csv", "#7209b7"),
            ("HTML", "html", "#f72585"),
            ("TÜM FORMATLAR", "all", "#06d6a0")
        ]
        
        self.export_buttons = {}
        for text, format_type, color in btn_configs:
            btn = ctk.CTkButton(
                export_container,
                text=text,
                command=lambda f=format_type: self._export_data(f),
                width=130,
                height=38,
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color=color,
                hover_color=self._darken_color(color),
                state="disabled",
                corner_radius=8
            )
            btn.pack(side="left", padx=5)
            self.export_buttons[format_type] = btn
    
    def _create_tabs(self):
        """Create tabbed interface for results"""
        # Tab container with enhanced styling
        tab_container = ctk.CTkFrame(
            self.main_container,
            fg_color=("#0f3460", "#1a1a2e")
        )
        tab_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Create tabview with custom colors
        self.tabview = ctk.CTkTabview(
            tab_container,
            fg_color=("#16213e", "#0f1923"),
            segmented_button_fg_color="#1a1a2e",
            segmented_button_selected_color="#e63946",
            segmented_button_selected_hover_color="#d62828",
            segmented_button_unselected_color="#0f3460",
            segmented_button_unselected_hover_color="#16213e",
            text_color="#a8dadc",
            text_color_disabled="#778da9"
        )
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Sekmeleri ekle
        self.tab_overview = self.tabview.add("GENEL BAKIŞ")
        self.tab_whois = self.tabview.add("WHOIS VERİ")
        self.tab_dns = self.tabview.add("DNS KAYITLARI")
        self.tab_ssl = self.tabview.add("SSL/TLS")
        self.tab_security = self.tabview.add("GÜVENLİK")
        self.tab_server = self.tabview.add("SUNUCU BİLGİ")
        self.tab_tech = self.tabview.add("TEKNOLOJİLER")
        self.tab_ports = self.tabview.add("PORT TARAMA")
        self.tab_subdomains = self.tabview.add("ALTDOMAINLER")
        self.tab_email = self.tabview.add("E-POSTA GÜV")
        self.tab_performance = self.tabview.add("PERFORMANS")
        self.tab_raw = self.tabview.add("HAM VERİ")
        
        # Create content for each tab
        self._create_tab_content(self.tab_overview, "overview")
        self._create_tab_content(self.tab_whois, "whois")
        self._create_tab_content(self.tab_dns, "dns")
        self._create_tab_content(self.tab_ssl, "ssl")
        self._create_tab_content(self.tab_security, "security")
        self._create_tab_content(self.tab_server, "server")
        self._create_tab_content(self.tab_tech, "tech")
        self._create_tab_content(self.tab_ports, "ports")
        self._create_tab_content(self.tab_subdomains, "subdomains")
        self._create_tab_content(self.tab_email, "email")
        self._create_tab_content(self.tab_performance, "performance")
        self._create_tab_content(self.tab_raw, "raw")
    
    def _create_tab_content(self, tab, tab_key: str):
        """Create content for a specific tab with enhanced styling"""
        # Scrollable frame with proper expansion - yüksekliği artırıldı
        scroll = ctk.CTkScrollableFrame(
            tab,
            fg_color=("#0d1b2a", "#0a0e27"),
            scrollbar_button_color="#e63946",
            scrollbar_button_hover_color="#d62828"
        )
        scroll.pack(fill="both", expand=True, padx=0, pady=0)  # Padding kaldırıldı
        
        # Create textbox with enhanced styling - yükseklik ve genişlik artırıldı
        textbox = ctk.CTkTextbox(
            scroll,
            wrap="none",  # Yatay scroll için
            font=ctk.CTkFont(size=13, family="Consolas", weight="normal"),  # Font boyutu artırıldı
            fg_color="#0a0e27",
            text_color="#00d4ff",  # Cyan renk - daha parlak ve okunabilir
            border_width=0,  # Border kaldırıldı daha geniş görünsün
            border_color="#1b263b",
            scrollbar_button_color="#e63946",
            scrollbar_button_hover_color="#d62828",
            height=800  # Yükseklik artırıldı
        )
        textbox.pack(fill="both", expand=True, padx=0, pady=0)  # Padding kaldırıldı
        
        # Store reference
        setattr(self, f"{tab_key}_text", textbox)
    
    def _create_status_bar(self):
        """Create status bar"""
        status_frame = ctk.CTkFrame(
            self.main_container,
            height=60,
            fg_color=("#0f3460", "#1a1a2e"),
            corner_radius=10
        )
        status_frame.pack(fill="x", padx=15, pady=(0, 15))
        status_frame.pack_propagate(False)
        
        # Progress section
        progress_section = ctk.CTkFrame(status_frame, fg_color="transparent")
        progress_section.pack(side="left", fill="both", expand=True, padx=15, pady=10)
        
        # Progress label
        progress_label = ctk.CTkLabel(
            progress_section,
            text="ANALİZ İLERLEYİŞİ",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#778da9"
        )
        progress_label.pack(anchor="w")
        
        # Progress bar with custom colors
        self.progress = ctk.CTkProgressBar(
            progress_section,
            mode="determinate",
            progress_color="#e63946",
            fg_color="#16213e",
            border_width=1,
            border_color="#1b263b"
        )
        self.progress.pack(fill="x", pady=(5, 0))
        self.progress.set(0)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Hazır",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#00d4ff"
        )
        self.status_label.pack(side="right", padx=20)
    
    def _darken_color(self, hex_color: str) -> str:
        """Darken a hex color by 20%"""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        darkened = tuple(max(0, int(c * 0.8)) for c in rgb)
        return f"#{darkened[0]:02x}{darkened[1]:02x}{darkened[2]:02x}"
    
    def _quick_scan(self):
        """Perform a quick scan with essential checks only"""
        domain = self.domain_entry.get().strip()
        
        if not domain:
            messagebox.showwarning("Giriş Gerekli", "Lütfen bir domain adı girin")
            return
        
        if self.analysis_in_progress:
            messagebox.showinfo("Analiz Devam Ediyor", "Lütfen mevcut analizin tamamlanmasını bekleyin")
            return
        
        messagebox.showinfo("Hızlı Tarama", "Hızlı tarama modu yalnızca temel kontrolleri yapar (WHOIS, DNS, SSL, Güvenlik Başlıkları)\n\nBu daha hızlı ama daha az kapsamlıdır.")
        self._start_analysis()
    
    def _start_analysis(self):
        """Domain analizini başlat"""
        domain = self.domain_entry.get().strip()
        
        if not domain:
            messagebox.showwarning("Giriş Gerekli", "Lütfen bir domain adı girin")
            return
        
        if self.analysis_in_progress:
            messagebox.showinfo("Analiz Devam Ediyor", "Lütfen mevcut analizin tamamlanmasını bekleyin")
            return
        
        # Clear previous results
        self._clear_results()
        
        # Disable controls
        self.analyze_btn.configure(state="disabled")
        self.domain_entry.configure(state="disabled")
        self.analysis_in_progress = True
        
        # İlerleme başlat
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        self.status_label.configure(text="Analiz başlatılıyor...")
        
        # Run analysis in thread
        thread = threading.Thread(target=self._run_analysis, args=(domain,), daemon=True)
        thread.start()
    
    def _run_analysis(self, domain: str):
        """Run analysis in background thread"""
        try:
            def progress_callback(task_name, current, total):
                progress_pct = (current / total) * 100
                self.root.after(0, lambda: self.status_label.configure(
                    text=f"Analiz ediliyor: {task_name} ({current}/{total})"))
                self.root.after(0, lambda p=progress_pct: self.progress.set(p / 100))
            
            # Perform analysis
            results = self.analyzer.analyze_domain(domain, progress_callback)
            
            # Update UI
            self.root.after(0, self._display_results, results)
            
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Analysis Error", str(e))
        finally:
            self.root.after(0, self._analysis_complete)
    
    def _analysis_complete(self):
        """Analiz tamamlandığında çağrılır"""
        self.progress.stop()
        self.progress.set(1)
        self.status_label.configure(text="Analiz tamamlandı")
        self.analyze_btn.configure(state="normal")
        self.domain_entry.configure(state="normal")
        self.analysis_in_progress = False
        
        # Enable export buttons
        for btn in self.export_buttons.values():
            btn.configure(state="normal")
    
    def _display_results(self, results: Dict[str, Any]):
        """Display analysis results"""
        self.current_results = results
        
        # Overview
        self._display_overview(results)
        
        # WHOIS
        self._display_whois(results.get('whois_data', {}))
        
        # DNS
        self._display_dns(results.get('dns_records', {}))
        
        # SSL
        self._display_ssl(results.get('ssl_certificate', {}))
        
        # Security
        self._display_security(results)
        
        # Server
        self._display_server(results.get('server_info', {}))
        
        # Technologies
        self._display_technologies(results.get('technologies', {}))
        
        # Ports
        self._display_ports(results.get('ports_scan', {}))
        
        # Raw
        self._display_raw(results)
    
    def _display_overview(self, results: Dict):
        """Display comprehensive overview with rich information"""
        self.overview_text.delete("1.0", "end")
        
        domain = results.get('domain', 'N/A')
        timestamp = results.get('timestamp', 'N/A')
        
        content = f"""

                    ╔═══════════════════════════════════════════════════════════════╗
                    ║         KAPSAMLI DOMAIN ANALİZ RAPORU                     ║
                    ║           PREMİUM GÜVENLİK DEĞERLENDİRMESİ               ║
                    ╚═══════════════════════════════════════════════════════════════╝

                               ┌─────────────────────────────────────────────┐
                               │         HEDEF BİLGİLERİ                   │
                               └─────────────────────────────────────────────┘

                                  Domain Adı          : {domain}
                                  Analiz Tarihi/Saati : {timestamp}
                                  Analiz Tamamlandı   : {results.get('analysis_complete', False)}
                                  Rapor Oluşturan    : DomainScout Pro v2.0


                    ╔═══════════════════════════════════════════════════════════════╗
                    ║          GÜVENLİK RİSK DEĞERLENDİRMESİ                   ║
                    ╚═══════════════════════════════════════════════════════════════╝
"""
        
        # Enhanced Risk Score Display
        risk_score = results.get('risk_score', {})
        if risk_score:
            score = risk_score.get('score', 0)
            rating = risk_score.get('rating', 'Unknown')
            issues = risk_score.get('issues', [])
            total_issues = risk_score.get('total_issues', 0)
            
            # Visual score bar with colors
            bar_length = 60
            filled = int((score / 100) * bar_length)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            # Risk seviye göstergesi
            if score >= 80:
                risk_emoji = '✓ GÜVENLİ'
                risk_color = 'YEŞİL'
            elif score >= 60:
                risk_emoji = '⚠ ORTA'
                risk_color = 'SARI'
            elif score >= 40:
                risk_emoji = '⚠ YÜKSEK RİSK'
                risk_color = 'TURUNCU'
            else:
                risk_emoji = '✗ KRİTİK'
                risk_color = 'KIRMIZI'
            
            content += f"""
┌─────────────────────────────────────────────────────────────────────────┐
│ OVERALL SECURITY SCORE                                                  │
└─────────────────────────────────────────────────────────────────────────┘

  Score      : {score}/100
  Rating     : {rating}
  Status     : {risk_emoji}
  Color Code : {risk_color}

  Visual Score:
  [{bar}] {score}%

┌─────────────────────────────────────────────────────────────────────────┐
│ SECURITY ISSUES DETECTED ({total_issues} Total)                         │
└─────────────────────────────────────────────────────────────────────────┘

"""
            if issues:
                for idx, issue in enumerate(issues, 1):
                    content += f"  [{idx}] ⚠ {issue}\n"
            else:
                content += "  ✓ No critical security issues detected\n"
        
        # Basic Information Section
        content += f"\n\n╔════════════════════════════════════════════════════════════════════════════╗\n"
        content += f"║                         DOMAIN BASIC INFORMATION                           ║\n"
        content += f"╚════════════════════════════════════════════════════════════════════════════╝\n\n"
        
        basic_info = results.get('basic_info', {})
        if basic_info:
            content += f"┌─────────────────────────────────────────────────────────────────────────┐\n"
            content += f"│ CONNECTIVITY & ACCESSIBILITY                                            │\n"
            content += f"└─────────────────────────────────────────────────────────────────────────┘\n\n"
            
            is_reachable = basic_info.get('is_reachable', False)
            has_www = basic_info.get('has_www', False)
            
            content += f"  Domain Reachable    : {'✓ YES' if is_reachable else '✗ NO'}\n"
            content += f"  WWW Version Exists  : {'✓ YES' if has_www else '✗ NO'}\n"
            content += f"  Full URL            : {basic_info.get('full_url', 'N/A')}\n"
            content += f"  Analyzed At         : {basic_info.get('analyzed_at', 'N/A')}\n"
            
            # Redirects
            redirects = basic_info.get('redirects', [])
            if redirects:
                content += f"\n  Redirect Chain ({len(redirects)} hops):\n"
                for idx, redirect in enumerate(redirects, 1):
                    content += f"    [{idx}] {redirect}\n"
        
        # WHOIS Summary
        whois_data = results.get('whois_data', {})
        if whois_data and 'error' not in whois_data:
            content += f"\n\n╔════════════════════════════════════════════════════════════════════════════╗\n"
            content += f"║                         WHOIS REGISTRATION DATA                            ║\n"
            content += f"╚════════════════════════════════════════════════════════════════════════════╝\n\n"
            
            content += f"┌─────────────────────────────────────────────────────────────────────────┐\n"
            content += f"│ REGISTRATION DETAILS                                                    │\n"
            content += f"└─────────────────────────────────────────────────────────────────────────┘\n\n"
            
            content += f"  Registrar         : {whois_data.get('registrar', 'N/A')}\n"
            content += f"  Organization      : {whois_data.get('organization', 'N/A')}\n"
            content += f"  Registrant        : {whois_data.get('registrant', 'N/A')}\n"
            content += f"  Country           : {whois_data.get('country', 'N/A')}\n"
            
            content += f"\n┌─────────────────────────────────────────────────────────────────────────┐\n"
            content += f"│ DOMAIN LIFECYCLE                                                        │\n"
            content += f"└─────────────────────────────────────────────────────────────────────────┘\n\n"
            
            creation_date = whois_data.get('creation_date', 'N/A')
            expiration_date = whois_data.get('expiration_date', 'N/A')
            updated_date = whois_data.get('updated_date', 'N/A')
            domain_age = whois_data.get('domain_age_days', 'N/A')
            
            content += f"  Created On        : {creation_date}\n"
            content += f"  Expires On        : {expiration_date}\n"
            content += f"  Last Updated      : {updated_date}\n"
            
            if isinstance(domain_age, int):
                years = domain_age // 365
                months = (domain_age % 365) // 30
                content += f"  Domain Age        : {domain_age} days ({years}y {months}m)\n"
            else:
                content += f"  Domain Age        : {domain_age}\n"
        
        # IP & Location Summary
        ip_info = results.get('ip_information', {})
        if ip_info and 'error' not in ip_info:
            content += f"\n\n╔════════════════════════════════════════════════════════════════════════════╗\n"
            content += f"║                      IP ADDRESS & GEOLOCATION                              ║\n"
            content += f"╚════════════════════════════════════════════════════════════════════════════╝\n\n"
            
            content += f"┌─────────────────────────────────────────────────────────────────────────┐\n"
            content += f"│ NETWORK INFORMATION                                                     │\n"
            content += f"└─────────────────────────────────────────────────────────────────────────┘\n\n"
            
            content += f"  IP Address        : {ip_info.get('ip_address', 'N/A')}\n"
            content += f"  IP Version        : {ip_info.get('ip_version', 'N/A')}\n"
            content += f"  ISP/Organization  : {ip_info.get('isp', 'N/A')}\n"
            content += f"  ASN               : {ip_info.get('asn', 'N/A')}\n"
            content += f"  Reverse DNS       : {ip_info.get('reverse_dns', 'N/A')}\n"
            
            content += f"\n┌─────────────────────────────────────────────────────────────────────────┐\n"
            content += f"│ GEOGRAPHIC LOCATION                                                     │\n"
            content += f"└─────────────────────────────────────────────────────────────────────────┘\n\n"
            
            content += f"  Country           : {ip_info.get('country', 'N/A')} ({ip_info.get('country_code', 'N/A')})\n"
            content += f"  Region/State      : {ip_info.get('region', 'N/A')}\n"
            content += f"  City              : {ip_info.get('city', 'N/A')}\n"
            content += f"  Postal Code       : {ip_info.get('postal', 'N/A')}\n"
            content += f"  Coordinates       : {ip_info.get('latitude', 'N/A')}, {ip_info.get('longitude', 'N/A')}\n"
            content += f"  Timezone          : {ip_info.get('timezone', 'N/A')}\n"
        
        # SSL Certificate Summary
        ssl_info = results.get('ssl_certificate', {})
        if ssl_info and ssl_info.get('has_ssl'):
            content += f"\n\n╔════════════════════════════════════════════════════════════════════════════╗\n"
            content += f"║                         SSL/TLS CERTIFICATE STATUS                        ║\n"
            content += f"╚════════════════════════════════════════════════════════════════════════════╝\n\n"
            
            days_left = ssl_info.get('days_until_expiry', 0)
            is_valid = ssl_info.get('is_valid', False)
            
            if is_valid:
                ssl_status = '✓ VALID'
            else:
                ssl_status = '✗ EXPIRED/INVALID'
            
            content += f"┌─────────────────────────────────────────────────────────────────────────┐\n"
            content += f"│ CERTIFICATE DETAILS                                                     │\n"
            content += f"└─────────────────────────────────────────────────────────────────────────┘\n\n"
            
            content += f"  Status            : {ssl_status}\n"
            content += f"  Issuer            : {ssl_info.get('issuer', 'N/A')[:70]}\n"
            content += f"  Subject           : {ssl_info.get('subject', 'N/A')[:70]}\n"
            content += f"  Valid From        : {ssl_info.get('valid_from', 'N/A')}\n"
            content += f"  Valid Until       : {ssl_info.get('valid_until', 'N/A')}\n"
            content += f"  Days Remaining    : {days_left} days\n"
            content += f"  Version           : {ssl_info.get('version', 'N/A')}\n"
            content += f"  Serial Number     : {ssl_info.get('serial_number', 'N/A')}\n"
            
            if days_left < 30:
                content += f"\n  ⚠ WARNING: Certificate expires in {days_left} days!\n"
        
        # Port Scan Summary
        ports_data = results.get('ports_scan', {})
        if ports_data and 'error' not in ports_data:
            content += f"\n\n╔════════════════════════════════════════════════════════════════════════════╗\n"
            content += f"║                         PORT SECURITY ANALYSIS                             ║\n"
            content += f"╚════════════════════════════════════════════════════════════════════════════╝\n\n"
            
            open_count = ports_data.get('open_count', 0)
            total_scanned = ports_data.get('total_scanned', 0)
            
            content += f"┌─────────────────────────────────────────────────────────────────────────┐\n"
            content += f"│ SCAN SUMMARY                                                            │\n"
            content += f"└─────────────────────────────────────────────────────────────────────────┘\n\n"
            
            content += f"  Total Ports Scanned  : {total_scanned}\n"
            content += f"  Open Ports Found     : {open_count}\n"
            
            open_ports = ports_data.get('open_ports', [])
            if open_ports:
                content += f"\n  Open Ports:\n"
                for port in open_ports[:5]:  # Show first 5
                    content += f"    • Port {port['port']} ({port['service']}) - {port['status']}\n"
                
                if len(open_ports) > 5:
                    content += f"    ... and {len(open_ports) - 5} more ports (see PORTS tab)\n"
        
        # Technologies Summary
        tech_data = results.get('technologies', {})
        if tech_data:
            content += f"\n\n╔════════════════════════════════════════════════════════════════════════════╗\n"
            content += f"║                         DETECTED TECHNOLOGIES                              ║\n"
            content += f"╚════════════════════════════════════════════════════════════════════════════╝\n\n"
            
            total_techs = sum(len(items) for items in tech_data.values() if isinstance(items, list))
            
            content += f"  Total Technologies Detected: {total_techs}\n\n"
            
            for category, items in tech_data.items():
                if isinstance(items, list) and items and category != 'error':
                    content += f"  {category.replace('_', ' ').title()} ({len(items)}): "
                    content += f"{', '.join(items[:3])}"
                    if len(items) > 3:
                        content += f" (+{len(items)-3} more)"
                    content += "\n"
        
        # Performance Summary
        perf_data = results.get('performance', {})
        if perf_data and 'error' not in perf_data:
            content += f"\n\n╔════════════════════════════════════════════════════════════════════════════╗\n"
            content += f"║                         PERFORMANCE METRICS                                ║\n"
            content += f"╚════════════════════════════════════════════════════════════════════════════╝\n\n"
            
            load_time = perf_data.get('load_time_seconds', 0)
            response_time = perf_data.get('response_time_ms', 0)
            page_size = perf_data.get('page_size_kb', 0)
            rating = perf_data.get('performance_rating', 'N/A')
            
            content += f"  Load Time         : {load_time}s\n"
            content += f"  Response Time     : {response_time}ms\n"
            content += f"  Page Size         : {page_size}KB\n"
            content += f"  Performance       : {rating}\n"
            content += f"  Compression       : {perf_data.get('compression', 'None')}\n"
        
        content += f"\n\n{'═'*80}\n"
        content += f"                    END OF OVERVIEW REPORT\n"
        content += f"           For detailed information, check individual tabs\n"
        content += f"{'═'*80}\n"
        
        self.overview_text.insert("1.0", content)
    
    def _display_whois(self, whois_data: Dict):
        """Display WHOIS data"""
        self.whois_text.delete("1.0", "end")
        
        if 'error' in whois_data:
            self.whois_text.insert("1.0", f"WHOIS data unavailable: {whois_data['error']}")
            return
        
        content = "WHOIS INFORMATION\n" + "="*60 + "\n\n"
        
        for key, value in whois_data.items():
            if isinstance(value, list):
                content += f"{key.replace('_', ' ').title()}:\n"
                for item in value:
                    content += f"  - {item}\n"
            else:
                content += f"{key.replace('_', ' ').title()}: {value}\n"
        
        self.whois_text.insert("1.0", content)
    
    def _display_dns(self, dns_data: Dict):
        """Display DNS records"""
        self.dns_text.delete("1.0", "end")
        
        content = "DNS RECORDS\n" + "="*60 + "\n\n"
        
        for record_type, values in dns_data.items():
            content += f"\n{record_type} Records:\n{'-'*40}\n"
            if isinstance(values, list):
                for value in values:
                    content += f"  {value}\n"
            else:
                content += f"  {values}\n"
        
        self.dns_text.insert("1.0", content)
    
    def _display_ssl(self, ssl_data: Dict):
        """Display SSL certificate info"""
        self.ssl_text.delete("1.0", "end")
        
        if not ssl_data.get('has_ssl'):
            self.ssl_text.insert("1.0", f"No SSL certificate found\nError: {ssl_data.get('error', 'Unknown')}")
            return
        
        content = "SSL/TLS CERTIFICATE\n" + "="*60 + "\n\n"
        
        for key, value in ssl_data.items():
            if key == 'san_names' and isinstance(value, list):
                content += f"\nSubject Alternative Names:\n"
                for san in value:
                    content += f"  - {san}\n"
            else:
                content += f"{key.replace('_', ' ').title()}: {value}\n"
        
        self.ssl_text.insert("1.0", content)
    
    def _display_security(self, results: Dict):
        """Display security analysis"""
        self.security_text.delete("1.0", "end")
        
        content = "SECURITY ANALYSIS\n" + "="*60 + "\n\n"
        
        # Security Headers
        sec_headers = results.get('security_headers', {})
        if sec_headers:
            content += f"\nSecurity Headers Score: {sec_headers.get('security_score', 0)}%\n"
            content += f"Present: {sec_headers.get('present_headers', 0)}/{sec_headers.get('total_headers', 0)}\n\n"
            
            headers_detail = sec_headers.get('headers_detail', {})
            for header, info in headers_detail.items():
                if isinstance(info, dict):
                    status = "PRESENT" if info.get('present') else "MISSING"
                    value = info.get('value', 'Not set')
                    content += f"{header}: [{status}]\n  Value: {value}\n\n"
        
        # Email Security
        email_sec = results.get('email_security', {})
        if email_sec:
            content += "\nEmail Security (SPF/DKIM/DMARC)\n" + "-"*40 + "\n"
            for protocol, data in email_sec.items():
                if isinstance(data, dict) and 'present' in data:
                    status = "CONFIGURED" if data['present'] else "NOT CONFIGURED"
                    content += f"{protocol}: [{status}]\n"
                    if data.get('records'):
                        for record in data['records']:
                            content += f"  {record}\n"
                    content += "\n"
        
        self.security_text.insert("1.0", content)
    
    def _display_server(self, server_data: Dict):
        """Display server information"""
        self.server_text.delete("1.0", "end")
        
        content = "SERVER INFORMATION\n" + "="*60 + "\n\n"
        
        for key, value in server_data.items():
            content += f"{key.replace('_', ' ').title()}: {value}\n"
        
        self.server_text.insert("1.0", content)
    
    def _display_technologies(self, tech_data: Dict):
        """Display detected technologies"""
        self.tech_text.delete("1.0", "end")
        
        content = "DETECTED TECHNOLOGIES\n" + "="*60 + "\n\n"
        
        for category, items in tech_data.items():
            if isinstance(items, list) and items and category != 'error':
                content += f"\n{category.replace('_', ' ').title()}:\n{'-'*40}\n"
                for item in items:
                    content += f"  - {item}\n"
        
        if 'error' in tech_data:
            content += f"\nError: {tech_data['error']}"
        
        self.tech_text.insert("1.0", content)
    
    def _display_ports(self, ports_data: Dict):
        """Display port scan results"""
        self.ports_text.delete("1.0", "end")
        
        content = "PORT SCAN RESULTS\n" + "="*60 + "\n\n"
        
        if 'error' in ports_data:
            content += f"Error: {ports_data['error']}"
        else:
            content += f"Total Ports Scanned: {ports_data.get('total_scanned', 0)}\n"
            content += f"Open Ports: {ports_data.get('open_count', 0)}\n\n"
            
            open_ports = ports_data.get('open_ports', [])
            if open_ports:
                content += "Open Ports:\n" + "-"*40 + "\n"
                for port in open_ports:
                    content += f"Port {port['port']}: {port['service']} [{port['status']}]\n"
        
        self.ports_text.insert("1.0", content)
    
    def _display_raw(self, results: Dict):
        """Display raw JSON data"""
        self.raw_text.delete("1.0", "end")
        
        formatted_json = json.dumps(results, indent=2, default=str)
        self.raw_text.insert("1.0", formatted_json)
    
    def _clear_results(self):
        """Clear all result displays"""
        for textbox in [self.overview_text, self.whois_text, self.dns_text, 
                       self.ssl_text, self.security_text, self.server_text,
                       self.tech_text, self.ports_text, self.raw_text]:
            textbox.delete("1.0", "end")
    
    def _export_data(self, format_type: str):
        """Export data to specified format"""
        if not self.current_results:
            messagebox.showwarning("No Data", "No analysis data to export")
            return
        
        domain = self.current_results.get('domain', 'unknown')
        
        try:
            if format_type == 'json':
                filepath = self.exporter.export_to_json(self.current_results, domain)
                messagebox.showinfo("Export Success", f"JSON exported to:\n{filepath}")
                
            elif format_type == 'csv':
                filepaths = self.exporter.export_to_csv(self.current_results, domain)
                files_list = '\n'.join(filepaths.values())
                messagebox.showinfo("Export Success", f"CSV files exported:\n{files_list}")
                
            elif format_type == 'html':
                filepath = self.exporter.export_to_html(self.current_results, domain)
                messagebox.showinfo("Export Success", f"HTML report exported to:\n{filepath}")
                
                # Ask to open
                if messagebox.askyesno("Open Report", "Would you like to open the HTML report?"):
                    webbrowser.open(filepath)
                
            elif format_type == 'all':
                results = self.exporter.export_all(self.current_results, domain)
                msg = f"All formats exported successfully!\n\n"
                msg += f"JSON: {results['json']}\n\n"
                msg += f"HTML: {results['html']}\n\n"
                msg += f"CSV Files: {len(results['csv'])} files"
                messagebox.showinfo("Export Success", msg)
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def run(self):
        """Start the application"""
        self.root.mainloop()


def main():
    """Main entry point"""
    app = DomainScoutPro()
    app.run()


if __name__ == "__main__":
    main()
