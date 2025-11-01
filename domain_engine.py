"""
DomainScout Pro - Core Domain Analysis Engine
Comprehensive domain intelligence gathering
"""
import socket
import ssl
import requests
import dns.resolver
import whois
import json
import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional
import validators
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import threading
import time


class DomainAnalyzer:
    """Advanced domain analysis and intelligence gathering"""
    
    def __init__(self):
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 10
        
    def analyze_domain(self, domain: str, progress_callback=None) -> Dict[str, Any]:
        """
        Complete domain analysis
        Returns comprehensive domain intelligence
        """
        self.results = {
            'domain': domain,
            'timestamp': datetime.datetime.now().isoformat(),
            'analysis_complete': False
        }
        
        # Clean domain
        domain = self._clean_domain(domain)
        
        if not self._validate_domain(domain):
            self.results['error'] = 'Invalid domain format'
            return self.results
        
        # Execute all analysis modules
        analysis_tasks = [
            ('Basic Info', self._get_basic_info, domain),
            ('WHOIS Data', self._get_whois_info, domain),
            ('DNS Records', self._get_dns_records, domain),
            ('IP Information', self._get_ip_info, domain),
            ('SSL Certificate', self._get_ssl_info, domain),
            ('HTTP Headers', self._get_http_headers, domain),
            ('Security Headers', self._analyze_security_headers, domain),
            ('Server Info', self._get_server_info, domain),
            ('Technologies', self._detect_technologies, domain),
            ('Ports Scan', self._scan_common_ports, domain),
            ('Subdomains', self._find_subdomains, domain),
            ('Email Security', self._check_email_security, domain),
            ('Performance', self._check_performance, domain),
        ]
        
        total_tasks = len(analysis_tasks)
        
        for idx, (name, func, param) in enumerate(analysis_tasks, 1):
            try:
                if progress_callback:
                    progress_callback(name, idx, total_tasks)
                self.results[name.lower().replace(' ', '_')] = func(param)
            except Exception as e:
                self.results[name.lower().replace(' ', '_')] = {
                    'error': str(e),
                    'status': 'failed'
                }
            time.sleep(0.1)
        
        self.results['analysis_complete'] = True
        self.results['risk_score'] = self._calculate_risk_score()
        
        return self.results
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain"""
        domain = domain.strip().lower()
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        domain = domain.split('/')[0]
        domain = domain.split(':')[0]
        return domain
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format"""
        return validators.domain(domain) == True
    
    def _get_basic_info(self, domain: str) -> Dict:
        """Get basic domain information"""
        return {
            'domain': domain,
            'full_url': f'https://{domain}',
            'analyzed_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_reachable': self._check_reachability(domain),
            'has_www': self._check_www_version(domain),
            'redirects': self._check_redirects(domain)
        }
    
    def _check_reachability(self, domain: str) -> bool:
        """Check if domain is reachable"""
        try:
            requests.get(f'https://{domain}', timeout=5)
            return True
        except:
            try:
                requests.get(f'http://{domain}', timeout=5)
                return True
            except:
                return False
    
    def _check_www_version(self, domain: str) -> bool:
        """Check if www version exists"""
        try:
            requests.get(f'https://www.{domain}', timeout=5)
            return True
        except:
            return False
    
    def _check_redirects(self, domain: str) -> List[str]:
        """Check redirect chain"""
        redirects = []
        try:
            response = requests.get(f'https://{domain}', timeout=5, allow_redirects=True)
            if response.history:
                for resp in response.history:
                    redirects.append(resp.url)
                redirects.append(response.url)
        except:
            pass
        return redirects
    
    def _get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            
            # Parse dates
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            updated_date = w.updated_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(updated_date, list):
                updated_date = updated_date[0]
            
            return {
                'registrar': w.registrar,
                'creation_date': str(creation_date) if creation_date else None,
                'expiration_date': str(expiration_date) if expiration_date else None,
                'updated_date': str(updated_date) if updated_date else None,
                'status': w.status if isinstance(w.status, list) else [w.status],
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers],
                'registrant': w.name,
                'registrant_email': w.emails if isinstance(w.emails, list) else [w.emails],
                'organization': w.org,
                'country': w.country,
                'domain_age_days': self._calculate_domain_age(creation_date)
            }
        except Exception as e:
            return {'error': str(e), 'status': 'unavailable'}
    
    def _calculate_domain_age(self, creation_date) -> Optional[int]:
        """Calculate domain age in days"""
        if not creation_date:
            return None
        try:
            if isinstance(creation_date, str):
                creation_date = datetime.datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
            delta = datetime.datetime.now() - creation_date.replace(tzinfo=None)
            return delta.days
        except:
            return None
    
    def _get_dns_records(self, domain: str) -> Dict:
        """Get comprehensive DNS records"""
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                dns_records[record_type] = []
            except dns.resolver.NXDOMAIN:
                dns_records[record_type] = ['Domain does not exist']
            except Exception as e:
                dns_records[record_type] = [f'Error: {str(e)}']
        
        return dns_records
    
    def _get_ip_info(self, domain: str) -> Dict:
        """Get IP address and geolocation information"""
        try:
            ip_address = socket.gethostbyname(domain)
            
            # Get IP info from ipapi
            ip_data = {}
            try:
                response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
                if response.status_code == 200:
                    ip_data = response.json()
            except:
                pass
            
            return {
                'ip_address': ip_address,
                'ip_version': 'IPv4' if '.' in ip_address else 'IPv6',
                'city': ip_data.get('city', 'Unknown'),
                'region': ip_data.get('region', 'Unknown'),
                'country': ip_data.get('country_name', 'Unknown'),
                'country_code': ip_data.get('country_code', 'Unknown'),
                'postal': ip_data.get('postal', 'Unknown'),
                'latitude': ip_data.get('latitude', 'Unknown'),
                'longitude': ip_data.get('longitude', 'Unknown'),
                'timezone': ip_data.get('timezone', 'Unknown'),
                'isp': ip_data.get('org', 'Unknown'),
                'asn': ip_data.get('asn', 'Unknown'),
                'reverse_dns': self._get_reverse_dns(ip_address)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return 'Not available'
    
    def _get_ssl_info(self, domain: str) -> Dict:
        """Get SSL/TLS certificate information"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    # Parse certificate
                    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                    
                    # Extract info
                    issuer = cert.issuer.rfc4514_string()
                    subject = cert.subject.rfc4514_string()
                    not_before = cert.not_valid_before
                    not_after = cert.not_valid_after
                    
                    days_until_expiry = (not_after - datetime.datetime.now()).days
                    
                    # Get SANs
                    san_extension = None
                    try:
                        san_extension = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        )
                        san_names = [name.value for name in san_extension.value]
                    except:
                        san_names = []
                    
                    return {
                        'has_ssl': True,
                        'issuer': issuer,
                        'subject': subject,
                        'valid_from': str(not_before),
                        'valid_until': str(not_after),
                        'days_until_expiry': days_until_expiry,
                        'is_valid': days_until_expiry > 0,
                        'san_names': san_names,
                        'version': cert.version.name,
                        'serial_number': str(cert.serial_number),
                        'signature_algorithm': cert.signature_algorithm_oid._name
                    }
        except Exception as e:
            return {'has_ssl': False, 'error': str(e)}
    
    def _get_http_headers(self, domain: str) -> Dict:
        """Get HTTP response headers"""
        headers_info = {}
        
        for protocol in ['https', 'http']:
            try:
                response = requests.get(f'{protocol}://{domain}', timeout=5, allow_redirects=True)
                headers_info[protocol] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds()
                }
                break
            except:
                headers_info[protocol] = {'error': 'Connection failed'}
        
        return headers_info
    
    def _analyze_security_headers(self, domain: str) -> Dict:
        """Analyze security headers"""
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Content-Type-Options': 'X-Content-Type',
            'X-Frame-Options': 'X-Frame',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer Policy',
            'Permissions-Policy': 'Permissions',
        }
        
        analysis = {
            'security_score': 0,
            'total_headers': len(security_headers),
            'present_headers': 0,
            'missing_headers': [],
            'headers_detail': {}
        }
        
        try:
            response = requests.get(f'https://{domain}', timeout=5)
            headers = response.headers
            
            for header, name in security_headers.items():
                if header in headers:
                    analysis['present_headers'] += 1
                    analysis['headers_detail'][name] = {
                        'present': True,
                        'value': headers[header]
                    }
                else:
                    analysis['missing_headers'].append(name)
                    analysis['headers_detail'][name] = {'present': False}
            
            analysis['security_score'] = round(
                (analysis['present_headers'] / analysis['total_headers']) * 100, 2
            )
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _get_server_info(self, domain: str) -> Dict:
        """Get web server information"""
        try:
            response = requests.get(f'https://{domain}', timeout=5)
            
            return {
                'server': response.headers.get('Server', 'Not disclosed'),
                'powered_by': response.headers.get('X-Powered-By', 'Not disclosed'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'content_length': response.headers.get('Content-Length', 'Unknown'),
                'last_modified': response.headers.get('Last-Modified', 'Unknown'),
                'etag': response.headers.get('ETag', 'Not set'),
                'encoding': response.encoding,
                'cookies': len(response.cookies),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_technologies(self, domain: str) -> Dict:
        """Detect technologies used"""
        technologies = {
            'cms': [],
            'analytics': [],
            'cdn': [],
            'javascript_frameworks': [],
            'web_servers': [],
            'programming_languages': []
        }
        
        try:
            response = requests.get(f'https://{domain}', timeout=5)
            html_content = response.text.lower()
            headers = response.headers
            
            # CMS Detection
            cms_patterns = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Joomla': ['joomla', 'com_content'],
                'Drupal': ['drupal', 'sites/default'],
                'Magento': ['magento', 'mage/cookies'],
                'Shopify': ['shopify', 'cdn.shopify'],
                'Wix': ['wix.com', 'wixstatic'],
            }
            
            for cms, patterns in cms_patterns.items():
                if any(pattern in html_content for pattern in patterns):
                    technologies['cms'].append(cms)
            
            # Analytics
            analytics_patterns = {
                'Google Analytics': 'google-analytics.com',
                'Google Tag Manager': 'googletagmanager.com',
                'Facebook Pixel': 'facebook.net/en_us/fbevents.js',
                'Hotjar': 'hotjar.com',
            }
            
            for analytics, pattern in analytics_patterns.items():
                if pattern in html_content:
                    technologies['analytics'].append(analytics)
            
            # JavaScript Frameworks
            js_frameworks = {
                'React': 'react',
                'Vue.js': 'vue',
                'Angular': 'angular',
                'jQuery': 'jquery',
            }
            
            for framework, pattern in js_frameworks.items():
                if pattern in html_content:
                    technologies['javascript_frameworks'].append(framework)
            
            # Server detection
            server = headers.get('Server', '').lower()
            if 'nginx' in server:
                technologies['web_servers'].append('Nginx')
            if 'apache' in server:
                technologies['web_servers'].append('Apache')
            if 'cloudflare' in server or 'cf-ray' in str(headers).lower():
                technologies['cdn'].append('Cloudflare')
            
            # Programming language hints
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                technologies['programming_languages'].append('PHP')
            if 'asp.net' in powered_by:
                technologies['programming_languages'].append('ASP.NET')
            
        except Exception as e:
            technologies['error'] = str(e)
        
        return technologies
    
    def _scan_common_ports(self, domain: str) -> Dict:
        """Kapsamlı port taraması - 100+ popüler port"""
        # Popüler portlar ve servisleri
        common_ports = {
            # Web Servisleri
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            8000: 'HTTP-Alt-2',
            8888: 'HTTP-Proxy',
            3000: 'Node.js/React Dev',
            5000: 'Flask Dev',
            9090: 'HTTP-Admin',
            # FTP
            20: 'FTP-Data',
            21: 'FTP-Control',
            990: 'FTPS',
            # SSH & Telnet
            22: 'SSH',
            23: 'Telnet',
            2222: 'SSH-Alt',
            # Mail Servisleri
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            465: 'SMTPS',
            587: 'SMTP-Submission',
            993: 'IMAPS',
            995: 'POP3S',
            # DNS
            53: 'DNS',
            # Veritabanları
            1433: 'MS-SQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3307: 'MySQL-Alt',
            5432: 'PostgreSQL',
            5433: 'PostgreSQL-Alt',
            27017: 'MongoDB',
            27018: 'MongoDB-Alt',
            6379: 'Redis',
            9200: 'Elasticsearch',
            9300: 'Elasticsearch-Alt',
            # Uzak Erişim
            3389: 'RDP',
            5900: 'VNC',
            5901: 'VNC-Alt',
            # Dosya Paylaşımı
            445: 'SMB',
            139: 'NetBIOS',
            137: 'NetBIOS-NS',
            138: 'NetBIOS-DGM',
            # Proxy & VPN
            1080: 'SOCKS',
            3128: 'Squid-Proxy',
            8081: 'Proxy-Alt',
            # Application Servers
            8009: 'Tomcat-AJP',
            8180: 'Tomcat-Alt',
            9000: 'PHP-FPM',
            # Container & Orchestration
            2375: 'Docker',
            2376: 'Docker-TLS',
            6443: 'Kubernetes-API',
            10250: 'Kubelet',
            # Message Queues
            5672: 'RabbitMQ',
            15672: 'RabbitMQ-Management',
            9092: 'Kafka',
            # Monitoring & Management
            9100: 'Node-Exporter',
            9090: 'Prometheus',
            3000: 'Grafana',
            5601: 'Kibana',
            # Gaming
            25565: 'Minecraft',
            27015: 'Steam/Source',
            # Diğer Popüler Servisler
            161: 'SNMP',
            162: 'SNMP-Trap',
            389: 'LDAP',
            636: 'LDAPS',
            1194: 'OpenVPN',
            3690: 'SVN',
            5000: 'UPnP',
            5001: 'Synology-DSM',
            8291: 'MikroTik',
            10000: 'Webmin',
            # Ekstra Kritik Portlar
            111: 'RPC',
            135: 'MS-RPC',
            512: 'rexec',
            513: 'rlogin',
            514: 'Syslog',
            873: 'rsync',
            1723: 'PPTP-VPN',
            2049: 'NFS',
            2082: 'cPanel',
            2083: 'cPanel-SSL',
            2086: 'WHM',
            2087: 'WHM-SSL',
            4444: 'Metasploit',
            5000: 'Docker-Registry',
            5555: 'Android-ADB',
            6000: 'X11',
            6667: 'IRC',
            7001: 'WebLogic',
            8443: 'Plesk',
            9418: 'Git',
            11211: 'Memcached',
        }
        
        open_ports = []
        closed_ports = []
        
        try:
            ip = socket.gethostbyname(domain)
            
            for port, service in sorted(common_ports.items()):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)  # Hızlı tarama
                    result = sock.connect_ex((ip, port))
                    
                    port_info = {
                        'port': port,
                        'service': service,
                        'protocol': 'TCP'
                    }
                    
                    if result == 0:
                        # Port açık - banner alınmaya çalış
                        banner = self._grab_banner(ip, port)
                        port_info['status'] = 'OPEN'
                        port_info['banner'] = banner if banner else 'No banner'
                        port_info['risk'] = self._assess_port_risk(port, service)
                        open_ports.append(port_info)
                    else:
                        port_info['status'] = 'CLOSED'
                        closed_ports.append(port_info)
                    
                    sock.close()
                except Exception as e:
                    pass  # Hata durumunda sessizce devam et
                    
        except Exception as e:
            return {'error': f'IP resolution failed: {str(e)}'}
        
        # Risk analizi
        high_risk_ports = [p for p in open_ports if p.get('risk') == 'HIGH']
        medium_risk_ports = [p for p in open_ports if p.get('risk') == 'MEDIUM']
        
        return {
            'ip_scanned': ip,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'total_scanned': len(common_ports),
            'open_count': len(open_ports),
            'high_risk_count': len(high_risk_ports),
            'medium_risk_count': len(medium_risk_ports),
            'security_risk': self._calculate_port_risk(open_ports),
            'vulnerabilities': self._identify_port_vulnerabilities(open_ports)
        }
    
    def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Servis banner bilgisi almaya çalış"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # HTTP portları için HTTP isteği gönder
            if port in [80, 8080, 8000, 8888, 9090]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else None
        except:
            return None
    
    def _assess_port_risk(self, port: int, service: str) -> str:
        """Port güvenlik riski değerlendirmesi"""
        # Yüksek riskli portlar
        high_risk = [21, 23, 445, 3389, 5900, 1433, 3306, 5432, 27017, 6379, 
                     11211, 2375, 4444, 5555, 512, 513, 514]
        # Orta riskli portlar  
        medium_risk = [22, 25, 110, 143, 1521, 9200, 2049, 873, 161, 389,
                       8080, 8443, 9000, 9090, 5672, 8009]
        
        if port in high_risk:
            return 'HIGH'
        elif port in medium_risk:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_port_risk(self, open_ports: List[Dict]) -> str:
        """Genel port güvenlik riski hesapla"""
        if not open_ports:
            return 'LOW'
        
        high_count = sum(1 for p in open_ports if p.get('risk') == 'HIGH')
        medium_count = sum(1 for p in open_ports if p.get('risk') == 'MEDIUM')
        
        if high_count > 0:
            return 'CRITICAL'
        elif medium_count > 3:
            return 'HIGH'
        elif medium_count > 0 or len(open_ports) > 10:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _identify_port_vulnerabilities(self, open_ports: List[Dict]) -> List[str]:
        """Açık portlardaki potansiyel güvenlik açıklarını belirle"""
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # Kritik açıklık kontrolleri
            if port == 21:
                vulnerabilities.append(f'[HIGH] FTP ({port}) - Şifreli olmayan dosya transferi, SFTP/FTPS kullanın')
            elif port == 23:
                vulnerabilities.append(f'[CRITICAL] Telnet ({port}) - Şifreli olmayan uzak erişim, SSH kullanın')
            elif port == 3389:
                vulnerabilities.append(f'[HIGH] RDP ({port}) - Uzak masaüstü açık, BlueKeep gibi açıklara karşı savunmasız')
            elif port == 445:
                vulnerabilities.append(f'[CRITICAL] SMB ({port}) - Dosya paylaşımı açık, WannaCry/EternalBlue riski')
            elif port == 5900:
                vulnerabilities.append(f'[HIGH] VNC ({port}) - Şifreli olmayan uzak masaüstü')
            elif port in [3306, 5432, 1433, 27017]:
                vulnerabilities.append(f'[HIGH] {service} ({port}) - Veritabanı internetten erişilebilir durumda')
            elif port == 6379:
                vulnerabilities.append(f'[CRITICAL] Redis ({port}) - Genellikle kimlik doğrulamasız, RCE riski')
            elif port == 11211:
                vulnerabilities.append(f'[HIGH] Memcached ({port}) - DDoS amplifikasyon saldırıları için kullanılabilir')
            elif port == 2375:
                vulnerabilities.append(f'[CRITICAL] Docker ({port}) - Kimlik doğrulamasız Docker API erişimi')
            elif port == 9200:
                vulnerabilities.append(f'[MEDIUM] Elasticsearch ({port}) - Yetkisiz veri erişimi riski')
            elif port in [8080, 8000, 8888]:
                vulnerabilities.append(f'[MEDIUM] {service} ({port}) - Alternatif web portu, yönetim paneli olabilir')
            elif port == 161:
                vulnerabilities.append(f'[MEDIUM] SNMP ({port}) - Sistem bilgisi sızdırma riski')
            elif port == 22:
                vulnerabilities.append(f'[INFO] SSH ({port}) - Güvenli ama brute-force saldırılarına karşı korunmalı')
        
        return vulnerabilities
    
    def _find_subdomains(self, domain: str) -> List[str]:
        """Find common subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'admin', 'blog', 'shop', 'api', 'dev', 'staging', 'test',
            'mobile', 'cdn', 'static', 'images', 'img', 'docs'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            full_domain = f'{subdomain}.{domain}'
            try:
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
            except:
                pass
        
        return {
            'found_subdomains': found_subdomains,
            'count': len(found_subdomains),
            'checked': len(common_subdomains)
        }
    
    def _check_email_security(self, domain: str) -> Dict:
        """Check email security (SPF, DKIM, DMARC)"""
        email_security = {}
        
        try:
            resolver = dns.resolver.Resolver()
            
            # SPF
            try:
                spf_records = resolver.resolve(domain, 'TXT')
                spf = [str(r) for r in spf_records if 'spf' in str(r).lower()]
                email_security['SPF'] = {
                    'present': len(spf) > 0,
                    'records': spf
                }
            except:
                email_security['SPF'] = {'present': False}
            
            # DMARC
            try:
                dmarc_records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dmarc = [str(r) for r in dmarc_records]
                email_security['DMARC'] = {
                    'present': len(dmarc) > 0,
                    'records': dmarc
                }
            except:
                email_security['DMARC'] = {'present': False}
            
            # DKIM (common selectors)
            dkim_selectors = ['default', 'google', 'k1', 'selector1', 'selector2']
            dkim_found = []
            
            for selector in dkim_selectors:
                try:
                    dkim_domain = f'{selector}._domainkey.{domain}'
                    dkim_records = resolver.resolve(dkim_domain, 'TXT')
                    dkim_found.extend([str(r) for r in dkim_records])
                except:
                    pass
            
            email_security['DKIM'] = {
                'present': len(dkim_found) > 0,
                'records': dkim_found
            }
            
        except Exception as e:
            email_security['error'] = str(e)
        
        return email_security
    
    def _check_performance(self, domain: str) -> Dict:
        """Check website performance metrics"""
        performance = {}
        
        try:
            start_time = time.time()
            response = requests.get(f'https://{domain}', timeout=10)
            load_time = time.time() - start_time
            
            performance = {
                'load_time_seconds': round(load_time, 3),
                'response_time_ms': round(response.elapsed.total_seconds() * 1000, 2),
                'page_size_bytes': len(response.content),
                'page_size_kb': round(len(response.content) / 1024, 2),
                'compression': response.headers.get('Content-Encoding', 'None'),
                'cache_control': response.headers.get('Cache-Control', 'Not set'),
                'performance_rating': self._rate_performance(load_time)
            }
        except Exception as e:
            performance['error'] = str(e)
        
        return performance
    
    def _rate_performance(self, load_time: float) -> str:
        """Rate website performance"""
        if load_time < 1:
            return 'Excellent'
        elif load_time < 2:
            return 'Good'
        elif load_time < 4:
            return 'Average'
        else:
            return 'Poor'
    
    def _calculate_risk_score(self) -> Dict:
        """Calculate overall security risk score"""
        score = 100
        issues = []
        
        # SSL check
        ssl_info = self.results.get('ssl_certificate', {})
        if not ssl_info.get('has_ssl'):
            score -= 30
            issues.append('No SSL certificate')
        elif ssl_info.get('days_until_expiry', 999) < 30:
            score -= 10
            issues.append('SSL certificate expiring soon')
        
        # Security headers
        sec_headers = self.results.get('security_headers', {})
        if sec_headers.get('security_score', 0) < 50:
            score -= 20
            issues.append('Missing security headers')
        
        # Email security
        email_sec = self.results.get('email_security', {})
        if not email_sec.get('SPF', {}).get('present'):
            score -= 10
            issues.append('No SPF record')
        if not email_sec.get('DMARC', {}).get('present'):
            score -= 10
            issues.append('No DMARC record')
        
        # Domain age
        whois_info = self.results.get('whois_data', {})
        domain_age = whois_info.get('domain_age_days', 0)
        if domain_age and domain_age < 30:
            score -= 15
            issues.append('Very new domain')
        
        score = max(0, min(100, score))
        
        if score >= 80:
            rating = 'Low Risk'
        elif score >= 60:
            rating = 'Medium Risk'
        elif score >= 40:
            rating = 'High Risk'
        else:
            rating = 'Critical Risk'
        
        return {
            'score': score,
            'rating': rating,
            'issues': issues,
            'total_issues': len(issues)
        }
