# DomainScout Pro

Premium Domain Intelligence & Security Analysis Platform

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## Genel Bakış

**DomainScout Pro**, web sitelerinin ve domainlerin kapsamlı güvenlik analizi için geliştirilmiş profesyonel bir siber güvenlik aracıdır. Modern bir GUI arayüzü ile birlikte 100+ port taraması, detaylı DNS analizi, WHOIS sorguları, SSL/TLS sertifika kontrolü ve güvenlik açığı tespiti gibi özellikler sunar.

### Etik Kullanım Uyarısı

Bu araç yalnızca eğitim amaçlı ve meşru güvenlik testleri için geliştirilmiştir. Kullanıcılar, bu aracı yalnızca yetkili oldukları sistemler üzerinde kullanmalıdır. İzinsiz sistemlere karşı kullanımı yasa dışıdır ve ciddi yasal sonuçlar doğurabilir.

**Lütfen dikkat:**
- Sadece sahip olduğunuz veya test etme izniniz olan domainler üzerinde kullanın
- Eğitim ve güvenlik araştırmaları için tasarlanmıştır
- Kötüye kullanım durumunda sorumluluk tamamen kullanıcıya aittir
- Penetrasyon testleri öncesinde mutlaka yazılı izin alın

## Ekran Görüntüleri

Premium mavi-siyah tema ile modern ve profesyonel arayüz:

- 1600x1000 çözünürlükte geniş çalışma alanı
- 12 farklı analiz sekmesi
- Gerçek zamanlı ilerleme takibi
- Çoklu format dışa aktarma

## Özellikler

### Gelişmiş Port Taraması
- **100+ popüler port** taraması
- Servis banner tespiti
- Risk seviyesi değerlendirmesi (HIGH/MEDIUM/LOW)
- Detaylı güvenlik açığı analizi
- Kategorilere ayrılmış port listesi:
  - Web servisleri (HTTP, HTTPS, alternatifleri)
  - Veritabanları (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch)
  - Mail servisleri (SMTP, POP3, IMAP, güvenli versiyonları)
  - Uzak erişim (RDP, VNC, SSH)
  - Container & Orchestration (Docker, Kubernetes)
  - Ve daha fazlası...

### Kapsamlı DNS Analizi
- A, AAAA, MX, NS, TXT kayıtları
- CNAME, SOA, PTR, SRV kayıtları
- Nameserver bilgileri
- Mail server konfigürasyonu
- DNS zonları

### WHOIS Bilgileri
- Registrar bilgileri
- Domain yaşı hesaplama
- Oluşturma ve bitiş tarihleri
- Kayıt sahibi bilgileri
- Name server listesi
- Domain durumu (status codes)

### SSL/TLS Sertifika Analizi
- Sertifika geçerliliği kontrolü
- İssuer (yayıncı) bilgileri
- Subject Alternative Names (SAN)
- Sertifika bitiş tarihi
- Versiyon ve serial number
- Sertifika zinciri analizi

### Güvenlik Başlıkları Analizi
- HSTS (HTTP Strict Transport Security)
- CSP (Content Security Policy)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Güvenlik skoru hesaplama

### Email Güvenliği
- SPF (Sender Policy Framework) kayıtları
- DKIM (DomainKeys Identified Mail) tespiti
- DMARC (Domain-based Message Authentication) kontrolü
- Email kimlik doğrulama durumu

### Teknoloji Tespiti
- CMS sistemleri (WordPress, Joomla, Drupal, Magento, Shopify, Wix)
- Web sunucuları (Nginx, Apache, IIS)
- CDN servisleri (Cloudflare, Akamai)
- Analytics araçları (Google Analytics, Tag Manager, Facebook Pixel)
- JavaScript framework'leri (React, Vue.js, Angular, jQuery)
- Programlama dilleri

### IP & Geolocation
- IP adresi çözümleme
- Coğrafi konum tespiti (Ülke, Şehir, Bölge)
- ISP ve organizasyon bilgileri
- ASN (Autonomous System Number)
- Reverse DNS lookup
- Koordinat bilgileri
- Timezone

### Performans Metrikleri
- Sayfa yükleme süresi
- Response time ölçümü
- Sayfa boyutu analizi
- Compression tespiti
- Cache control başlıkları
- Performans değerlendirmesi

### Subdomain Keşfi
- Yaygın subdomain taraması
- DNS çözümleme doğrulaması
- Alt domain sayısı istatistiği

### Risk Değerlendirmesi
- Kapsamlı güvenlik skoru (0-100)
- Risk seviyesi sınıflandırması
- Tespit edilen sorunlar listesi
- Güvenlik önerileri

## Kurulum

### Sistem Gereksinimleri

- Python 3.8 veya üzeri
- Windows 10/11, Linux veya macOS
- Minimum 4GB RAM
- 100MB boş disk alanı
- İnternet bağlantısı

### Otomatik Kurulum (Önerilen)

#### Windows:
```bash
# 1. Repository'yi klonlayın
git clone https://github.com/Muhammedcengizz598/DomainScout.git
cd DomainScout

# 2. Otomatik kurulumu çalıştırın
INSTALL.bat
# veya
python domainscout_pro.py
```

#### Linux/macOS:
```bash
# 1. Repository'yi klonlayın
git clone https://github.com/Muhammedcengizz598/DomainScout.git
cd DomainScout

# 2. Otomatik kurulumu çalıştırın
python auto_setup.py
```

### Manuel Kurulum

```bash
# 1. Repository'yi klonlayın
git clone https://github.com/Muhammedcengizz598/DomainScout.git
cd DomainScout

# 2. Sanal ortam oluşturun (opsiyonel ama önerilir)
python -m venv venv

# Windows'ta aktifleştirin:
venv\Scripts\activate

# Linux/macOS'ta aktifleştirin:
source venv/bin/activate

# 3. Bağımlılıkları yükleyin
pip install -r requirements.txt
```

## Kullanım

### Uygulamayı Başlatma

#### Windows:
```bash
START_DOMAINSCOUT.bat
# veya
python domainscout_pro.py
```

#### Linux/macOS:
```bash
python domainscout_pro.py
```

### Temel Kullanım

1. **Domain Girişi**: Ana ekrandaki giriş alanına analiz etmek istediğiniz domain'i girin (örn: `example.com`)
2. **Analiz Başlatma**: "ANALİZİ BAŞLAT" butonuna tıklayın
3. **İlerleme Takibi**: Alt kısımdaki ilerleme çubuğundan analiz durumunu takip edin
4. **Sonuçları İnceleme**: 12 farklı sekmeden detaylı sonuçları inceleyin
5. **Dışa Aktarma**: İstediğiniz formatta (JSON, CSV, HTML) rapor alın

### Sekmeler

- **GENEL BAKIŞ**: Özet bilgiler ve risk değerlendirmesi
- **WHOIS VERİ**: Domain kayıt bilgileri
- **DNS KAYITLARI**: Tüm DNS kayıt tipleri
- **SSL/TLS**: Sertifika detayları
- **GÜVENLİK**: Güvenlik başlıkları ve email güvenliği
- **SUNUCU BİLGİ**: Web sunucu bilgileri
- **TEKNOLOJİLER**: Tespit edilen teknolojiler
- **PORT TARAMA**: 100+ port tarama sonuçları
- **ALTDOMAINLER**: Subdomain keşfi
- **E-POSTA GÜV**: SPF, DKIM, DMARC kontrolleri
- **PERFORMANS**: Yükleme süreleri ve metrikler
- **HAM VERİ**: JSON formatında tüm veri

### Hızlı Tarama

"HIZLI TARAMA" butonu ile sadece temel kontrolleri (WHOIS, DNS, SSL, Güvenlik Başlıkları) gerçekleştirerek daha hızlı sonuç alabilirsiniz.

## Dışa Aktarma Formatları

### JSON Export
Tüm analiz verileri yapılandırılmış JSON formatında:
```json
{
  "domain": "example.com",
  "timestamp": "2025-01-14T12:00:00",
  "analysis_complete": true,
  "whois_data": {...},
  "dns_records": {...}
}
```

### CSV Export
Her kategori için ayrı CSV dosyaları:
- `domain_basic_info.csv`
- `domain_whois.csv`
- `domain_dns_records.csv`
- `domain_security_headers.csv`
- `domain_open_ports.csv`

### HTML Report
Profesyonel, yazdırılabilir HTML raporu:
- Responsive tasarım
- Tablolar ve grafikler
- Renk kodlu risk göstergeleri
- Tarayıcıda doğrudan açılır

## Proje Yapısı

```
DomainScout/
├── domainscout_pro.py      # Ana GUI uygulaması
├── domain_engine.py         # Analiz motoru (100+ port tarama)
├── data_exporter.py         # Dışa aktarma sistemi
├── visualizations.py        # Grafik ve görselleştirme
├── logger.py                # Loglama sistemi
├── auto_setup.py            # Otomatik kurulum scripti
├── config.json              # Konfigürasyon dosyası
├── requirements.txt         # Python bağımlılıkları
├── INSTALL.bat              # Windows kurulum
├── START_DOMAINSCOUT.bat    # Windows başlatıcı
├── data/                    # Dışa aktarma klasörü
│   ├── json_exports/
│   ├── csv_exports/
│   ├── html_reports/
│   └── visualizations/
└── logs/                    # Log dosyaları
```

## Bağımlılıklar

```
customtkinter>=5.0.0    # Modern GUI framework
requests>=2.28.0         # HTTP istekleri
dnspython>=2.2.0        # DNS sorguları
python-whois>=0.7.3     # WHOIS sorguları
beautifulsoup4>=4.11.0  # HTML parsing
lxml>=4.9.0             # XML/HTML işleme
pyOpenSSL>=22.0.0       # SSL sertifika analizi
cryptography>=38.0.0    # Kriptografik işlemler
validators>=0.20.0      # Domain validasyonu
matplotlib>=3.6.0       # Grafik oluşturma
pandas>=1.5.0           # Veri analizi
tabulate>=0.9.0         # Tablo formatlama
```

## Güvenlik ve Gizlilik

- Tüm işlemler lokal olarak gerçekleştirilir
- Hiçbir veri toplanmaz veya üçüncü taraflara gönderilmez
- Analiz sonuçları yalnızca yerel bilgisayarınızda saklanır
- Açık kaynak kodlu - kaynak kodu incelenebilir
- Telemetri yok, analitik yok

## Yasal Uyarı

**DomainScout Pro** eğitim ve meşru güvenlik araştırmaları için geliştirilmiştir. Bu aracı kullanarak:

- Yalnızca sahip olduğunuz veya test etme yetkisi aldığınız sistemlerde kullanın
- Yerel ve uluslararası yasalara uygun hareket edin
- İzinsiz tarama ve sızma testleri yasa dışıdır
- Kötüye kullanımdan kaynaklanan sorumluluk tamamen kullanıcıya aittir

**Geliştiriciler için not:** Bu araç, güvenlik uzmanlarının ve penetrasyon test uzmanlarının işlerini kolaylaştırmak için tasarlanmıştır. Profesyonel kullanım için tasarlanmıştır.

## Performans İpuçları

- İlk kurulumdan sonra `cache/` klasörünü temizlemeyin
- Büyük taramalar için yeterli RAM'e sahip olduğunuzdan emin olun
- Firewall ayarlarınız port taramasını engelleyebilir
- VPN kullanıyorsanız DNS çözümlemesi yavaşlayabilir

## Sorun Giderme

### Port Taraması Çalışmıyor
- Firewall ayarlarınızı kontrol edin
- Antivirüs yazılımınızı geçici olarak devre dışı bırakın
- Yönetici yetkisiyle çalıştırmayı deneyin

### WHOIS Verisi Alınamıyor
- İnternet bağlantınızı kontrol edin
- Bazı domainler WHOIS gizleme kullanıyor olabilir
- Rate limiting nedeniyle geçici olarak engellenmiş olabilirsiniz

### GUI Açılmıyor
```bash
pip install customtkinter --upgrade
```

### Kurulum Hataları
```bash
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

## Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'inizi push edin (`git push origin feature/AmazingFeature`)
5. Pull Request açın

## Yol Haritası

- [ ] Batch domain analizi
- [ ] Zamanlanmış taramalar
- [ ] Geçmiş takip sistemi
- [ ] Domain karşılaştırma
- [ ] API entegrasyonu
- [ ] PDF rapor desteği
- [ ] Dark web kontrolleri
- [ ] Subdomain brute force
- [ ] CVE veritabanı entegrasyonu
- [ ] Makine öğrenmesi tabanlı risk analizi

## Lisans

MIT License - Detaylar için `LICENSE` dosyasına bakın.

## İletişim

**Geliştirici**: Muhammed Cengiz  
**GitHub**: [@Muhammedcengizz598](https://github.com/Muhammedcengizz598)

## Teşekkürler

Bu proje aşağıdaki açık kaynak projeleri kullanmaktadır:
- CustomTkinter - Modern GUI framework
- dnspython - DNS toolkit
- python-whois - WHOIS client
- pyOpenSSL - SSL/TLS toolkit
- Ve diğer tüm bağımlılıklar

## Versiyon Geçmişi

### v2.0 (Mevcut)
- 100+ port taraması eklendi
- Premium mavi-siyah tema
- Gelişmiş güvenlik analizi
- Banner grabbing özelliği
- Risk değerlendirmesi sistemi
- 12 analiz sekmesi
- Türkçe dil desteği
- Geliştirilmiş performans

### v1.0
- İlk sürüm
- Temel domain analizi
- WHOIS ve DNS sorguları
- SSL sertifika kontrolü
- Basit GUI

---

**Not**: Bu araç sürekli geliştirilmektedir. Önerileriniz ve hata bildirimleriniz için GitHub Issues kullanabilirsiniz.

**Unutmayın**: Güç, sorumlulukla birlikte gelir. Bu aracı etik ve yasal çerçevede kullanın.
