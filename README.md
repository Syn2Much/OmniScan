# Cobra Scan 🐍

*a powerful, modular reconnaissance tool designed for security professionals, ethical hackers, and system administrators.* 
##
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Syn2Much/CobraScan/graphs/commit-activity)

---



## ✨ Features

### Core Features

- **🔌 Modular Architecture**: Plugin-based system for easy extension
- **🎯 Target Management**: Single or batch target scanning
- **🌐 Proxy Support**: HTTP/HTTPS proxy rotation from file lists
- **💾 Persistent Configuration**: Save preferences between sessions
- **📈 JSON Export**: Structured data for automation and reporting
- **📈 Detailed Reporting**: Generated HTML writeups, PDF's, and optionally manage reports over a Flask Web Pannel

### Vulnerability Scanner Module (v1.0.0) - NEW 🔓

- **📋 OWASP Top 10**: Complete coverage of OWASP Top 10  categories
- **🔍 CVE Detection**: Known vulnerable software signatures (Apache, PHP, jQuery, WordPress, etc.)
- **💉 Injection Testing**: XSS (reflected), SQL injection, command injection, path traversal
- **🔒 SSL/TLS Analysis**: TLS version, cipher strength, certificate expiry checks
- **🛡️ Security Headers**: CSP, HSTS, X-Frame-Options, CORS misconfiguration
- **📂 Sensitive Files**: .git, .env, config backups, database dumps, logs
- **🔄 Open Redirect**: URL redirect vulnerability detection
- **📊 Risk Scoring**: Severity-based findings with OWASP categorization
- **📦 Batch Scanning**: Scan multiple targets with comprehensive reports
- 
### Web Analyzer Module (v2.0.0)

- **🌐 Quick Scan**: Basic HTTP information (status, server, encoding)
- **🔍 DNS Reconnaissance**: A, AAAA, MX, TXT, NS record analysis
- **📍 IP Geolocation**: IP address location, ISP, reverse DNS
- **🔒 SSL/TLS Analysis**: Certificate validation, expiry warnings, cipher detection, SANs
- **🛡️ Security Headers**: CSP, HSTS, X-Frame-Options, Referrer-Policy analysis with recommendations
- **🔴 HTTP Methods Scan**: Detects dangerous methods (TRACE, PUT, DELETE)
- **📄 Content Analysis**: Email extraction, meta tags, phone numbers, sensitive path detection
- **⚡ Performance Metrics**: Response time, compression, caching, speed ratings
- **🔌 Port Scanning**: 21 common ports including PostgreSQL, Redis, Elasticsearch
- **🛠️ Technology Detection**: CMS, JS frameworks, CSS, backend language, analytics tools
- **📋 Full Reconnaissance**: Complete all-in-one scan with structured output
- **📦 Batch Processing**: Scan multiple targets from file with timestamped results

### Sensitive Path Finder Module (v1.0.0) - NEW

- **🔐 Admin/Login Paths**: Discover admin panels, login pages, phpMyAdmin, database managers
- **📝 CMS Detection**: WordPress, Joomla, Drupal, Magento, Laravel path scanning
- **🔌 API Endpoints**: REST, GraphQL, Swagger, OpenAPI, health checks, hidden endpoints
- **📁 Sensitive Files**: Config files, backups, .git, .env, logs, credentials
- **⚡ Multi-threaded**: Fast concurrent scanning with 10 threads
- **📋 Custom Wordlists**: Support for external wordlist files
- **📦 Batch Scanning**: Scan multiple targets with selected path categories

### Subdomain Enumeration Module (v1.0.0)

- **🔍 DNS Bruteforce**: Quick (150+) and Deep (250+) subdomain wordlists
- **📜 Certificate Transparency**: Query crt.sh for SSL certificate subdomains
- **🔓 Zone Transfer (AXFR)**: Test for misconfigured DNS servers
- **🔄 Reverse DNS**: Scan /24 network range for related hosts
- **🎯 Full Enumeration**: Combine all methods for comprehensive discovery
- **📋 Custom Wordlists**: Support for external subdomain wordlists
- **📦 Batch Scanning**: Enumerate subdomains across multiple domains


---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/Syn2Much/CobraScan.git
cd CobraScan

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

---

## 🚀 Quick Start

1. **Start CobraScan**:

   ```bash
   python main.py
   ```

2. **Load Targets**:
   - Press `T` from main menu
   - Choose single target or load from file

3. **Load Proxies** (Optional):
   - Press `P` from main menu
   - Load proxy list from file (one per line)
   - Proxies auto-rotate across all HTTP requests

4. **Run Scans**:
   - Select a module (e.g., `1` for Web Analyzer)
   - Choose scan type
   - View results or export to JSON

5. **Configure Settings**:
   - Press `C` from main menu
   - Adjust timeout, output file, etc.

---

## 🛠️ Usage Guide

### Main Menu

```
┌─────────────────────────────────────────────┐
│ Available Modules:                          │
│ 1. Web Analyzer (v2.0.0)                    │
│ 2. Sensitive Path Finder (v1.0.0)           │
│ 3. Subdomain Enumeration (v1.0.0)           │
│ 4. Vulnerability Scanner (v1.0.0)           │
│                                             │
│ T. Load Target (URL/IP or File)             │
│ P. Load Proxies (HTTP/HTTPS from File)      │
│ R. Results (View / Clear / Reports)         │
│ C. Configuration & Settings                 │
│ H. Help & Information                       │
│ Q. Exit                                     │
└─────────────────────────────────────────────┘
```

### Example of Vulnerability Scanner Menu

```
┌─────────────────────────────────────────────┐
│  1. Full Vulnerability Scan (All checks)    │
│  2. Quick Scan (Headers + Versions + Files) │
│  3. OWASP Top 10 Assessment                 │
│  4. Injection Testing (XSS, SQLi, LFI)      │
│  5. SSL/TLS & Headers Check                 │
│  6. Batch Scan (All Targets)                │
│  B. Back to Main Menu                       │
└─────────────────────────────────────────────┘
```

### Target Management

**Single Target:**

```
T -> 1 -> Enter URL/IP
```

**Batch from File:**
Create `targets.txt`:

```txt
https://example.com
https://test-site.com
192.168.1.1
```

Then:

```
T -> 2 -> targets.txt
```

### Proxy Configuration

**Load Proxies from File:**
Create `proxies.txt`:

```txt
192.168.1.100:8080
http://10.0.0.1:3128
https://proxy.example.com:8443
user:password@proxy.corp.com:8080
```

Then:

```
P -> 1 -> proxies.txt
```

**Supported Formats:**

- `ip:port` - Basic format (assumes HTTP)
- `http://ip:port` - Explicit HTTP proxy
- `https://ip:port` - HTTPS proxy
- `user:pass@ip:port` - Authenticated proxy

**Proxy Management:**

- View loaded proxies: `P -> 2`
- Clear all proxies: `P -> 3`
- Proxies rotate randomly across all HTTP requests in all modules

### Configuration

Access via `C` from main menu:

- Timeout settings
- Output file naming
- Auto-save preferences
- Verbose mode toggle


---


### Sample JSON Output (Full Recon)

```json
  {
    "scan_info": {
      "url": "https://httpbin.org/",
      "requested_url": "https://httpbin.org/",
      "hostname": "httpbin.org",
      "scan_timestamp": "2026-01-22T17:43:46.855101"
    },
    "http_info": {
      "status_code": 200,
      "reason": "OK",
      "is_ok": true,
      "encoding": "utf-8",
      "apparent_encoding": "Windows-1252"
    },
    "headers": {
      "Date": "Thu, 22 Jan 2026 17:43:46 GMT",
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": "9593",
      "Connection": "keep-alive",
      "Server": "gunicorn/19.9.0",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true"
    },
    "cookies": {},
    "redirects": [],
    "performance": {
      "response_time_ms": 403.8,
      "content_size_bytes": 9593,
      "content_size_kb": 9.37,
      "headers_count": 7,
      "gzip_enabled": false,
      "cache_control": "Not set",
      "compression": "None",
      "performance_rating": "EXCELLENT"
    },
    "content_analysis": {
      "emails": [
        "me@kennethreitz.org"
      ],
      "phone_numbers": [],
      "meta_tags": {},
      "page_title": "httpbin.org",
      "sensitive_paths": [],
      "word_count": 641
    },
    "dns_info": {
      "a_records": [
        "54.147.217.198",
        "18.207.71.162",
        "98.88.114.252",
        "54.80.48.62",
        "98.88.224.123",
        "52.20.30.6"
      ],
      "aaaa_records": "No AAAA records found",
      "mx_records": "No MX records found",
      "txt_records": [
        "\"v=spf1 -all\""
      ],
      "ns_records": [
        "ns-1053.awsdns-03.org.",
        "ns-1555.awsdns-02.co.uk.",
        "ns-173.awsdns-21.com.",
        "ns-884.awsdns-46.net."
      ]
    },
    "ip_info": {
      "ip_address": "98.88.114.252",
      "reverse_dns": "ec2-98-88-114-252.compute-1.amazonaws.com",
      "geolocation": {
        "country": "United States",
        "region": "Virginia",
        "city": "Ashburn",
        "isp": "Amazon.com",
        "org": "AWS EC2 (us-east-1)"
      }
    },
    "ssl_info": {
      "certificate": {
        "issuer": {
          "countryName": "US",
          "organizationName": "Amazon",
          "commonName": "Amazon RSA 2048 M03"
        },
        "subject": {
          "commonName": "httpbin.org"
        },
        "version": 3,
        "serialNumber": "0E2558D492728E9C01A8DADEDC05D13D",
        "notBefore": "Jul 20 00:00:00 2025 GMT",
        "notAfter": "Aug 17 23:59:59 2026 GMT"
      },
      "subject_alternative_names": [
        "httpbin.org",
        "*.httpbin.org"
      ],
      "days_until_expiry": 207,
      "expiry_date": "2026-08-17T23:59:59",
      "cert_valid": true,
      "cert_status": "VALID",
      "tls_version": "TLSv1.2",
      "cipher": "ECDHE-RSA-AES128-GCM-SHA256"
    },
    "http_methods": {
      "allowed_methods": [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "PATCH"
      ],
      "vulnerable_methods": [
        {
          "method": "PUT",
          "risk": "HIGH",
          "description": "PUT method is enabled - potential security risk"
        },
        {
          "method": "DELETE",
          "risk": "HIGH",
          "description": "DELETE method is enabled - potential security risk"
        },
        {
          "method": "TRACE",
          "risk": "HIGH",
          "description": "TRACE method is enabled - potential security risk"
        }
      ],
      "method_count": 8
    },
    "security_headers": {
      "Content-Security-Policy": {
        "present": false,
        "value": null,
        "description": "Prevents XSS attacks by controlling resource loading"
      },
      "Strict-Transport-Security": {
        "present": false,
        "value": null,
        "description": "Enforces HTTPS connections"
      },
      "X-Frame-Options": {
        "present": false,
        "value": null,
        "description": "Prevents clickjacking attacks"
      },
      "X-Content-Type-Options": {
        "present": false,
        "value": null,
        "description": "Prevents MIME type sniffing"
      },
      "X-XSS-Protection": {
        "present": false,
        "value": null,
        "description": "Legacy XSS protection header"
      },
      "Referrer-Policy": {
        "present": false,
        "value": null,
        "description": "Controls referrer information"
      },
      "Permissions-Policy": {
        "present": false,
        "value": null,
        "description": "Controls browser features and APIs"
      },
      "X-Permitted-Cross-Domain-Policies": {
        "present": false,
        "value": null,
        "description": "Controls cross-domain policies"
      },
      "vulnerabilities": [
        "Missing Content-Security-Policy",
        "Missing Strict-Transport-Security",
        "Missing X-Frame-Options",
        "Missing X-Content-Type-Options",
        "Missing X-XSS-Protection",
        "Missing Referrer-Policy",
        "Missing Permissions-Policy",
        "Missing X-Permitted-Cross-Domain-Policies"
      ]
    },
    "open_ports": [
      {
        "port": 80,
        "service": "HTTP",
        "status": "open"
      },
      {
        "port": 443,
        "service": "HTTPS",
        "status": "open"
      }
    ],
    "technologies": {
      "javascript_libraries": [
        "jquery",
        "react"
      ]
    }
  }
```

## 🔌 Module Development

### Creating a New Module

1. **Copy the Template**:

   ```bash
   cp dev/module_template.py modules/your_module.py
   ```

2. **Customize Your Module**:

   ```python
   # modules/your_module.py
   class YourModuleName:
       def __init__(self):
           self.name = "Your Module Name"
           self.version = "1.0.0"

       def run(self, config, target_manager, proxy_manager=None):
           """Main entry point for your module."""
           # Use proxy_manager.get_random_proxy() for HTTP requests
           # Your module logic here
           pass
   ```

3. **Register the Module** in `main.py`:

   ```python
   # Add to _load_modules() method
   from modules.your_module import YourModuleName
   self.modules['your_module'] = YourModuleName()
   ```

### Module Template Features

- Pre-built menu system
- Configuration management
- Target handling
- Proxy rotation support
- Error handling
- JSON export utilities

### Best Practices

1. Follow the template structure
2. Include comprehensive docstrings
3. Add error handling for network issues
4. Test with various target types
5. Document your module in README

---

---

## 🛣️ Roadmap

### Current Modules

- ✅ **Web Analyzer** - Comprehensive web target analysis (v2.0.0)
- ✅ **Sensitive Path Finder** - Admin panels, CMS paths, API endpoints, sensitive files (v1.0.0)
- ✅ **Subdomain Enumeration** - DNS bruteforce, certificate transparency, zone transfer (v1.0.0)
- ✅ **Vulnerability Scanner** - CVE detection, OWASP Top 10, injection testing (v1.0.0)
- ✅ **Report Generator** - Professional HTML 
### Planned Modules

- 🔌 **API Security Tester** - REST/GraphQL endpoint testing and validation
- 🗺️ **Network Mapper** - Network topology visualization and CIDR scanning
- 🔍 **OSINT Collector** - Open-source intelligence gathering and correlation

### Core Enhancements

- ⚡ Multi-threading support
- ✅ **Proxy Integration** - HTTP/HTTPS proxy rotation from file lists
- 📋 Tor integration
- 📊 API integrations (Shodan, VirusTotal)
- 🛡️ WAF detection and evasion
- 📈 Advanced reporting and visualization

---

## 📝 Changelog

### Version 1.6.0 (Current)
- **Vulnerability Scanner v1.0.0**: New comprehensive security assessment module
- **Results Manager**: Enhanced results handling
### Version 1.5.0
- **Proxy Support**: HTTP/HTTPS proxy integration across all modules
### Version 1.4.0

- **Sensitive Path Finder v1.0.0**: New module for path discovery
- **Subdomain Enumeration v1.0.0**: New module for subdomain discovery

### Version 1.3.0
- **Web Analyzer v2.0.0**: Major expansion with 12 scan types

### Version 1.2.5

- Modular Architecture: Complete refactor to plugin system
- Dynamic Module Loading: Automatic menu generation
- Module Template: Easy module creation
- Improved Structure: Better code organization
- Bug Fixes: Banner spacing and error handling

### Version 1.2.0

- Rebranded to CobraScan
- Target Manager: Single and batch scanning
- Configuration System: Persistent settings
- Enhanced UI: Improved user interface

### Version 1.0.0

- Initial Release
- Basic Scanning: Core functionality
- JSON Export: Structured output

[View full changelog](CHANGELOG.md)

---

## 📁 Project Structure

```
CobraScan/
│
├── main.py                 # Main application entry point
├── README.md               # Documentation
├── CLAUDE.md               # AI assistant guidance
├── requirements.txt        # Python dependencies
│
├── helpers/                # Helper modules
│   ├── __init__.py
│   ├── target_manager.py   # Target loading and management
│   ├── proxy_manager.py    # HTTP/HTTPS proxy rotation
│   ├── http_client.py      # Proxy-aware HTTP client
│   ├── report_builder.py   # HTML report generation
│   ├── report_server.py    # Flask report hosting
│   └── utils.py            # Utility functions
│
├── reports/                # Generated HTML reports
│   ├── style.css           # Report stylesheet
│   └── *.html              # Target reports
│
├── modules/                # Scan modules (auto-loaded)
│   ├── __init__.py
│   ├── web_analyzer.py     # Web analysis module (v2.0.0)
│   ├── path_finder.py      # Sensitive path discovery (v1.0.0)
│   ├── sub_domain.py       # Subdomain enumeration (v1.0.0)
│   └── vuln_scanner.py     # Vulnerability scanner (v1.0.0)
│
├── guides/                 # Development resources
│   ├── module_creation_guide.md
│   └── module_template.py  # New module template
│
├── targets.txt             # Target list (user-created)
├── cobra_config.json       # Configuration (auto-generated)
└── cobra_scan_results.json # Scan results (auto-generated)
```

---

## ⚖️ Legal Disclaimer

**CobraScan is for authorized security testing only.**

### ❌ Prohibited Use

- Scanning systems without explicit permission
- Malicious or disruptive activities
- Violating laws or terms of service
- Unauthorized access attempts

**Users are responsible for compliance with all applicable laws.**

---

## 📞 Support

### Documentation

- [Module Creation Guide](dev/module_creation_guide.md)

### Contact

- **Email**: <dev@sinners.city>
- **GitHub**: [@Syn2Much](https://github.com/Syn2Much)
- **Website**: [sinners.city](https://sinners.city)

---

<div align="center">
s
## 🐍 CobraScan - The All-Seeing Reconnaissance Tool

*In the realm of security, visibility is power. CobraScan grants you omniscience.*

**⭐ If you find this useful, please give it a star! ⭐**

[Report Bug](https://github.com/Syn2Much/CobraScan/issues) ·
[Request Feature](https://github.com/Syn2Much/CobraScan/issues) ·
[View Source](https://github.com/Syn2Much/CobraScan)

---

**Made with 🐍 by [Syn2Much](https://github.com/Syn2Much)**

</div>
