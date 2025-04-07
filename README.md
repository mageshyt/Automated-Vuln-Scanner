# Automated Vulnerability Scanner

A comprehensive web application vulnerability scanner written in Python that helps identify security weaknesses in websites.

![Automated Vulnerability Scanner](https://img.shields.io/badge/Security-Scanner-red)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 📑 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Modules](#modules)
- [Reporting](#reporting)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

The Automated Vulnerability Scanner is a powerful tool designed to identify and report security vulnerabilities in web applications. It performs comprehensive scans including subdomain enumeration, port scanning, directory discovery, SQL injection detection, and Cross-Site Scripting (XSS) vulnerability detection. The scanner generates detailed HTML and PDF reports of its findings, making it easier for security professionals to identify and fix security issues.

## ✨ Features

- **Subdomain Enumeration**: Discover subdomains of a target domain
- **Port Scanning**: Identify open ports and services running on the target
- **Directory Scanning**: Find hidden directories and files on web servers
- **SQL Injection Testing**: Detect SQL injection vulnerabilities in forms and URL parameters
- **Cross-Site Scripting (XSS) Detection**: Identify XSS vulnerabilities in forms and URL parameters
- **Detailed Reporting**: Generate comprehensive HTML and PDF reports
- **Customizable Wordlists**: Use built-in or custom wordlists for various scan types
- **Multi-threading Support**: Faster scanning with configurable thread count

## 📋 Requirements

- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mageshyt/automated-vuln-scanner.git
   cd automated-vuln-scanner
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

### Basic Usage

```bash
python main.py example.com
```

### Advanced Usage

```bash
# Run all scan types
python main.py example.com --all

# Run specific scan types
python main.py example.com --subdomains --ports --dirs

# Specify output report format and location
python main.py example.com --all --output reports/my_report --format html

# Use custom wordlist for directory scanning
python main.py example.com --dirs --wordlist /path/to/wordlist.txt

# Set number of threads for scanning
python main.py example.com --dirs --threads 20
```

### Command Line Arguments

- `url`: Target URL to scan (required)
- `-s`, `--subdomains`: Scan for subdomains
- `-p`, `--ports`: Scan for open ports
- `-d`, `--dirs`: Scan for directories
- `-sq`, `--sqli`: Scan for SQL injection vulnerabilities
- `-x`, `--xss`: Scan for XSS vulnerabilities
- `-a`, `--all`: Run all scans
- `-o`, `--output`: Output report file path
- `-f`, `--format`: Report format (html or pdf)
- `-w`, `--wordlist`: Custom wordlist for directory scanning
- `-t`, `--threads`: Number of threads (default: 10)

## 📁 Project Structure

```
.
├── main.py                 # Main script to run the scanner
├── requirements.txt        # Dependencies
├── report/                 # Report generation modules
│   ├── report_generator.py # HTML and PDF report generator
│   └── templates/          # Report templates
├── reports/                # Output reports directory
├── results/                # Scan results directory
├── scanner/                # Scanner modules
│   ├── dir_scanner.py      # Directory scanner
│   ├── port_scanner.py     # Port scanner
│   ├── sql_injection_scanner.py  # SQL injection scanner
│   ├── subdomain_scanner.py     # Subdomain scanner
│   └── xss_scanner.py      # XSS vulnerability scanner
└── wordlists/              # Wordlists for various scans
    ├── directories.txt     # Common directories
    ├── sql_payloads.txt    # SQL injection payloads
    ├── subdomains.txt      # Common subdomains
    └── xss_payloads.txt    # XSS payloads
```

## 📚 Modules

### Scanner Modules

1. **Subdomain Scanner** (`scanner/subdomain_scanner.py`)
   - Discovers subdomains of a target domain
   - Extracts DNS records (A, AAAA, MX, NS, TXT, SOA)

2. **Port Scanner** (`scanner/port_scanner.py`)
   - Scans for open ports on the target
   - Identifies services and versions running on open ports
   - Uses python-nmap for detailed port information

3. **Directory Scanner** (`scanner/dir_scanner.py`)
   - Discovers hidden directories and files on the web server
   - Supports multi-threading for faster scanning
   - Customizable wordlists

4. **SQL Injection Scanner** (`scanner/sql_injection_scanner.py`)
   - Detects SQL injection vulnerabilities in forms and URL parameters
   - Tests with various SQL injection payloads
   - Identifies vulnerable input fields

5. **XSS Scanner** (`scanner/xss_scanner.py`)
   - Detects Cross-Site Scripting vulnerabilities
   - Tests with various XSS payloads
   - Identifies reflected XSS issues

### Reporting Modules

1. **Report Generator** (`report/report_generator.py`)
   - Generates HTML and PDF reports
   - Uses Jinja2 templates for HTML generation
   - Uses FPDF for PDF generation

## 📊 Reporting

The scanner generates detailed reports in HTML and PDF formats. Reports include:

- Executive summary with risk assessment
- Subdomain enumeration results
- Open ports and services
- Directory/file discovery results
- SQL injection vulnerabilities
- XSS vulnerabilities
- Security recommendations

## 🤝 Contributing

Contributions are welcome! Here's how you can contribute to this project:

1. **Fork the repository**

2. **Create a new branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

3. **Make your changes**:
   - Add new scanner modules
   - Improve existing scanners
   - Enhance report templates
   - Fix bugs or improve performance

4. **Run tests** to ensure your changes don't break existing functionality

5. **Commit your changes**:
   ```bash
   git commit -am 'Add some feature'
   ```

6. **Push to the branch**:
   ```bash
   git push origin feature/my-new-feature
   ```

7. **Create a Pull Request**

### Contribution Ideas

- Add new vulnerability scanners (CSRF, SSRF, LFI, etc.)
- Improve scanning accuracy and reduce false positives
- Enhance reporting with more detailed remediation steps
- Add API support for integration with other tools
- Improve threading and performance
- Add support for authenticated scanning

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for security professionals to test their own systems or systems they have permission to test. Do not use this tool against systems without explicit permission. The authors are not responsible for any misuse or damage caused by this tool.