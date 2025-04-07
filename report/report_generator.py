#!/usr/bin/env python3
"""
Report Generator Module
---------------------
Generates HTML and PDF reports for the vulnerability scanning results.
"""

import os
import time
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from fpdf import FPDF
from colorama import Fore, Style

class ReportGenerator:
    def __init__(self, report_data, output_path, report_format="html"):
        """Initialize the report generator."""
        self.report_data = report_data
        self.output_path = output_path
        self.report_format = report_format.lower()
        
        # Create report templates directory if it doesn't exist
        os.makedirs("report/templates", exist_ok=True)
        
        # Create the HTML template if it doesn't exist
        self._create_html_template()
    
    def _create_html_template(self):
        """Create the HTML template for reports if it doesn't exist."""
        template_path = "report/templates/report_template.html"
        
        if not os.path.exists(template_path):
            print(f"{Fore.BLUE}[*] Creating HTML report template...{Style.RESET_ALL}")
            
            template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {{ report_data.target }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .severity-high {
            color: #e74c3c;
            font-weight: bold;
        }
        .severity-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .severity-low {
            color: #3498db;
            font-weight: bold;
        }
        .severity-info {
            color: #2ecc71;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.9em;
            color: #7f8c8d;
        }
        .details {
            padding: 10px;
            background-color: #f2f2f2;
            border-left: 5px solid #2c3e50;
            margin: 10px 0;
        }
        code {
            background-color: #f8f8f8;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        pre {
            background-color: #f8f8f8;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .summary-box {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .summary-item {
            flex: 1;
            min-width: 200px;
            margin: 10px;
            padding: 20px;
            background-color: #f2f2f2;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }
        .count {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .label {
            font-size: 1em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Scan Report</h1>
        <p>Target: {{ report_data.target }}</p>
        <p>Scan Date: {{ report_data.scan_date }}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary-box">
            <div class="summary-item">
                <div class="count">{{ report_data.subdomains.subdomains|length if report_data.subdomains else 0 }}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="summary-item">
                <div class="count">{{ report_data.open_ports.open_ports|length if report_data.open_ports else 0 }}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="summary-item">
                <div class="count">{{ report_data.directories.directories|length if report_data.directories else 0 }}</div>
                <div class="label">Directories</div>
            </div>
            <div class="summary-item">
                <div class="count">{{ (report_data.sql_vulnerabilities.vulnerable_forms|length + report_data.sql_vulnerabilities.vulnerable_links|length) if report_data.sql_vulnerabilities else 0 }}</div>
                <div class="label">SQL Injections</div>
            </div>
            <div class="summary-item">
                <div class="count">{{ (report_data.xss_vulnerabilities.vulnerable_forms|length + report_data.xss_vulnerabilities.vulnerable_links|length) if report_data.xss_vulnerabilities else 0 }}</div>
                <div class="label">XSS Vulnerabilities</div>
            </div>
        </div>
        
        <h3>Overall Risk Assessment</h3>
        <p>
            {% set total_high = ((report_data.sql_vulnerabilities.vulnerable_forms|length + report_data.sql_vulnerabilities.vulnerable_links|length) + (report_data.xss_vulnerabilities.vulnerable_forms|length + report_data.xss_vulnerabilities.vulnerable_links|length)) if (report_data.sql_vulnerabilities and report_data.xss_vulnerabilities) else 0 %}
            {% if total_high > 5 %}
                <span class="severity-high">High Risk</span>: The target has significant security vulnerabilities that should be addressed immediately.
            {% elif total_high > 0 %}
                <span class="severity-medium">Medium Risk</span>: The target has some security vulnerabilities that should be addressed.
            {% else %}
                <span class="severity-low">Low Risk</span>: The target appears to have minimal security vulnerabilities based on the scan.
            {% endif %}
        </p>
    </div>
    
    {% if report_data.subdomains %}
    <div class="section">
        <h2>Subdomain Enumeration</h2>
        <p>Found {{ report_data.subdomains.subdomains|length }} subdomains for {{ report_data.subdomains.domain }}.</p>
        
        {% if report_data.subdomains.dns_records %}
        <h3>DNS Records</h3>
        <table>
            <tr>
                <th>Record Type</th>
                <th>Value</th>
            </tr>
            {% for record in report_data.subdomains.dns_records %}
            <tr>
                <td>{{ record.record_type }}</td>
                <td>{{ record.value }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        {% if report_data.subdomains.subdomains %}
        <h3>Discovered Subdomains</h3>
        <table>
            <tr>
                <th>Subdomain</th>
                <th>IP Address</th>
            </tr>
            {% for subdomain in report_data.subdomains.subdomains %}
            <tr>
                <td>{{ subdomain.subdomain }}</td>
                <td>{{ subdomain.ip_address }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>
    {% endif %}
    
    {% if report_data.open_ports %}
    <div class="section">
        <h2>Port Scanning</h2>
        <p>Target Host: {{ report_data.open_ports.host }} ({{ report_data.open_ports.ip_address }})</p>
        <p>Found {{ report_data.open_ports.open_ports|length }} open ports.</p>
        
        {% if report_data.open_ports.open_ports %}
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Version</th>
            </tr>
            {% for port in report_data.open_ports.open_ports %}
            <tr>
                <td>{{ port.port }}</td>
                <td>{{ port.service }}</td>
                <td>{{ port.version }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>
    {% endif %}
    
    {% if report_data.directories %}
    <div class="section">
        <h2>Directory Scanning</h2>
        <p>Found {{ report_data.directories.directories|length }} directories/files on {{ report_data.directories.target }}.</p>
        
        {% if report_data.directories.directories %}
        <table>
            <tr>
                <th>URL</th>
                <th>Status Code</th>
                <th>Size (bytes)</th>
            </tr>
            {% for directory in report_data.directories.directories %}
            <tr>
                <td>{{ directory.url }}</td>
                <td>{{ directory.status_code }}</td>
                <td>{{ directory.size }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>
    {% endif %}
    
    {% if report_data.sql_vulnerabilities %}
    <div class="section">
        <h2>SQL Injection Vulnerabilities</h2>
        <p>Found {{ report_data.sql_vulnerabilities.total_vulnerabilities }} SQL Injection vulnerabilities on {{ report_data.sql_vulnerabilities.target }}.</p>
        
        {% if report_data.sql_vulnerabilities.vulnerable_forms %}
        <h3>Vulnerable Forms</h3>
        {% for vuln in report_data.sql_vulnerabilities.vulnerable_forms %}
        <div class="details">
            <p><strong>URL:</strong> {{ vuln.url }}</p>
            <p><strong>Method:</strong> {{ vuln.method }}</p>
            <p><strong>Vulnerable Inputs:</strong> {{ vuln.inputs|join(', ') }}</p>
            <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
            <p><strong>Error Pattern:</strong> {{ vuln.error_pattern }}</p>
        </div>
        {% endfor %}
        {% endif %}
        
        {% if report_data.sql_vulnerabilities.vulnerable_links %}
        <h3>Vulnerable Links</h3>
        {% for vuln in report_data.sql_vulnerabilities.vulnerable_links %}
        <div class="details">
            <p><strong>URL:</strong> {{ vuln.url }}</p>
            <p><strong>Vulnerable Parameter:</strong> {{ vuln.parameter }}</p>
            <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
            <p><strong>Error Pattern:</strong> {{ vuln.error_pattern }}</p>
        </div>
        {% endfor %}
        {% endif %}
        
        <h3>Recommendations</h3>
        <ul>
            <li>Use prepared statements and parameterized queries</li>
            <li>Apply input validation and sanitization</li>
            <li>Use ORM frameworks that handle SQL escaping</li>
            <li>Apply the principle of least privilege to database accounts</li>
            <li>Use stored procedures when possible</li>
            <li>Implement proper error handling that doesn't expose SQL details</li>
        </ul>
    </div>
    {% endif %}
    
    {% if report_data.xss_vulnerabilities %}
    <div class="section">
        <h2>Cross-Site Scripting (XSS) Vulnerabilities</h2>
        <p>Found {{ report_data.xss_vulnerabilities.total_vulnerabilities }} XSS vulnerabilities on {{ report_data.xss_vulnerabilities.target }}.</p>
        
        {% if report_data.xss_vulnerabilities.vulnerable_forms %}
        <h3>Vulnerable Forms</h3>
        {% for vuln in report_data.xss_vulnerabilities.vulnerable_forms %}
        <div class="details">
            <p><strong>URL:</strong> {{ vuln.url }}</p>
            <p><strong>Method:</strong> {{ vuln.method }}</p>
            <p><strong>Vulnerable Inputs:</strong> {{ vuln.inputs|join(', ') }}</p>
            <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
        </div>
        {% endfor %}
        {% endif %}
        
        {% if report_data.xss_vulnerabilities.vulnerable_links %}
        <h3>Vulnerable Links</h3>
        {% for vuln in report_data.xss_vulnerabilities.vulnerable_links %}
        <div class="details">
            <p><strong>URL:</strong> {{ vuln.url }}</p>
            <p><strong>Vulnerable Parameter:</strong> {{ vuln.parameter }}</p>
            <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
        </div>
        {% endfor %}
        {% endif %}
        
        <h3>Recommendations</h3>
        <ul>
            <li>Encode output data using HTML entity encoding</li>
            <li>Implement Content Security Policy (CSP) headers</li>
            <li>Validate and sanitize all user inputs</li>
            <li>Use framework-provided protection mechanisms</li>
            <li>Apply context-specific output encoding</li>
            <li>Use HTTPOnly and Secure flags for cookies</li>
            <li>Consider using X-XSS-Protection header</li>
        </ul>
    </div>
    {% endif %}
    
    <div class="section">
        <h2>General Security Recommendations</h2>
        <ul>
            <li>Keep all software and frameworks up-to-date with security patches</li>
            <li>Implement a proper Web Application Firewall (WAF)</li>
            <li>Use HTTPS for all connections</li>
            <li>Implement proper authentication and authorization</li>
            <li>Apply the principle of least privilege</li>
            <li>Perform regular security assessments and penetration testing</li>
            <li>Develop and maintain a security incident response plan</li>
            <li>Train developers on secure coding practices</li>
            <li>Use strong password policies and consider multi-factor authentication</li>
            <li>Regularly backup important data</li>
        </ul>
    </div>
    
    <div class="footer">
        <p>This report was generated using Automated Vulnerability Scanner on {{ report_data.scan_date }}</p>
    </div>
</body>
</html>"""
            
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(template_path), exist_ok=True)
            
            # Write the template file
            with open(template_path, 'w') as f:
                f.write(template_content)
            
            print(f"{Fore.GREEN}[+] HTML report template created at {template_path}{Style.RESET_ALL}")
    
    def _generate_html_report(self):
        """Generate an HTML report."""
        # Set up Jinja2 environment
        env = Environment(loader=FileSystemLoader('report/templates'))
        template = env.get_template('report_template.html')
        
        # Render the template with the report data
        html_content = template.render(report_data=self.report_data)
        
        # Define output file path
        output_file = f"{self.output_path}.html"
        
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Write the HTML report
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    def _generate_pdf_report(self):
        """Generate a PDF report from the HTML report."""
        # First generate an HTML report
        html_report_path = self._generate_html_report()
        
        # Define output PDF path
        pdf_path = f"{self.output_path}.pdf"
        
        # Create a PDF object
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(190, 10, "Vulnerability Scan Report", 0, 1, 'C')
        pdf.set_font("Arial", '', 12)
        pdf.cell(190, 10, f"Target: {self.report_data['target']}", 0, 1)
        pdf.cell(190, 10, f"Scan Date: {self.report_data['scan_date']}", 0, 1)
        
        # Add a note about HTML report
        pdf.ln(10)
        pdf.set_font("Arial", '', 10)
        pdf.multi_cell(190, 10, "This is a simplified PDF version of the report. For a more detailed report with formatting and complete information, please refer to the HTML version.", 0)
        
        # Add summary
        pdf.ln(10)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(190, 10, "Summary", 0, 1)
        pdf.set_font("Arial", '', 12)
        
        # Count vulnerabilities
        subdomains_count = len(self.report_data.get('subdomains', {}).get('subdomains', [])) if self.report_data.get('subdomains') else 0
        ports_count = len(self.report_data.get('open_ports', {}).get('open_ports', [])) if self.report_data.get('open_ports') else 0
        dirs_count = len(self.report_data.get('directories', {}).get('directories', [])) if self.report_data.get('directories') else 0
        
        sql_forms_count = len(self.report_data.get('sql_vulnerabilities', {}).get('vulnerable_forms', [])) if self.report_data.get('sql_vulnerabilities') else 0
        sql_links_count = len(self.report_data.get('sql_vulnerabilities', {}).get('vulnerable_links', [])) if self.report_data.get('sql_vulnerabilities') else 0
        
        xss_forms_count = len(self.report_data.get('xss_vulnerabilities', {}).get('vulnerable_forms', [])) if self.report_data.get('xss_vulnerabilities') else 0
        xss_links_count = len(self.report_data.get('xss_vulnerabilities', {}).get('vulnerable_links', [])) if self.report_data.get('xss_vulnerabilities') else 0
        
        pdf.cell(100, 10, f"Subdomains found: {subdomains_count}", 0, 1)
        pdf.cell(100, 10, f"Open ports found: {ports_count}", 0, 1)
        pdf.cell(100, 10, f"Directories/files found: {dirs_count}", 0, 1)
        pdf.cell(100, 10, f"SQL Injection vulnerabilities: {sql_forms_count + sql_links_count}", 0, 1)
        pdf.cell(100, 10, f"XSS vulnerabilities: {xss_forms_count + xss_links_count}", 0, 1)
        
        # Refer to HTML report for detailed info
        pdf.ln(20)
        pdf.set_font("Arial", 'I', 10)
        pdf.cell(190, 10, f"Please see the HTML report for detailed information: {html_report_path}", 0, 1)
        
        # Save the PDF
        pdf.output(pdf_path)
        
        return pdf_path
    
    def generate(self):
        """Generate the report in the specified format."""
        print(f"{Fore.YELLOW}[*] Generating {self.report_format.upper()} report...{Style.RESET_ALL}")
        
        if self.report_format == "pdf":
            output_file = self._generate_pdf_report()
        else:
            output_file = self._generate_html_report()
        
        print(f"{Fore.GREEN}[+] Report generated successfully: {output_file}{Style.RESET_ALL}")
        
        return output_file


if __name__ == "__main__":
    # For testing purposes
    test_data = {
        "target": "example.com",
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": {
            "domain": "example.com",
            "subdomains": [
                {"subdomain": "www.example.com", "ip_address": "93.184.216.34"},
                {"subdomain": "mail.example.com", "ip_address": "93.184.216.34"}
            ],
            "dns_records": [
                {"record_type": "A", "value": "93.184.216.34"},
                {"record_type": "MX", "value": "10 mail.example.com"}
            ]
        },
        "open_ports": {
            "host": "example.com",
            "ip_address": "93.184.216.34",
            "open_ports": [
                {"port": 80, "service": "http", "version": "nginx 1.17.6"},
                {"port": 443, "service": "https", "version": "nginx 1.17.6"}
            ]
        },
        "directories": {
            "target": "http://example.com",
            "directories": [
                {"path": "robots.txt", "url": "http://example.com/robots.txt", "status_code": 200, "size": 45},
                {"path": "admin", "url": "http://example.com/admin", "status_code": 302, "size": 0}
            ]
        },
        "sql_vulnerabilities": {
            "target": "http://example.com",
            "vulnerable_forms": [
                {
                    "url": "http://example.com/login",
                    "method": "post",
                    "inputs": ["username", "password"],
                    "payload": "' OR '1'='1",
                    "error_pattern": "MySQL Query fail"
                }
            ],
            "vulnerable_links": [],
            "total_vulnerabilities": 1
        },
        "xss_vulnerabilities": {
            "target": "http://example.com",
            "vulnerable_forms": [],
            "vulnerable_links": [
                {
                    "url": "http://example.com/search?q=test",
                    "parameter": "q",
                    "payload": "<script>alert(1)</script>"
                }
            ],
            "total_vulnerabilities": 1
        }
    }
    
    # Test HTML report
    html_generator = ReportGenerator(test_data, "reports/test_report", "html")
    html_report = html_generator.generate()
    
    # Test PDF report
    pdf_generator = ReportGenerator(test_data, "reports/test_report", "pdf")
    pdf_report = pdf_generator.generate()