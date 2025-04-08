#!/usr/bin/env python3
"""
Automated Vulnerability Scanner for Websites
-------------------------------------------
A tool to scan websites for common vulnerabilities and generate detailed reports.
"""

import argparse
import sys
import os
from datetime import datetime
from colorama import init, Fore, Style

# Import scanner modules
from scanner.subdomain_scanner import SubdomainScanner
from scanner.port_scanner import PortScanner
from scanner.dir_scanner import DirectoryScanner
from scanner.sql_injection_scanner import SQLInjectionScanner
from scanner.xss_scanner import XSSScanner

# Import report generator
from report.report_generator import ReportGenerator

# Initialize colorama
init()

def banner():
    """Display the tool banner."""
    print(f"""{Fore.CYAN}
    ╔═══════════════════════════════════════════════════╗
    ║ {Fore.RED}█▀▀█ █░░█ ▀▀█▀▀ █▀▀█ ▀█░█▀ █░░█ █░░ █▀▀▄{Fore.CYAN} ║
    ║ {Fore.RED}█▄▄█ █░░█ ░░█░░ █░░█ ░█▄█░ █░░█ █░░ █░░█{Fore.CYAN} ║
    ║ {Fore.RED}▀░░▀ ░▀▀▀ ░░▀░░ ▀▀▀▀ ░░▀░░ ░▀▀▀ ▀▀▀ ▀░░▀{Fore.CYAN} ║
    ║ {Fore.GREEN}Automated Vulnerability Scanner{Fore.CYAN}              ║
    ║ {Fore.YELLOW}Version 1.0{Fore.CYAN}                                 ║
    ╚═══════════════════════════════════════════════════╝
    {Style.RESET_ALL}""")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Automated Website Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan (e.g., example.com)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Scan for subdomains")
    parser.add_argument("-p", "--ports", action="store_true", help="Scan for open ports")
    parser.add_argument("-d", "--dirs", action="store_true", help="Scan for directories")
    parser.add_argument("-sq", "--sqli", action="store_true", help="Scan for SQL injection vulnerabilities")
    parser.add_argument("-x", "--xss", action="store_true", help="Scan for XSS vulnerabilities")
    parser.add_argument("-a", "--all", action="store_true", help="Run all scans")
    parser.add_argument("-o", "--output", help="Output report file path")
    parser.add_argument("-f", "--format", choices=["html", "pdf"], default="html", help="Report format (html or pdf)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for directory scanning")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-b", "--browser", action="store_true", help="Use browser for form detection (for SQL/XSS scanning)")
    parser.add_argument("--browser-type", choices=["safari", "brave", "firefox"], default="safari", 
                        help="Browser to use for automation (safari, brave, or firefox)")
    
    return parser.parse_args()

def validate_url(url):
    """Validate and format the target URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def main():
    """Main function to run the vulnerability scanner."""
    banner()
    args = parse_arguments()
    
    # Validate URL
    target_url = validate_url(args.url)
    print(f"{Fore.GREEN}[+] Target: {Fore.WHITE}{target_url}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Scan started at: {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    
    # Create results directory if it doesn't exist
    os.makedirs("results", exist_ok=True)
    
    # Initialize report data
    report_data = {
        "target": target_url,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": [],
        "open_ports": [],
        "directories": [],
        "sql_vulnerabilities": [],
        "xss_vulnerabilities": []
    }
    
    # Run selected scans
    if args.all or args.subdomains:
        print(f"\n{Fore.YELLOW}[*] Starting Subdomain Scan...{Style.RESET_ALL}")
        subdomain_scanner = SubdomainScanner(target_url)
        report_data["subdomains"] = subdomain_scanner.scan()
    
    if args.all or args.ports:
        print(f"\n{Fore.YELLOW}[*] Starting Port Scan...{Style.RESET_ALL}")
        port_scanner = PortScanner(target_url)
        report_data["open_ports"] = port_scanner.scan()
    
    if args.all or args.dirs:
        print(f"\n{Fore.YELLOW}[*] Starting Directory Scan...{Style.RESET_ALL}")
        wordlist = args.wordlist if args.wordlist else "wordlists/directories.txt"
        dir_scanner = DirectoryScanner(target_url, wordlist, args.threads)
        report_data["directories"] = dir_scanner.scan()
    
    if args.all or args.sqli:
        print(f"\n{Fore.YELLOW}[*] Starting SQL Injection Scan...{Style.RESET_ALL}")
        if args.browser:
            print(f"{Fore.BLUE}[*] Using {args.browser_type.capitalize()} browser for form detection{Style.RESET_ALL}")
        sqli_scanner = SQLInjectionScanner(target_url, use_browser=args.browser, browser_name=args.browser_type)
        report_data["sql_vulnerabilities"] = sqli_scanner.scan()
    
    if args.all or args.xss:
        print(f"\n{Fore.YELLOW}[*] Starting XSS Scan...{Style.RESET_ALL}")
        if args.browser:
            print(f"{Fore.BLUE}[*] Using {args.browser_type.capitalize()} browser for form detection{Style.RESET_ALL}")
        xss_scanner = XSSScanner(target_url, use_browser=args.browser, browser_name=args.browser_type)
        report_data["xss_vulnerabilities"] = xss_scanner.scan()
    
    # Generate report
    output_path = args.output if args.output else f"results/{args.url.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_generator = ReportGenerator(report_data, output_path, args.format)
    report_file = report_generator.generate()
    
    print(f"\n{Fore.GREEN}[+] Scan completed at: {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Report saved to: {Fore.WHITE}{report_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan aborted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)