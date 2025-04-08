#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Scanner Module
---------------------------------------
Scans for XSS vulnerabilities in a web application.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
from colorama import Fore, Style
import time
import random
import os

class XSSScanner:
    def __init__(self, target_url, use_browser=False, browser_name='safari'):
        """Initialize the XSS scanner.
        
        Args:
            target_url (str): The URL to scan
            use_browser (bool): Whether to use a browser for form detection (better for JS apps)
            browser_name (str): Browser to use ('safari', 'brave', or 'firefox')
        """
        self.target_url = target_url
        self.use_browser = use_browser
        self.browser_name = browser_name.lower()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'
        })
        self.forms = []
        self.links = []
        self.vulnerable_forms = []
        self.vulnerable_links = []
        self.driver = None
        
        # Load XSS payloads from wordlist file
        self.payloads = self._load_payloads()
        
        # Initialize browser if needed
        if self.use_browser:
            self._setup_browser()
    
    def _load_payloads(self):
        """Load XSS payloads from the wordlist file."""
        payloads = []
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'wordlists', 'xss_payloads.txt')
        
        try:
            with open(wordlist_path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[+] Loaded {len(payloads)} XSS payloads from wordlist{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading XSS payloads: {str(e)}{Style.RESET_ALL}")
            # Fallback to default payloads
            payloads = [
                '<script>alert(1)</script>',
                '<script>alert("XSS")</script>',
                '<img src="x" onerror="alert(1)">',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>'
            ]
            print(f"{Fore.YELLOW}[*] Using default payloads instead{Style.RESET_ALL}")
        
        return payloads
    
    def _extract_forms(self, url):
        """Extract all forms from a webpage, including JavaScript-rendered forms."""
        forms = []
        
        # Method 1: Static HTML form extraction with BeautifulSoup
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            static_forms = soup.find_all('form')
            forms.extend(static_forms)
            print(f"{Fore.BLUE}[*] Found {len(static_forms)} static HTML forms{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting static forms from {url}: {str(e)}{Style.RESET_ALL}")
        
        # Method 2: Use browser automation to get JavaScript-rendered forms
        if self.use_browser and self.driver:
            try:
                from selenium.webdriver.common.by import By
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                from selenium.common.exceptions import TimeoutException, WebDriverException
                
                self.driver.get(url)
                # Wait for page to load completely
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                
                # Extract regular forms
                js_forms = self.driver.find_elements(By.TAG_NAME, "form")
                print(f"{Fore.BLUE}[*] Found {len(js_forms)} forms via browser automation{Style.RESET_ALL}")
                
                # Convert Selenium form elements to BeautifulSoup objects
                for form in js_forms:
                    form_html = form.get_attribute('outerHTML')
                    if form_html:
                        soup_form = BeautifulSoup(form_html, 'html.parser')
                        if soup_form.form:
                            forms.append(soup_form.form)
                
                # Also detect SPA form-like components (React, Angular, etc.)
                potential_forms = self.driver.find_elements(By.CSS_SELECTOR, 
                    "div[ng-submit], div[formGroup], div[ng-form], div[data-form], " + 
                    "div[class*='form'], div[id*='form'], form[ng-submit], form[formGroup], " +
                    "div[data-reactid], div[class*='react'], div[class*='Form']")
                
                for element in potential_forms:
                    # Create a synthetic form element for testing
                    form_html = f"<form>{element.get_attribute('innerHTML')}</form>"
                    soup_form = BeautifulSoup(form_html, 'html.parser')
                    if soup_form.form:
                        forms.append(soup_form.form)
                
                print(f"{Fore.BLUE}[*] Found {len(potential_forms)} potential JS framework forms{Style.RESET_ALL}")
                
            except TimeoutException:
                print(f"{Fore.RED}[!] Timeout while loading page with browser: {url}{Style.RESET_ALL}")
            except WebDriverException as e:
                print(f"{Fore.RED}[!] Browser error while extracting forms: {str(e)}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error extracting JS forms from {url}: {str(e)}{Style.RESET_ALL}")
        
        # Make sure we have unique forms
        unique_forms = []
        form_strings = set()
        
        for form in forms:
            form_str = str(form)
            if form_str not in form_strings:
                form_strings.add(form_str)
                unique_forms.append(form)
        
        return unique_forms
    
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
    
    def _is_vulnerable_to_xss(self, response, payload):
        """Check if a response contains the XSS payload (reflected XSS)."""
        # Check if the payload is reflected in the response
        # We need to escape special characters in the payload for regex
        escaped_payload = re.escape(payload)
        if re.search(escaped_payload, response.text, re.IGNORECASE):
            return True
        
        return False
    
    def _test_form(self, form, url):
        """Test a form for XSS vulnerabilities."""
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
        
        # Test each payload
        for payload in self.payloads:
            test_data = inputs.copy()
            
            # Apply payload to each input
            for input_name in test_data:
                test_data[input_name] = payload
            
            try:
                # Send request based on method
                if method == 'post':
                    response = self.session.post(form_url, data=test_data, timeout=10, allow_redirects=True)
                else:
                    response = self.session.get(form_url, params=test_data, timeout=10, allow_redirects=True)
                
                # Check if vulnerable
                if self._is_vulnerable_to_xss(response, payload):
                    return True, {
                        'url': form_url,
                        'method': method,
                        'inputs': list(inputs.keys()),
                        'payload': payload
                    }
                
                # Wait a bit to avoid overwhelming the server
                time.sleep(random.uniform(0.1, 0.5))
                
            except Exception as e:
                print(f"{Fore.RED}[!] Error testing form at {form_url}: {str(e)}{Style.RESET_ALL}")
        
        return False, None
    
    def _test_link(self, url):
        """Test a URL with parameters for XSS vulnerabilities."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return False, None
        
        base_url = parsed.scheme + '://' + parsed.netloc + parsed.path
        
        # Test each payload
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
                    if self._is_vulnerable_to_xss(response, payload):
                        return True, {
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        }
                    
                    # Wait a bit to avoid overwhelming the server
                    time.sleep(random.uniform(0.1, 0.5))
                    
                except Exception as e:
                    print(f"{Fore.RED}[!] Error testing link {test_url}: {str(e)}{Style.RESET_ALL}")
        
        return False, None
    
    def _setup_browser(self):
        """Set up headless browser for JavaScript-rendered content."""
        try:
            # Import necessary selenium components
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options as ChromeOptions
            from selenium.webdriver.firefox.options import Options as FirefoxOptions
            from selenium.webdriver.safari.options import Options as SafariOptions
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.common.exceptions import TimeoutException, WebDriverException
            
            # Check for browser preference
            browser_name = self.browser_name
            
            if browser_name == 'brave':
                # Brave browser setup (based on Chromium)
                # Mac OS path to Brave browser
                brave_path = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
                
                # If Brave is not in the default location, try alternative locations
                if not os.path.exists(brave_path):
                    # Check alternative locations
                    alternative_paths = [
                        # User Applications folder
                        os.path.expanduser("~/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
                        # Other possible locations
                        "/Applications/Brave.app/Contents/MacOS/Brave"
                    ]
                    
                    for path in alternative_paths:
                        if os.path.exists(path):
                            brave_path = path
                            break
                
                options = ChromeOptions()
                options.binary_location = brave_path
                options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--disable-gpu")
                options.add_argument("--window-size=1920,1080")
                
                # Use ChromeDriver for Brave
                self.driver = webdriver.Chrome(options=options)
                print(f"{Fore.GREEN}[+] Brave browser initialized for form detection{Style.RESET_ALL}")
                
            elif browser_name == 'safari':
                # Safari browser setup
                # Note: Safari requires the Safari WebDriver to be enabled in Safari's 
                # Develop menu (Develop > Allow Remote Automation)
                safari_options = SafariOptions()
                # Safari doesn't support headless mode natively
                
                self.driver = webdriver.Safari(options=safari_options)
                print(f"{Fore.GREEN}[+] Safari browser initialized for form detection{Style.RESET_ALL}")
                
            else:
                # Fallback to Firefox by default
                firefox_options = FirefoxOptions()
                firefox_options.add_argument("--headless")
                
                self.driver = webdriver.Firefox(options=firefox_options)
                print(f"{Fore.GREEN}[+] Firefox browser initialized for form detection{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize browser: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Falling back to static HTML analysis{Style.RESET_ALL}")

    def scan(self):
        """Run the XSS scanner."""
        print(f"{Fore.YELLOW}[*] Starting XSS scan for {self.target_url}{Style.RESET_ALL}")
        
        # Extract forms and links
        print(f"{Fore.BLUE}[*] Extracting forms and links from the target...{Style.RESET_ALL}")
        self.forms = self._extract_forms(self.target_url)
        self.links = self._extract_links(self.target_url)
        
        print(f"{Fore.BLUE}[*] Found {len(self.forms)} forms and {len(self.links)} links with parameters{Style.RESET_ALL}")
        
        # Test forms
        if self.forms:
            print(f"{Fore.BLUE}[*] Testing forms for XSS vulnerabilities...{Style.RESET_ALL}")
            for i, form in enumerate(self.forms, start=1):
                print(f"{Fore.BLUE}[*] Testing form {i}/{len(self.forms)}{Style.RESET_ALL}")
                vulnerable, details = self._test_form(form, self.target_url)
                
                if vulnerable:
                    self.vulnerable_forms.append(details)
                    print(f"{Fore.RED}[!] XSS vulnerability found in form:{Style.RESET_ALL}")
                    print(f"{Fore.RED}    URL: {details['url']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Method: {details['method']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Inputs: {', '.join(details['inputs'])}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Payload: {details['payload']}{Style.RESET_ALL}")
        
        # Test links
        if self.links:
            print(f"{Fore.BLUE}[*] Testing links for XSS vulnerabilities...{Style.RESET_ALL}")
            for i, link in enumerate(self.links, start=1):
                print(f"{Fore.BLUE}[*] Testing link {i}/{len(self.links)}: {link}{Style.RESET_ALL}")
                vulnerable, details = self._test_link(link)
                
                if vulnerable:
                    self.vulnerable_links.append(details)
                    print(f"{Fore.RED}[!] XSS vulnerability found in link:{Style.RESET_ALL}")
                    print(f"{Fore.RED}    URL: {details['url']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Parameter: {details['parameter']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}    Payload: {details['payload']}{Style.RESET_ALL}")
        
        # Clean up browser if used
        if self.use_browser and self.driver:
            try:
                self.driver.quit()
                print(f"{Fore.GREEN}[+] Browser closed successfully{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error closing browser: {str(e)}{Style.RESET_ALL}")
        
        total_vulnerabilities = len(self.vulnerable_forms) + len(self.vulnerable_links)
        print(f"{Fore.YELLOW}[*] XSS scan completed. Found {total_vulnerabilities} vulnerabilities.{Style.RESET_ALL}")
        
        return {
            "target": self.target_url,
            "vulnerable_forms": self.vulnerable_forms,
            "vulnerable_links": self.vulnerable_links,
            "total_vulnerabilities": total_vulnerabilities
        }


if __name__ == "__main__":
    # For testing purposes
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='XSS Scanner')
    parser.add_argument('target_url', help='The URL to scan for XSS vulnerabilities')
    parser.add_argument('--browser', '-b', action='store_true', help='Use browser automation for form detection')
    parser.add_argument('--browser-type', '-t', choices=['safari', 'brave', 'firefox'], 
                        default='safari', help='Browser to use for automation (safari, brave, or firefox)')
    
    args = parser.parse_args()
    
    scanner = XSSScanner(args.target_url, use_browser=args.browser, browser_name=args.browser_type)
    
    if args.browser:
        print(f"{Fore.YELLOW}[*] Using {args.browser_type.capitalize()} browser for form detection{Style.RESET_ALL}")
    
    results = scanner.scan()
    
    print(f"Found {results['total_vulnerabilities']} XSS vulnerabilities for {results['target']}")