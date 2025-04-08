#!/usr/bin/env python3
"""
Subdomain Scanner Module
-----------------------
Identifies subdomains for a given target domain.
"""

import dns.resolver
import requests
from colorama import Fore, Style
from tqdm import tqdm
import socket
import time
import random
import os

class SubdomainScanner:
    def __init__(self, target_url):
        """Initialize the subdomain scanner."""
        self.target = self._extract_domain(target_url)
        self.subdomains = []
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
        # Load wordlist for subdomain bruteforcing
        self.wordlist = self._load_wordlist()
    
    def _load_wordlist(self):
        """Load the wordlist for subdomain bruteforcing."""
        wordlist_path = "wordlists/subdomains.txt"
        
        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print(f"{Fore.GREEN}[+] Loaded {len(wordlist)} subdomains from {wordlist_path}{Style.RESET_ALL}")
                return wordlist
            except Exception as e:
                print(f"{Fore.RED}[!] Error loading subdomains from {wordlist_path}: {str(e)}{Style.RESET_ALL}")
        
        # Fallback to default wordlist if file not found or error occurs
        print(f"{Fore.YELLOW}[!] Using default subdomain wordlist{Style.RESET_ALL}")
        return [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
            "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
            "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
            "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
            "sip", "dns", "api", "cdn", "stats", "dns1", "dns2", "ns4", "mail1", "docs",
            "localhost", "master", "auth", "mx1", "backup", "chat", "wap", "dashboard"
        ]
    
    def _extract_domain(self, url):
        """Extract the base domain from a URL."""
        if '://' in url:
            url = url.split('://')[1]
        if '/' in url:
            url = url.split('/')[0]
        return url
    
    def _is_valid_subdomain(self, subdomain):
        """Check if a subdomain is valid by resolving its IP address."""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            if answers:
                ip_address = str(answers[0])
                return True, ip_address
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass
        return False, None
    
    def bruteforce_subdomains(self):
        """Bruteforce common subdomains."""
        found_subdomains = []
        
        print(f"{Fore.BLUE}[*] Bruteforcing subdomains for {self.target}...{Style.RESET_ALL}")
        
        for word in tqdm(self.wordlist, desc="Bruteforcing subdomains", unit="subdomain"):
            subdomain = f"{word}.{self.target}"
            valid, ip = self._is_valid_subdomain(subdomain)
            
            if valid:
                found_subdomains.append({"subdomain": subdomain, "ip_address": ip})
                print(f"{Fore.GREEN}[+] Found: {Fore.WHITE}{subdomain} {Fore.YELLOW}({ip}){Style.RESET_ALL}")
            
            # Add a small delay to avoid overwhelming DNS servers
            time.sleep(random.uniform(0.1, 0.3))
            
        return found_subdomains
    
    def scan_common_dns_records(self):
        """Scan for common DNS records."""
        dns_records = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        print(f"{Fore.BLUE}[*] Scanning common DNS records for {self.target}...{Style.RESET_ALL}")
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(self.target, record_type)
                for answer in answers:
                    dns_records.append({
                        "record_type": record_type,
                        "value": str(answer)
                    })
                    print(f"{Fore.GREEN}[+] {record_type} Record: {Fore.WHITE}{str(answer)}{Style.RESET_ALL}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                continue
                
        return dns_records
    
    def scan(self):
        """Run the subdomain scanner."""
        print(f"{Fore.YELLOW}[*] Starting subdomain enumeration for {self.target}{Style.RESET_ALL}")
        
        # Scan for DNS records
        dns_records = self.scan_common_dns_records()
        
        # Bruteforce subdomains
        bruteforced = self.bruteforce_subdomains()
        
        results = {
            "domain": self.target,
            "dns_records": dns_records,
            "subdomains": bruteforced
        }
        
        total_subdomains = len(bruteforced)
        print(f"{Fore.YELLOW}[*] Subdomain enumeration completed. Found {total_subdomains} subdomains.{Style.RESET_ALL}")
        
        return results


if __name__ == "__main__":
    # For testing purposes
    import sys
    if len(sys.argv) != 2:
        print("Usage: python subdomain_scanner.py <domain>")
        sys.exit(1)
    
    scanner = SubdomainScanner(sys.argv[1])
    results = scanner.scan()
    print(f"Found {len(results['subdomains'])} subdomains for {results['domain']}")