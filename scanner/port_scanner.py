#!/usr/bin/env python3
"""
Port Scanner Module
-----------------
Scans for open ports on a target host using python-nmap.
"""

import nmap
import socket
from urllib.parse import urlparse
from tqdm import tqdm
from colorama import Fore, Style

class PortScanner:
    def __init__(self, target_url):
        """Initialize the port scanner."""
        self.target_url = target_url
        self.target_host = self._extract_host(target_url)
        self.nm = nmap.PortScanner()
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        # Port service mapping for common ports
        self.port_service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
    
    def _extract_host(self, url):
        """Extract the hostname from a URL."""
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # If netloc includes port, remove it
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        return hostname
        
    def _get_ip_address(self, hostname):
        """Get the IP address for a hostname."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    def scan_port(self, port):
        """Scan a single port using nmap."""
        try:
            result = self.nm.scan(self.target_host, str(port), arguments='-sV -T4')
            if result['scan'] and self.target_host in result['scan']:
                host_data = result['scan'][self.target_host]
                if 'tcp' in host_data and port in host_data['tcp']:
                    port_data = host_data['tcp'][port]
                    return {
                        'port': port,
                        'state': port_data['state'],
                        'service': port_data['name'],
                        'version': port_data['product'] + ' ' + port_data['version'] if port_data['product'] and port_data['version'] else port_data['product'] or 'Unknown'
                    }
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning port {port}: {str(e)}{Style.RESET_ALL}")
        
        return None
    
    def scan(self):
        """Run the port scanner."""
        ip_address = self._get_ip_address(self.target_host)
        
        if not ip_address:
            print(f"{Fore.RED}[!] Could not resolve hostname: {self.target_host}{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.YELLOW}[*] Starting port scan for {self.target_host} ({ip_address}){Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Scanning {len(self.common_ports)} common ports...{Style.RESET_ALL}")
        
        open_ports = []
        
        for port in tqdm(self.common_ports, desc="Scanning ports", unit="port"):
            result = self.scan_port(port)
            if result and result['state'] == 'open':
                open_ports.append(result)
                service_name = self.port_service_map.get(port, "Unknown")
                print(f"{Fore.GREEN}[+] Port {port} ({service_name}) is open - {result['service']} {result['version']}{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[*] Port scan completed. Found {len(open_ports)} open ports.{Style.RESET_ALL}")
        
        return {
            "host": self.target_host,
            "ip_address": ip_address,
            "open_ports": open_ports
        }


if __name__ == "__main__":
    # For testing purposes
    import sys
    if len(sys.argv) != 2:
        print("Usage: python port_scanner.py <target>")
        sys.exit(1)
    
    scanner = PortScanner(sys.argv[1])
    results = scanner.scan()
    print(f"Found {len(results['open_ports'])} open ports for {results['host']} ({results['ip_address']})")