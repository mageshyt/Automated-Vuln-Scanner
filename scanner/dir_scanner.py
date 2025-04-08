#!/usr/bin/env python3
"""
Directory Scanner Module
----------------------
Scans for hidden directories and files in a web application.
"""

import requests
import threading
import queue
import os
from urllib.parse import urljoin
from colorama import Fore, Style
from tqdm import tqdm

class DirectoryScanner:
    def __init__(self, target_url, wordlist_path=None, threads=10):
        """Initialize the directory scanner."""
        self.target_url = target_url
        self.threads = threads
        self.queue = queue.Queue()
        self.found_directories = []
        self.lock = threading.Lock()
        self.progress_bar = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'
        })
        
        # Default wordlist if not provided
        if wordlist_path and os.path.exists(wordlist_path):
            self.wordlist_path = wordlist_path
        else:
            print(f"{Fore.YELLOW}[!] Wordlist not found: {wordlist_path}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Using default wordlist{Style.RESET_ALL}")
            
            # Create default wordlist
            self.wordlist_path = "wordlists/directories.txt"
            self._create_default_wordlist()
    
    def _create_default_wordlist(self):
        """Create a default wordlist for directory bruteforcing."""
        os.makedirs(os.path.dirname(self.wordlist_path), exist_ok=True)
        
        common_dirs = [
            "admin", "administrator", "backup", "backups", "css", "data", "images", 
            "img", "js", "login", "logs", "old", "temp", "test", "uploads", "api",
            "config", "dashboard", "db", "files", "forum", "home", "static", "user",
            "users", "wp-admin", "wp-content", "wp-includes", "account", "assets",
            "login.php", "register.php", "upload.php", "setup", "admin.php", 
            "wp-login.php", "cpanel", "phpmyadmin", "webmail", "mail", "mysql",
            "database", "databases", "setup.php", "wp-config.php", "config.php",
            "phpinfo.php", "info.php", "private", "secret", "hidden", "backup.sql",
            "dump.sql", ".git", ".svn", ".htaccess", "robots.txt", "sitemap.xml",
            "server-status", "server-info", "test.php", "phpMyAdmin", "adminer.php",
            "admin/login", "login/admin", "portal", "dev"
        ]
        
        with open(self.wordlist_path, 'w') as f:
            for directory in common_dirs:
                f.write(directory + '\n')
        
        print(f"{Fore.GREEN}[+] Created default wordlist at {self.wordlist_path}{Style.RESET_ALL}")
    
    def _load_wordlist(self):
        """Load the wordlist for directory bruteforcing."""
        with open(self.wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    def _worker(self):
        """Worker thread for directory bruteforcing."""
        while not self.queue.empty():
            path = self.queue.get()
            self._check_directory(path)
            self.progress_bar.update(1)
            self.queue.task_done()
    
    def _check_directory(self, path):
        """Check if a directory or file exists on the target."""
        url = urljoin(self.target_url, path)
        
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            
            if response.status_code in [200, 201, 202, 203, 301, 302, 307, 308]:
                with self.lock:
                    self.found_directories.append({
                        'path': path,
                        'url': url,
                        'status_code': response.status_code,
                        'size': len(response.content)
                    })
                    
                    status_color = Fore.GREEN if response.status_code == 200 else Fore.YELLOW
                    print(f"{status_color}[+] Found: {Fore.WHITE}{url} {status_color}[{response.status_code}] {Fore.BLUE}[{len(response.content)} bytes]{Style.RESET_ALL}")
        
        except requests.RequestException:
            pass
    
    def scan(self):
        """Run the directory scanner."""
        print(f"{Fore.YELLOW}[*] Starting directory scan for {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Using wordlist: {self.wordlist_path}{Style.RESET_ALL}")
        
        wordlist = self._load_wordlist()
        print(f"{Fore.BLUE}[*] Loaded {len(wordlist)} paths to scan{Style.RESET_ALL}")
        
        # Initialize progress bar
        self.progress_bar = tqdm(total=len(wordlist), desc="Scanning directories", unit="path")
        
        # Add all paths to the queue
        for path in wordlist:
            self.queue.put(path)
        
        # Start worker threads
        threads = []
        for _ in range(min(self.threads, len(wordlist))):
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all tasks to complete
        self.queue.join()
        
        # Close progress bar
        self.progress_bar.close()
        
        print(f"{Fore.YELLOW}[*] Directory scan completed. Found {len(self.found_directories)} directories/files.{Style.RESET_ALL}")
        
        return {
            "target": self.target_url,
            "wordlist": self.wordlist_path,
            "directories": self.found_directories
        }


if __name__ == "__main__":
    # For testing purposes
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dir_scanner.py <target_url> [wordlist_path]")
        sys.exit(1)
    
    target = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = DirectoryScanner(target, wordlist)
    results = scanner.scan()
    
    print(f"Found {len(results['directories'])} directories/files for {results['target']}")