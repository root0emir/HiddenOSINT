#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DarkwebDomainInfo - A Darkweb domain information gathering tool for digital forensics
"""

import sys
import time
import argparse
import socket
import requests
import socks
import hashlib
import re
import platform
import ipaddress
from stem import Signal
from stem.control import Controller
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from tqdm import tqdm
import json
import os
from datetime import datetime
from urllib.parse import urljoin, urlparse

# Initialize color codes
init(autoreset=True)

# Banner
def print_banner():
    banner = f"""
{Fore.CYAN}

 _   _ _     _     _            
| | | (_) __| | __| | ___ _ __  
| |_| | |/ _` |/ _` |/ _ \ '_ \ 
|  _  | | (_| | (_| |  __/ | | |
|_|_|_|_|\__,_|\__,_|\___|_| |_|
 / _ \ ___(_)_ __ | |_          
| | | / __| | '_ \| __|         
| |_| \__ \ | | | | |_          
 \___/|___/_|_| |_|\__|         

"""
    print(banner)
    print(f"{Fore.YELLOW}[*] HiddenOSINT v1.0 - Darkweb domain information gathering tool")
    print(f"{Fore.YELLOW}[*] Developer: root0emir")
    print(f"{Fore.YELLOW}[*] Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print(f"{Fore.LIGHTRED_EX}LEGAL WARNING:This tool is developed solely for open-source intelligence, educational, and academic purposes. It does not provide access to any illegal content or services.\n")

    # Display system information
    print(f"{Fore.YELLOW}[*] System: {platform.system()} {platform.release()}")
    print(f"{Fore.YELLOW}[*] Python: {platform.python_version()}\n")

class TorConnection:
    """Class for managing connections via Tor network"""
    
    def __init__(self, tor_port=9050, controller_port=9051, password=None):
        self.tor_port = tor_port
        self.controller_port = controller_port
        self.password = password
        self.session = requests.Session()
        self.ip_address = None
        self.country = None
        
    def connect(self):
        """Configure Tor SOCKS proxy connection"""
        # Configure the SOCKS proxy
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
        socket.socket = socks.socksocket
        
        # Apply Tor connection settings to the requests session
        self.session.proxies = {
            'http': f'socks5h://127.0.0.1:{self.tor_port}',
            'https': f'socks5h://127.0.0.1:{self.tor_port}'
        }
        
        # Test connection
        try:
            response = self.session.get("https://check.torproject.org")
            if "Congratulations. This browser is configured to use Tor." in response.text:
                print(f"{Fore.GREEN}[+] Successfully connected to Tor network!")
                
                # Get exit node information
                try:
                    ip_response = self.session.get("https://api.ipify.org", timeout=30)
                    self.ip_address = ip_response.text.strip()
                    print(f"{Fore.GREEN}[+] Tor exit node IP: {self.ip_address}")
                    
                    # Try to get country information
                    try:
                        geo_response = self.session.get(f"https://ipapi.co/{self.ip_address}/country_name/", timeout=30)
                        self.country = geo_response.text.strip()
                        if self.country and not "error" in self.country.lower():
                            print(f"{Fore.GREEN}[+] Exit node country: {self.country}")
                    except:
                        pass
                except:
                    pass
                    
                return True
            else:
                print(f"{Fore.RED}[-] Failed to connect to Tor network!")
                return False
        except Exception as e:
            print(f"{Fore.RED}[-] Tor connection error: {e}")
            print(f"{Fore.YELLOW}[!] Please make sure the Tor service is running.")
            return False
            
    def renew_connection(self):
        """Request a new Tor identity"""
        try:
            with Controller.from_port(port=self.controller_port) as controller:
                if self.password:
                    controller.authenticate(password=self.password)
                else:
                    controller.authenticate()
                controller.signal(Signal.NEWNYM)
                print(f"{Fore.GREEN}[+] Requested new Tor identity")
                time.sleep(5)  # Wait for the new identity to be established
                
                # Update exit node information
                try:
                    ip_response = self.session.get("https://api.ipify.org", timeout=30)
                    new_ip = ip_response.text.strip()
                    if new_ip != self.ip_address:
                        print(f"{Fore.GREEN}[+] New exit node IP: {new_ip} (was {self.ip_address})")
                        self.ip_address = new_ip
                    else:
                        print(f"{Fore.YELLOW}[!] Warning: IP address did not change after identity renewal")
                except:
                    pass
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Tor identity renewal error: {e}")
            
    def get(self, url, headers=None, timeout=30):
        """Send a GET request"""
        if headers is None:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'
            }
        
        try:
            response = self.session.get(url, headers=headers, timeout=timeout)
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Request error: {e}")
            return None
            
    def post(self, url, data=None, json=None, headers=None, timeout=30):
        """Send a POST request"""
        if headers is None:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'
            }
        
        try:
            response = self.session.post(url, data=data, json=json, headers=headers, timeout=timeout)
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Request error: {e}")
            return None

class HiddenOSINT:
    """Main class for gathering information about darkweb domains"""
    
    def __init__(self, domain, output_dir="results", timeout=30, generate_html_report=True, scan_subpages=False, max_subpages=5):
        if not domain.endswith(".onion"):
            raise ValueError("Please enter a valid .onion address!")
            
        self.domain = domain
        self.base_url = f"http://{domain}"
        self.output_dir = output_dir
        self.timeout = timeout
        self.generate_html_report = generate_html_report
        self.scan_subpages = scan_subpages
        self.max_subpages = max_subpages
        self.processed_urls = set()  # Keep track of URLs we've already processed
        
        self.info = {
            "domain": domain,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reachable": False,
            "title": None,
            "server": None,
            "headers": {},
            "links": [],
            "description": None,
            "keywords": [],
            "images": [],
            "status_code": None,
            "response_time": None,
            "content_type": None,
            "content_length": None,
            "security_headers": {},
            "technologies": None,
            "forms": [],
            "emails": [],
            "scripts": [],
            "page_hash": {},
            "subpages": []
        }
        
        # Create result directory
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Initialize Tor connection
        self.tor = TorConnection()
        
    def scan(self):
        """Gather information about the domain"""
        print(f"{Fore.CYAN}[*] Starting scan: {self.domain}")
        
        # Connect to Tor
        if not self.tor.connect():
            print(f"{Fore.RED}[-] Cannot continue without Tor connection!")
            return None
            
        # Visit the main page
        print(f"{Fore.CYAN}[*] Attempting to access main page...")
        start_time = time.time()
        response = self.tor.get(self.base_url, timeout=self.timeout)
        end_time = time.time()
        
        if response is None:
            print(f"{Fore.RED}[-] Site is unreachable!")
            return self.info
            
        self.info["response_time"] = round(end_time - start_time, 2)
        self.info["status_code"] = response.status_code
        self.info["reachable"] = response.status_code == 200
        
        if not self.info["reachable"]:
            print(f"{Fore.RED}[-] Site access status: {response.status_code}")
            return self.info
            
        print(f"{Fore.GREEN}[+] Site is accessible! (HTTP {response.status_code}, {self.info['response_time']} seconds)")
        
        # Collect HTTP headers
        print(f"{Fore.CYAN}[*] Collecting HTTP headers...")
        self.info["headers"] = dict(response.headers)
        self.info["server"] = response.headers.get("Server", "Unknown")
        self.info["content_type"] = response.headers.get("Content-Type", "Unknown")
        self.info["content_length"] = response.headers.get("Content-Length", "Unknown")
        
        # Analyze security headers
        self._analyze_security_headers(response.headers)
        
        # Server information
        if self.info["server"] != "Unknown":
            print(f"{Fore.GREEN}[+] Server: {self.info['server']}")
        
        # Analyze HTML content
        if "text/html" in self.info["content_type"]:
            print(f"{Fore.CYAN}[*] Analyzing HTML content...")
            self._analyze_html(response.text)
            
            # Scan subpages if enabled
            if self.scan_subpages and self.info["links"]:
                self._scan_subpages()
        
        # Save results
        self._save_results()
        return self.info
        
    def _analyze_security_headers(self, headers):
        """Analyze security-related HTTP headers"""
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "Referrer-Policy": headers.get("Referrer-Policy")
        }
        
        # Filter out None values
        self.info["security_headers"] = {k: v for k, v in security_headers.items() if v is not None}
        
        # Check for missing important security headers
        missing_headers = [header for header, value in security_headers.items() if value is None]
        
        if self.info["security_headers"]:
            print(f"{Fore.GREEN}[+] Found {len(self.info['security_headers'])} security headers")
        if missing_headers:
            print(f"{Fore.YELLOW}[!] Missing security headers: {', '.join(missing_headers)}")
            
    def _scan_subpages(self):
        """Scan a subset of internal pages"""
        internal_links = []
        for link in self.info["links"]:
            if link.get("type") == "internal" and link["href"].startswith(self.base_url):
                # Only add if we haven't processed this URL yet
                if link["href"] not in self.processed_urls:
                    internal_links.append(link["href"])
                    self.processed_urls.add(link["href"])
        
        # Limit to max_subpages
        scan_links = internal_links[:self.max_subpages]
        if scan_links:
            print(f"{Fore.CYAN}[*] Scanning {len(scan_links)} internal pages...")
            
            for idx, url in enumerate(scan_links, 1):
                print(f"{Fore.CYAN}[*] Scanning subpage {idx}/{len(scan_links)}: {url}")
                try:
                    subpage_info = {
                        "url": url,
                        "title": None,
                        "status_code": None,
                        "content_type": None,
                        "response_time": None
                    }
                    
                    # Get the page
                    start_time = time.time()
                    response = self.tor.get(url, timeout=self.timeout)
                    end_time = time.time()
                    
                    if response is None:
                        print(f"{Fore.YELLOW}[!] Subpage unreachable: {url}")
                        continue
                        
                    subpage_info["status_code"] = response.status_code
                    subpage_info["response_time"] = round(end_time - start_time, 2)
                    subpage_info["content_type"] = response.headers.get("Content-Type", "Unknown")
                    
                    # Extract title if HTML
                    if "text/html" in subpage_info["content_type"]:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        title_tag = soup.find('title')
                        if title_tag:
                            subpage_info["title"] = title_tag.text.strip()
                            
                    print(f"{Fore.GREEN}[+] Subpage scan complete: {url} (HTTP {subpage_info['status_code']})")
                    self.info["subpages"].append(subpage_info)
                    
                except Exception as e:
                    print(f"{Fore.RED}[-] Error scanning subpage {url}: {e}")
                    
            print(f"{Fore.GREEN}[+] Completed scanning {len(scan_links)} internal pages")
    
    def _analyze_html(self, html_content):
        """Analyze HTML content for intelligence gathering"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Page title
            title_tag = soup.find('title')
            if title_tag:
                self.info["title"] = title_tag.text.strip()
                print(f"{Fore.GREEN}[+] Page title: {self.info['title']}")
                
            # Meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc and meta_desc.get('content'):
                self.info["description"] = meta_desc.get('content')
                print(f"{Fore.GREEN}[+] Meta description found ({len(self.info['description'])} characters)")
                
            # Meta keywords
            meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
            if meta_keywords and meta_keywords.get('content'):
                self.info["keywords"] = [k.strip() for k in meta_keywords.get('content').split(',')]
                print(f"{Fore.GREEN}[+] Keywords: {', '.join(self.info['keywords'][:5])}" + 
                     (f" and {len(self.info['keywords'])-5} more..." if len(self.info['keywords']) > 5 else ""))
            
            # Extract website framework information
            self.info["framework"] = self._detect_framework(soup, html_content)
            if self.info["framework"]:
                print(f"{Fore.GREEN}[+] Detected framework/technology: {self.info['framework']}")
                
            # Extract form information
            forms = self._analyze_forms(soup)
            if forms:
                self.info["forms"] = forms
                print(f"{Fore.GREEN}[+] Found {len(forms)} forms on the page")
                
            # Look for email addresses
            emails = self._extract_emails(html_content)
            if emails:
                self.info["emails"] = emails
                print(f"{Fore.GREEN}[+] Found {len(emails)} email addresses")
                
            # Extract scripts and their sources
            scripts = self._analyze_scripts(soup)
            if scripts:
                self.info["scripts"] = scripts
                print(f"{Fore.GREEN}[+] Found {len(scripts)} script resources")
                
            # Collect links
            links = []
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href and (href.startswith('http') or href.startswith('/') or href.startswith('#') or '.onion' in href):
                    # Normalize the URL
                    if href.startswith('/'):
                        href = urljoin(self.base_url, href)
                    
                    # Only add non-empty links
                    link_text = link.text.strip()[:100]
                    if href not in [l['href'] for l in links]:  # Avoid duplicates
                        links.append({
                            'text': link_text if link_text else "[No text]",
                            'href': href,
                            'type': 'internal' if self.domain in href or href.startswith('/') else 'external'
                        })
            
            self.info["links"] = links[:150]  # Limit to 150 links
            print(f"{Fore.GREEN}[+] Found {len(self.info['links'])} unique links")
            
            # Collect images
            images = []
            for img in soup.find_all('img', src=True):
                src = img.get('src')
                alt = img.get('alt', '')
                if src:
                    # Normalize the URL
                    if src.startswith('/'):
                        src = urljoin(self.base_url, src)
                        
                    if src not in [i['src'] for i in images]:  # Avoid duplicates
                        images.append({
                            'src': src,
                            'alt': alt,
                            'size': self._get_image_size(src)
                        })
            
            self.info["images"] = images[:75]  # Limit to 75 images
            print(f"{Fore.GREEN}[+] Found {len(self.info['images'])} unique images")
            
            # Calculate page fingerprint (hash)
            self.info["page_hash"] = {
                "md5": hashlib.md5(html_content.encode()).hexdigest(),
                "sha256": hashlib.sha256(html_content.encode()).hexdigest()
            }
            print(f"{Fore.GREEN}[+] Generated page fingerprint: {self.info['page_hash']['md5']}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] HTML analysis error: {e}")
            
    def _detect_framework(self, soup, html_content):
        """Detect web frameworks and technologies used by the site"""
        frameworks = []
        
        # Check for common JavaScript frameworks
        if re.search(r'react\.|react-dom\.|\bReact\b', html_content, re.I):
            frameworks.append("React")
        if re.search(r'angular\.|ng-app|ng-controller', html_content, re.I):
            frameworks.append("Angular")
        if re.search(r'vue\.|new Vue|v-bind|v-model', html_content, re.I):
            frameworks.append("Vue.js")
        if re.search(r'jquery\.|\$\(document\)', html_content, re.I):
            frameworks.append("jQuery")
            
        # Check for server-side frameworks
        if re.search(r'django|dsn=|csrftoken', html_content, re.I):
            frameworks.append("Django")
        if re.search(r'laravel|csrf-token', html_content, re.I):
            frameworks.append("Laravel")
        if re.search(r'wordpress|wp-content|wp-includes', html_content, re.I):
            frameworks.append("WordPress")
        if re.search(r'drupal|drupal.org', html_content, re.I):
            frameworks.append("Drupal")
            
        # Check meta generator tag
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            gen_content = meta_generator.get('content')
            frameworks.append(f"Generator: {gen_content[:30]}")
            
        # Look for server info in script attributes
        for script in soup.find_all('script'):
            if script.has_attr('data-cfasync'):
                frameworks.append("Cloudflare")
                
        return ', '.join(frameworks) if frameworks else "Unknown"
        
    def _analyze_forms(self, soup):
        """Extract and analyze forms on the page"""
        forms_data = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'fields': []
            }
            
            # Extract form fields
            for input_field in form.find_all(['input', 'textarea', 'select']):
                field = {
                    'type': input_field.name,
                    'name': input_field.get('name', ''),
                    'id': input_field.get('id', ''),
                    'required': input_field.has_attr('required')
                }
                
                if input_field.name == 'input':
                    field['input_type'] = input_field.get('type', 'text')
                    
                form_data['fields'].append(field)
                
            # Check if it might be a login form
            password_fields = [f for f in form_data['fields'] 
                              if (f['type'] == 'input' and f.get('input_type') == 'password') 
                              or 'password' in f.get('name', '').lower()]
                              
            if password_fields:
                form_data['possible_login_form'] = True
                
            # Check if it might be a search form
            search_indicators = ['search', 'query', 'q', 'find']
            if any(ind in form_data['action'].lower() for ind in search_indicators) or \
               any(f.get('name', '') in search_indicators for f in form_data['fields']):
                form_data['possible_search_form'] = True
                
            forms_data.append(form_data)
            
        return forms_data
        
    def _extract_emails(self, content):
        """Extract email addresses from content"""
        # Basic email regex pattern
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, content)
        
        # Filter out common false positives
        filtered_emails = []
        for email in emails:
            # Skip emails with common placeholder domains
            if 'example.com' in email or 'domain.com' in email:
                continue
            # Skip very long emails (likely false positives)
            if len(email) > 50:
                continue
            filtered_emails.append(email)
            
        return list(set(filtered_emails))  # Remove duplicates
        
    def _analyze_scripts(self, soup):
        """Analyze script tags and their sources"""
        scripts = []
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                # Normalize URL
                if src.startswith('/'):
                    src = urljoin(self.base_url, src)
                
                scripts.append({
                    'src': src,
                    'type': script.get('type', 'text/javascript'),
                    'async': script.has_attr('async'),
                    'defer': script.has_attr('defer')
                })
        
        return scripts
        
    def _get_image_size(self, src):
        """Try to determine image dimensions without downloading the full image"""
        try:
            # For local images only - don't actually download remote images
            if src.startswith(self.base_url) and self.tor and self.tor.session:
                head_resp = self.tor.session.head(src, timeout=5)
                content_length = head_resp.headers.get('Content-Length')
                if content_length:
                    return f"{int(content_length) // 1024} KB"
        except:
            pass
        return "Unknown"
    
    def _save_results(self):
        """Save results to JSON file"""
        output_file = os.path.join(self.output_dir, f"{self.domain.replace('.onion', '')}_info.json")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.info, f, indent=4, ensure_ascii=False)
            print(f"{Fore.GREEN}[+] Results saved: {output_file}")
            
            # Also create HTML report if requested
            if self.generate_html_report:
                html_file = output_file.replace('.json', '.html')
                self._generate_html_report(html_file)
                print(f"{Fore.GREEN}[+] HTML report generated: {html_file}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving results: {e}")
            
    def _generate_html_report(self, html_file):
        """Generate an HTML report from the collected data"""
        try:
            # Basic HTML template
            html = f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>HiddenOSINT Report: {self.domain}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; background-color: #f8f8f8; }}
                    .container {{ max-width: 1200px; margin: 0 auto; background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                    h1, h2, h3 {{ color: #444; }}
                    h1 {{ border-bottom: 2px solid #444; padding-bottom: 10px; }}
                    h2 {{ border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
                    th, td {{ padding: 8px; text-align: left; border: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    .warning {{ color: #856404; background-color: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; }}
                    .success {{ color: #155724; background-color: #d4edda; padding: 10px; border-radius: 5px; margin: 10px 0; }}
                    .danger {{ color: #721c24; background-color: #f8d7da; padding: 10px; border-radius: 5px; margin: 10px 0; }}
                    .timestamp {{ color: #6c757d; font-size: 0.9em; }}
                    .footer {{ margin-top: 30px; padding-top: 10px; border-top: 1px solid #ddd; font-size: 0.8em; color: #777; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>HiddenOSINT Darkweb Intelligence Report</h1>
                    <p class="timestamp">Generated on: {self.info['scan_date']}</p>
                    
                    <div class="{'success' if self.info['reachable'] else 'danger'}">
                        <h3>Target Status: {'Online' if self.info['reachable'] else 'Offline'}</h3>
                        <p>Domain: {self.domain}</p>
                        <p>HTTP Status: {self.info['status_code']}</p>
                        <p>Response Time: {self.info['response_time']} seconds</p>
                    </div>
                    
                    <h2>Basic Information</h2>
                    <table>
                        <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>Page Title</td><td>{self.info['title'] or 'N/A'}</td></tr>
                        <tr><td>Server</td><td>{self.info['server']}</td></tr>
                        <tr><td>Content Type</td><td>{self.info['content_type']}</td></tr>
                        <tr><td>Content Length</td><td>{self.info['content_length']}</td></tr>
                        <tr><td>Description</td><td>{self.info['description'] or 'N/A'}</td></tr>
                    </table>
            '''
            
            # Add framework/technology information if available
            if self.info.get('framework'):
                html += f'''
                    <h2>Technologies Detected</h2>
                    <p>{self.info['framework']}</p>
                '''
                
            # Add security headers section
            html += f'''
                <h2>Security Headers ({len(self.info['security_headers'])}/6)</h2>
            '''
            
            if self.info['security_headers']:
                html += f'''
                    <table>
                        <tr><th>Header</th><th>Value</th></tr>
                '''
                for header, value in self.info['security_headers'].items():
                    html += f'''
                        <tr><td>{header}</td><td>{value}</td></tr>
                    '''
                html += f'''
                    </table>
                '''
            else:
                html += f'''
                    <div class="warning">
                        <p>No security headers found. This might indicate poor security practices.</p>
                    </div>
                '''
                
            # Add links section if available
            if self.info['links']:
                html += f'''
                    <h2>Links Found ({len(self.info['links'])})</h2>
                    <table>
                        <tr><th>Text</th><th>URL</th><th>Type</th></tr>
                '''
                for link in self.info['links'][:30]:  # Limit to first 30 links
                    html += f'''
                        <tr>
                            <td>{link['text']}</td>
                            <td>{link['href']}</td>
                            <td>{link.get('type', 'unknown')}</td>
                        </tr>
                    '''
                html += f'''
                    </table>
                '''
                if len(self.info['links']) > 30:
                    html += f'''
                        <p><em>Showing 30 of {len(self.info['links'])} links. See the JSON report for the complete list.</em></p>
                    '''
                    
            # Add forms section if available
            if self.info.get('forms'):
                html += f'''
                    <h2>Forms Found ({len(self.info['forms'])})</h2>
                    <table>
                        <tr><th>Action</th><th>Method</th><th>Fields</th><th>Notes</th></tr>
                '''
                for form in self.info['forms']:
                    form_type = []
                    if form.get('possible_login_form'):
                        form_type.append("Possible login form")
                    if form.get('possible_search_form'):
                        form_type.append("Possible search form")
                        
                    html += f'''
                        <tr>
                            <td>{form['action']}</td>
                            <td>{form['method']}</td>
                            <td>{len(form['fields'])}</td>
                            <td>{', '.join(form_type) if form_type else 'N/A'}</td>
                        </tr>
                    '''
                html += f'''
                    </table>
                '''
                
            # Add emails section if available
            if self.info.get('emails'):
                html += f'''
                    <h2>Email Addresses Found ({len(self.info['emails'])})</h2>
                    <ul>
                '''
                for email in self.info['emails']:
                    html += f'''
                        <li>{email}</li>
                    '''
                html += f'''
                    </ul>
                '''
                
            # Add subpages section if available
            if self.info.get('subpages'):
                html += f'''
                    <h2>Subpages Scanned ({len(self.info['subpages'])})</h2>
                    <table>
                        <tr><th>URL</th><th>Title</th><th>Status</th><th>Response Time</th></tr>
                '''
                for page in self.info['subpages']:
                    html += f'''
                        <tr>
                            <td>{page['url']}</td>
                            <td>{page.get('title', 'N/A')}</td>
                            <td>{page['status_code']}</td>
                            <td>{page.get('response_time', 'N/A')} sec</td>
                        </tr>
                    '''
                html += f'''
                    </table>
                '''
                
            # Add page hash information
            if self.info.get('page_hash'):
                html += f'''
                    <h2>Page Fingerprint</h2>
                    <table>
                        <tr><th>Hash Type</th><th>Value</th></tr>
                        <tr><td>MD5</td><td>{self.info['page_hash'].get('md5', 'N/A')}</td></tr>
                        <tr><td>SHA256</td><td>{self.info['page_hash'].get('sha256', 'N/A')}</td></tr>
                    </table>
                '''
                
            # Add footer and close HTML tags
            html += f'''
                    <div class="footer">
                        <p>Generated by HiddenOSINT - A Darkweb Intelligence Gathering Tool</p>
                    </div>
                </div>
            </body>
            </html>
            '''
            
            # Save the HTML report
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html)
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error generating HTML report: {e}")
            
def main():
    """Main program flow"""
    print_banner()
    
    # Define command line arguments
    parser = argparse.ArgumentParser(description="HiddenOSINT - Darkweb intelligence gathering tool for digital forensics")
    parser.add_argument("domain", help=".onion domain address (e.g., abcdefgh12345.onion)")
    parser.add_argument("-o", "--output", default="results", help="Directory to save results")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("-s", "--subpages", action="store_true", help="Scan subpages (internal links)")
    parser.add_argument("-m", "--max-subpages", type=int, default=5, help="Maximum number of subpages to scan")
    parser.add_argument("--no-html", action="store_true", help="Disable HTML report generation")
    parser.add_argument("--new-identity", action="store_true", help="Request a new Tor identity before scanning")
    
    # Parse arguments
    args = parser.parse_args()
    
    try:
        # Create and run the intelligence gatherer
        scanner = HiddenOSINT(
            domain=args.domain, 
            output_dir=args.output, 
            timeout=args.timeout,
            generate_html_report=not args.no_html,
            scan_subpages=args.subpages,
            max_subpages=args.max_subpages
        )
        
        # Request new Tor identity if requested
        if args.new_identity and scanner.tor and scanner.tor.session:
            print(f"{Fore.CYAN}[*] Requesting new Tor identity before scanning...")
            scanner.tor.renew_connection()
            
        # Run the scan
        info = scanner.scan()
        
        if info["reachable"]:
            print(f"\n{Fore.GREEN}[+] Scan completed! Details saved to {args.output} directory.")
            print(f"{Fore.GREEN}[+] Scanned {len(info.get('subpages', []))} subpages and found {len(info.get('links', []))} links.")
        else:
            print(f"\n{Fore.YELLOW}[!] Domain is unreachable. Partial results saved to {args.output} directory.")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Stopped by user.")
        sys.exit(1)
    except ValueError as e:
        print(f"\n{Fore.RED}[-] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
