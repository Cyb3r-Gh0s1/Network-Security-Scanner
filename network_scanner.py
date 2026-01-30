#!/usr/bin/env python3
"""
Automated Network Security Scanner v2.0
Author: Faiz Ahemad
GitHub: @Cyb3r-Gh0s1
LinkedIn: faiz-ahemad

Description: A modular network security scanner with plugin-based CVE and Shodan integration.
             Core scanning works independently - plugins enhance but never break functionality.
"""

import nmap
import requests
import json
import argparse
import sys
import socket
from datetime import datetime
from typing import Dict, List, Optional
import os
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

VERSION = "2.0.0"


class CoreScanner:
    """
    Core network scanner - works independently without any plugins.
    This is the foundation that ALWAYS works, even offline.
    """
    
    def __init__(self):
        """Initialize the core scanner"""
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print(f"{Fore.RED}[!] ERROR: Nmap not found. Please install nmap first.{Style.RESET_ALL}")
            sys.exit(1)
        
        self.results = {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scanner_version': VERSION,
            'target': None,
            'target_ip': None,
            'scan_status': 'pending',
            'open_ports': [],
            'os_detection': [],
            'total_ports_scanned': 0
        }
    
    def resolve_target(self, target: str) -> Optional[str]:
        """
        Resolve hostname to IP address or validate IP
        
        Args:
            target: Hostname or IP address
            
        Returns:
            IP address string or None if resolution fails
        """
        print(f"\n{Fore.YELLOW}[*] Resolving target: {target}{Style.RESET_ALL}")
        
        # Check if it's already an IP address
        try:
            socket.inet_aton(target)
            print(f"{Fore.GREEN}[+] Valid IP address: {target}{Style.RESET_ALL}")
            return target
        except socket.error:
            pass
        
        # Try to resolve hostname
        try:
            ip = socket.gethostbyname(target)
            print(f"{Fore.GREEN}[+] Resolved {target} → {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}[!] Failed to resolve hostname: {target}{Style.RESET_ALL}")
            return None
    
    def scan_ports(self, target: str, port_range: str = '1-1000', scan_type: str = 'default') -> bool:
        """
        Perform port scanning on target
        
        Args:
            target: IP address or hostname to scan
            port_range: Range of ports to scan (default: 1-1000)
            scan_type: Scan type - 'default', 'quick', 'thorough'
            
        Returns:
            True if scan succeeded, False otherwise
        """
        # Resolve target to IP
        target_ip = self.resolve_target(target)
        if not target_ip:
            self.results['scan_status'] = 'failed'
            return False
        
        self.results['target'] = target
        self.results['target_ip'] = target_ip
        
        # Determine scan arguments based on type
        if scan_type == 'quick':
            # Fast scan - no version detection, no OS detection
            scan_args = '-T4'
        elif scan_type == 'thorough':
            # Comprehensive scan with service version and OS detection
            scan_args = '-sV -T4 -A --version-intensity 7'
        else:
            # Default balanced scan
            scan_args = '-sV -T4 --version-intensity 5'
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  Port Scanning: {target} ({target_ip})")
        print(f"  Ports: {port_range}")
        print(f"  Mode: {scan_type}")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        try:
            # Perform the scan
            print(f"\n{Fore.YELLOW}[*] Scanning in progress...{Style.RESET_ALL}")
            self.nm.scan(hosts=target_ip, ports=port_range, arguments=scan_args)
            
            # Check if host is up
            if target_ip not in self.nm.all_hosts():
                print(f"{Fore.RED}[!] Host appears to be down or unreachable{Style.RESET_ALL}")
                self.results['scan_status'] = 'host_down'
                return False
            
            # Get host state
            host_state = self.nm[target_ip].state()
            print(f"{Fore.GREEN}[+] Host is {host_state}{Style.RESET_ALL}")
            
            if host_state != 'up':
                self.results['scan_status'] = 'host_down'
                return False
            
            # Extract open ports
            ports_found = 0
            for proto in self.nm[target_ip].all_protocols():
                ports = self.nm[target_ip][proto].keys()
                for port in sorted(ports):
                    port_info = self.nm[target_ip][proto][port]
                    
                    # Only include open ports
                    if port_info['state'] == 'open':
                        service_data = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', 'unknown'),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        self.results['open_ports'].append(service_data)
                        ports_found += 1
                        
                        # Print service info
                        version_str = f"{port_info.get('product', 'unknown')} {port_info.get('version', '')}"
                        print(f"{Fore.GREEN}[+] {port}/{proto}\t{port_info['state']}\t{port_info.get('name', 'unknown')}\t{version_str.strip()}{Style.RESET_ALL}")
            
            # OS Detection (if available)
            if 'osmatch' in self.nm[target_ip]:
                print(f"\n{Fore.CYAN}[*] OS Detection:{Style.RESET_ALL}")
                for os_match in self.nm[target_ip]['osmatch'][:3]:  # Top 3 matches
                    os_info = {
                        'name': os_match['name'],
                        'accuracy': os_match['accuracy']
                    }
                    self.results['os_detection'].append(os_info)
                    print(f"{Fore.GREEN}[+] {os_match['name']} ({os_match['accuracy']}% accuracy){Style.RESET_ALL}")
            
            # Summary
            print(f"\n{Fore.CYAN}[*] Scan Summary:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Total open ports found: {ports_found}{Style.RESET_ALL}")
            
            self.results['scan_status'] = 'completed'
            self.results['total_ports_scanned'] = len(port_range.split(',')) if ',' in port_range else int(port_range.split('-')[1]) - int(port_range.split('-')[0]) + 1
            
            return True
            
        except nmap.PortScannerError as e:
            print(f"{Fore.RED}[!] Nmap scan error: {str(e)}{Style.RESET_ALL}")
            self.results['scan_status'] = 'error'
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Unexpected error during scan: {str(e)}{Style.RESET_ALL}")
            self.results['scan_status'] = 'error'
            return False
    
    def get_results(self) -> Dict:
        """Return scan results"""
        return self.results


class CVEPlugin:
    """
    CVE Vulnerability Plugin - OPTIONAL MODULE
    Takes service + version, returns known CVEs.
    If this fails, main scanner continues working.
    """
    
    @staticmethod
    def lookup_cve(service: str, version: str) -> List[Dict]:
        """
        Query NIST NVD for CVEs related to service and version
        
        Args:
            service: Service/product name
            version: Version string
            
        Returns:
            List of CVE dictionaries (empty list if fails)
        """
        if not service or service == 'unknown' or not version:
            return []
        
        print(f"\n{Fore.YELLOW}[CVE Plugin] Searching for {service} {version}...{Style.RESET_ALL}")
        
        try:
            # Search NIST NVD
            search_term = f"{service} {version}"
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': search_term,
                'resultsPerPage': 5
            }
            
            headers = {'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
            response = requests.get(url, params=params, headers=headers, timeout=10)
            
            if response.status_code != 200:
                print(f"{Fore.YELLOW}[CVE Plugin] API returned status {response.status_code}{Style.RESET_ALL}")
                return []
            
            data = response.json()
            cves = []
            
            if 'vulnerabilities' in data and data['vulnerabilities']:
                for item in data['vulnerabilities']:
                    cve_data = item.get('cve', {})
                    cve_id = cve_data.get('id', 'Unknown')
                    
                    # Extract CVSS score
                    metrics = cve_data.get('metrics', {})
                    cvss_score = 'N/A'
                    severity = 'UNKNOWN'
                    
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 'N/A')
                        severity = metrics['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'UNKNOWN')
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss_score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 'N/A')
                        severity = 'MEDIUM'  # V2 doesn't have severity
                    
                    descriptions = cve_data.get('descriptions', [])
                    description = descriptions[0].get('value', 'No description') if descriptions else 'No description'
                    
                    cve_info = {
                        'cve_id': cve_id,
                        'description': description[:150] + '...' if len(description) > 150 else description,
                        'cvss_score': cvss_score,
                        'severity': severity
                    }
                    cves.append(cve_info)
                    
                    # Color code severity
                    color = Fore.RED if severity in ['CRITICAL', 'HIGH'] else Fore.YELLOW
                    print(f"{color}[CVE Plugin] {cve_id} - {severity} (CVSS: {cvss_score}){Style.RESET_ALL}")
                
                return cves
            else:
                print(f"{Fore.GREEN}[CVE Plugin] No CVEs found{Style.RESET_ALL}")
                return []
                
        except requests.Timeout:
            print(f"{Fore.YELLOW}[CVE Plugin] Request timed out - continuing without CVE data{Style.RESET_ALL}")
            return []
        except requests.RequestException as e:
            print(f"{Fore.YELLOW}[CVE Plugin] Network error: {str(e)}{Style.RESET_ALL}")
            return []
        except Exception as e:
            print(f"{Fore.YELLOW}[CVE Plugin] Unexpected error: {str(e)}{Style.RESET_ALL}")
            return []


class ShodanPlugin:
    """
    Shodan Intelligence Plugin - OPTIONAL MODULE
    Takes IP address, returns passive intelligence.
    If this fails, main scanner continues working.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize Shodan plugin with API key"""
        self.api_key = api_key or os.getenv('SHODAN_API_KEY')
    
    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """
        Query Shodan for passive intelligence about an IP
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with Shodan data (None if fails)
        """
        if not self.api_key:
            print(f"{Fore.YELLOW}[Shodan Plugin] No API key provided - skipping{Style.RESET_ALL}")
            return None
        
        print(f"\n{Fore.YELLOW}[Shodan Plugin] Querying {ip}...{Style.RESET_ALL}")
        
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                if response.status_code == 404:
                    print(f"{Fore.YELLOW}[Shodan Plugin] No data found for {ip}{Style.RESET_ALL}")
                elif response.status_code == 401:
                    print(f"{Fore.YELLOW}[Shodan Plugin] Invalid API key{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[Shodan Plugin] API returned status {response.status_code}{Style.RESET_ALL}")
                return None
            
            data = response.json()
            
            shodan_info = {
                'ip': data.get('ip_str'),
                'organization': data.get('org', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'country': data.get('country_name', 'N/A'),
                'city': data.get('city', 'N/A'),
                'ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'tags': data.get('tags', []),
                'vulns': data.get('vulns', [])
            }
            
            # Display results
            print(f"{Fore.GREEN}[Shodan Plugin] Data retrieved:{Style.RESET_ALL}")
            print(f"  Organization: {shodan_info['organization']}")
            print(f"  ISP: {shodan_info['isp']}")
            print(f"  Location: {shodan_info['city']}, {shodan_info['country']}")
            print(f"  Open ports: {', '.join(map(str, shodan_info['ports'][:10]))}")
            
            if shodan_info['vulns']:
                print(f"{Fore.RED}  Known vulnerabilities: {', '.join(shodan_info['vulns'][:5])}{Style.RESET_ALL}")
            
            return shodan_info
            
        except requests.Timeout:
            print(f"{Fore.YELLOW}[Shodan Plugin] Request timed out{Style.RESET_ALL}")
            return None
        except requests.RequestException as e:
            print(f"{Fore.YELLOW}[Shodan Plugin] Network error: {str(e)}{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.YELLOW}[Shodan Plugin] Unexpected error: {str(e)}{Style.RESET_ALL}")
            return None


class ReportGenerator:
    """Generate reports from scan results"""
    
    @staticmethod
    def generate_json(results: Dict, output_file: str):
        """
        Generate JSON report
        
        Args:
            results: Scan results dictionary
            output_file: Output filename
        """
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"\n{Fore.GREEN}[+] Report saved: {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save report: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def print_summary(results: Dict):
        """Print scan summary to console"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print("  SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Target: {results.get('target', 'N/A')} ({results.get('target_ip', 'N/A')})")
        print(f"Scan time: {results.get('scan_time', 'N/A')}")
        print(f"Status: {results.get('scan_status', 'N/A')}")
        print(f"Open ports: {len(results.get('open_ports', []))}")
        
        if 'shodan_data' in results and results['shodan_data']:
            print(f"Shodan data: ✓ Retrieved")
        
        if 'cve_data' in results and results['cve_data']:
            total_cves = sum(len(cves) for cves in results['cve_data'].values())
            print(f"CVEs found: {total_cves}")


def print_banner():
    """Display application banner"""
    banner = f"""
{Fore.CYAN}{'='*70}
   Automated Network Security Scanner v{VERSION}
   Author: Faiz Ahemad | GitHub: @Cyb3r-Gh0s1
   
   Plugin Architecture: Core + CVE + Shodan
{'='*70}{Style.RESET_ALL}
"""
    print(banner)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Modular Network Security Scanner with Plugin Architecture',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
IMPORTANT - KALI LINUX USERS:
  Before running, activate your virtual environment:
    source venv/bin/activate

EXAMPLES:

  Scan IP address (default ports 1-1000):
    python %(prog)s -t 192.168.1.1

  Scan domain/hostname:
    python %(prog)s -t scanme.nmap.org

  Quick scan (top 100 ports):
    python %(prog)s -t example.com -p 1-100 --quick

  Thorough scan with all plugins:
    python %(prog)s -t 192.168.1.1 -p 1-5000 --thorough --cve --shodan

  Scan specific ports:
    python %(prog)s -t 10.0.0.1 -p 22,80,443,3389

  Scan with CVE lookup only:
    python %(prog)s -t scanme.nmap.org -p 1-1000 --cve

  Scan with Shodan intelligence:
    python %(prog)s -t 8.8.8.8 --shodan -s YOUR_API_KEY

  Full scan with custom output:
    python %(prog)s -t example.com -p 1-10000 --cve --shodan -o report.json

SCAN MODES:
  --quick     Fast scan, no version detection (fastest)
  --thorough  Deep scan with OS detection (slowest, most detailed)
  (default)   Balanced scan with service version detection

PLUGINS:
  --cve       Enable CVE vulnerability lookup (requires internet)
  --shodan    Enable Shodan passive intelligence (requires API key)

NOTES:
  - Core scanner works offline, plugins are optional
  - CVE and Shodan failures do not affect core scanning
  - Use 'sudo' for OS detection and SYN scans on Linux
  - Test on authorized targets only (e.g., scanme.nmap.org)

DISCLAIMER:
  This tool is for authorized security testing and educational purposes only.
  Unauthorized scanning is illegal. Always obtain permission before scanning.
        """
    )
    
    # Required arguments
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address or hostname (e.g., 192.168.1.1 or scanme.nmap.org)')
    
    # Optional arguments
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Port range to scan (default: 1-1000). Examples: "1-1000", "80,443", "1-65535"')
    
    parser.add_argument('-o', '--output', default='scan_report.json',
                       help='Output JSON report file (default: scan_report.json)')
    
    # Scan modes
    scan_mode = parser.add_mutually_exclusive_group()
    scan_mode.add_argument('--quick', action='store_true',
                          help='Quick scan mode (no version detection, faster)')
    scan_mode.add_argument('--thorough', action='store_true',
                          help='Thorough scan mode (includes OS detection, slower)')
    
    # Plugin options
    parser.add_argument('--cve', action='store_true',
                       help='Enable CVE vulnerability lookup plugin')
    
    parser.add_argument('--shodan', action='store_true',
                       help='Enable Shodan intelligence plugin')
    
    parser.add_argument('-s', '--shodan-key',
                       help='Shodan API key (or set SHODAN_API_KEY env variable)')
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    # Print banner and disclaimer
    print_banner()
    print(f"{Fore.RED}[!] DISCLAIMER: For authorized testing only. Unauthorized scanning is illegal.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Always obtain permission before scanning any target.{Style.RESET_ALL}\n")
    
    # Determine scan type
    scan_type = 'default'
    if args.quick:
        scan_type = 'quick'
    elif args.thorough:
        scan_type = 'thorough'
    
    # STEP 1: Core Scan (ALWAYS runs, works offline)
    print(f"{Fore.CYAN}[*] Starting core network scan...{Style.RESET_ALL}")
    scanner = CoreScanner()
    
    success = scanner.scan_ports(args.target, args.ports, scan_type)
    
    if not success:
        print(f"\n{Fore.RED}[!] Core scan failed. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    results = scanner.get_results()
    
    # STEP 2: CVE Plugin (OPTIONAL - runs only if --cve flag is set)
    if args.cve and results['open_ports']:
        print(f"\n{Fore.CYAN}{'='*60}")
        print("  CVE VULNERABILITY LOOKUP (Plugin)")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        cve_plugin = CVEPlugin()
        results['cve_data'] = {}
        
        for port_info in results['open_ports']:
            service = port_info['product']
            version = port_info['version']
            
            if service and service != 'unknown' and version:
                cves = cve_plugin.lookup_cve(service, version)
                if cves:
                    key = f"{service}_{version}"
                    results['cve_data'][key] = cves
                    port_info['cves'] = cves
    
    # STEP 3: Shodan Plugin (OPTIONAL - runs only if --shodan flag is set)
    if args.shodan:
        print(f"\n{Fore.CYAN}{'='*60}")
        print("  SHODAN PASSIVE INTELLIGENCE (Plugin)")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        shodan_plugin = ShodanPlugin(args.shodan_key)
        shodan_data = shodan_plugin.lookup_ip(results['target_ip'])
        
        if shodan_data:
            results['shodan_data'] = shodan_data
    
    # STEP 4: Generate Report
    ReportGenerator.print_summary(results)
    ReportGenerator.generate_json(results, args.output)
    
    print(f"\n{Fore.GREEN}{'='*60}")
    print("  SCAN COMPLETED SUCCESSFULLY")
    print(f"{'='*60}{Style.RESET_ALL}\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
