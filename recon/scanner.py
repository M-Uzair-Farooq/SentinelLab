"""
Real Network Scanner using Nmap
"""

import nmap
import socket
import ipaddress
from typing import List, Dict
import subprocess
import time

class NetworkScanner:
    """Real network scanner using Nmap"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.nm = nmap.PortScanner()
        
    def validate_ip(self, ip_address: str) -> bool:
        """Validate IP address is in allowed range"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Only allow private IP ranges for safety
            if not ip.is_private:
                return False
                
            return True
        except ValueError:
            return False
            
    def scan_target(self, target_ip: str, ports: str = "21,22,23,25,53,80,110,135,139,443,445,3389,8080") -> List[Dict]:
        """
        Perform REAL network scan using Nmap
        
        Returns actual scan results from the network
        """
        if not self.validate_ip(target_ip):
            raise ValueError(f"Target IP {target_ip} is not in allowed private ranges")
            
        print(f"[*] Starting REAL nmap scan of {target_ip}")
        print(f"[*] Scanning ports: {ports}")
        
        try:
            # Perform actual Nmap scan
            scan_result = self.nm.scan(
                hosts=target_ip,
                ports=ports,
                arguments='-sS -sV -O --script vuln --min-rate 500'
            )
            
            if target_ip not in scan_result['scan']:
                print(f"[-] Target {target_ip} not responding")
                return []
                
            results = []
            host_info = scan_result['scan'][target_ip]
            
            # Check TCP ports
            if 'tcp' in host_info:
                for port, info in host_info['tcp'].items():
                    if info['state'] == 'open':
                        result = {
                            'port': port,
                            'protocol': 'tcp',
                            'service': info.get('name', 'unknown'),
                            'version': info.get('version', ''),
                            'state': info['state'],
                            'risk': self.assess_risk(port, info.get('name', '')),
                            'product': info.get('product', ''),
                            'extra': info.get('extrainfo', ''),
                            'cpe': info.get('cpe', ''),
                            'script': info.get('script', {})
                        }
                        results.append(result)
            
            # Check UDP ports (common Windows services)
            udp_ports = "53,67,68,69,123,137,138,161,162,500"
            try:
                udp_scan = self.nm.scan(
                    hosts=target_ip,
                    ports=udp_ports,
                    arguments='-sU --min-rate 100'
                )
                
                if target_ip in udp_scan['scan'] and 'udp' in udp_scan['scan'][target_ip]:
                    for port, info in udp_scan['scan'][target_ip]['udp'].items():
                        if info['state'] == 'open':
                            result = {
                                'port': port,
                                'protocol': 'udp',
                                'service': info.get('name', 'unknown'),
                                'version': info.get('version', ''),
                                'state': info['state'],
                                'risk': self.assess_risk(port, info.get('name', '')),
                                'product': info.get('product', ''),
                                'extra': info.get('extrainfo', '')
                            }
                            results.append(result)
            except:
                pass  # UDP scan might fail, that's okay
            
            print(f"[+] Scan completed: Found {len(results)} open ports")
            return results
            
        except Exception as e:
            print(f"[-] Scan error: {e}")
            # Fallback to ping and basic port check
            return self.fallback_scan(target_ip)
            
    def fallback_scan(self, target_ip: str) -> List[Dict]:
        """Fallback scanning using basic socket connection"""
        print(f"[*] Using fallback scan for {target_ip}")
        
        results = []
        common_ports = [
            (21, 'FTP'),
            (22, 'SSH'),
            (23, 'Telnet'),
            (25, 'SMTP'),
            (80, 'HTTP'),
            (110, 'POP3'),
            (135, 'MSRPC'),
            (139, 'NetBIOS'),
            (443, 'HTTPS'),
            (445, 'SMB'),
            (3389, 'RDP'),
            (8080, 'HTTP-Proxy')
        ]
        
        for port, service in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    # Try to get banner
                    try:
                        sock.send(b'\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    except:
                        banner = ''
                    
                    result_data = {
                        'port': port,
                        'protocol': 'tcp',
                        'service': service,
                        'version': self.guess_version(service, banner),
                        'state': 'open',
                        'risk': self.assess_risk(port, service),
                        'banner': banner[:100] if banner else ''
                    }
                    results.append(result_data)
                    
                sock.close()
                
            except:
                continue
                
        return results
        
    def guess_version(self, service: str, banner: str) -> str:
        """Guess service version from banner"""
        banner_lower = banner.lower()
        
        if 'microsoft' in banner_lower:
            if 'iis/7.5' in banner_lower:
                return 'Microsoft IIS 7.5'
            elif 'windows' in banner_lower:
                return 'Microsoft Windows'
                
        if 'apache' in banner_lower:
            return 'Apache'
        if 'nginx' in banner_lower:
            return 'Nginx'
        if 'filezilla' in banner_lower:
            return 'FileZilla'
            
        return 'Unknown'
        
    def assess_risk(self, port: int, service: str) -> str:
        """Assess risk based on port and service"""
        high_risk_ports = {135, 139, 445, 3389}
        high_risk_services = {'smb', 'netbios', 'rpc', 'ftp', 'telnet'}
        
        service_lower = service.lower()
        
        if port in high_risk_ports or any(risk_service in service_lower for risk_service in high_risk_services):
            return 'High'
        elif port in {21, 23, 80, 443}:
            return 'Medium'
        else:
            return 'Low'
            
    def check_vulnerability(self, target_ip: str, port: int, service: str) -> Dict:
        """Check for specific vulnerabilities using Nmap scripts"""
        try:
            if service.lower() == 'smb' and port == 445:
                # Check for MS17-010 (EternalBlue)
                script_result = self.nm.scan(
                    hosts=target_ip,
                    ports=str(port),
                    arguments='--script smb-vuln-ms17-010'
                )
                
                if target_ip in script_result['scan']:
                    scripts = script_result['scan'][target_ip]['tcp'][port].get('script', {})
                    if 'smb-vuln-ms17-010' in scripts:
                        return {
                            'vulnerable': True,
                            'name': 'MS17-010 (EternalBlue)',
                            'description': 'Remote Code Execution in SMBv1',
                            'risk': 'Critical'
                        }
                        
            elif service.lower() == 'msrpc' and port == 135:
                # Check for MS08-067
                script_result = self.nm.scan(
                    hosts=target_ip,
                    ports=str(port),
                    arguments='--script smb-vuln-ms08-067'
                )
                
                if target_ip in script_result['scan']:
                    scripts = script_result['scan'][target_ip]['tcp'][port].get('script', {})
                    if 'smb-vuln-ms08-067' in scripts:
                        return {
                            'vulnerable': True,
                            'name': 'MS08-067 (NetAPI)',
                            'description': 'Server Service Remote Code Execution',
                            'risk': 'Critical'
                        }
                        
        except Exception as e:
            print(f"[-] Vulnerability check error: {e}")
            
        return {'vulnerable': False}