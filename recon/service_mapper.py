"""
Map discovered services to known vulnerabilities
"""

import json
from typing import List, Dict

class ServiceMapper:
    """Map services to known vulnerabilities"""
    
    # Vulnerability database (simplified for educational purposes)
    VULNERABILITY_DB = {
        'SMB': [
            {
                'name': 'MS17-010 (EternalBlue)',
                'cve': 'CVE-2017-0143',
                'severity': 'Critical',
                'description': 'Remote Code Execution vulnerability in SMBv1',
                'impact': 'Complete system compromise',
                'port': 445
            },
            {
                'name': 'SMBv1 Null Session',
                'cve': 'CVE-1999-0519',
                'severity': 'High',
                'description': 'Allows anonymous access to shares',
                'impact': 'Information disclosure',
                'port': 445
            }
        ],
        'NetBIOS': [
            {
                'name': 'NetBIOS Name Service Overflow',
                'cve': 'CVE-2003-0661',
                'severity': 'High',
                'description': 'Buffer overflow in NetBIOS service',
                'impact': 'Remote Code Execution',
                'port': 139
            }
        ],
        'RDP': [
            {
                'name': 'BlueKeep (CVE-2019-0708)',
                'cve': 'CVE-2019-0708',
                'severity': 'Critical',
                'description': 'Remote Desktop Services RCE',
                'impact': 'Wormable system compromise',
                'port': 3389
            }
        ],
        'FTP': [
            {
                'name': 'FTP Anonymous Access',
                'cve': None,
                'severity': 'Medium',
                'description': 'FTP server allows anonymous login',
                'impact': 'Information disclosure',
                'port': 21
            }
        ],
        'HTTP': [
            {
                'name': 'IIS 7.5 Directory Traversal',
                'cve': 'CVE-2010-2731',
                'severity': 'Medium',
                'description': 'Directory traversal vulnerability',
                'impact': 'Information disclosure',
                'port': 80
            }
        ],
        'MSRPC': [
            {
                'name': 'MS08-067 (NetAPI)',
                'cve': 'CVE-2008-4250',
                'severity': 'Critical',
                'description': 'Server Service RCE vulnerability',
                'impact': 'Remote system compromise',
                'port': 135
            }
        ]
    }
    
    def map_vulnerabilities(self, scan_results: List[Dict]) -> List[Dict]:
        """Map scan results to known vulnerabilities"""
        vulnerabilities = []
        
        for result in scan_results:
            service = result.get('service', '').upper()
            port = result.get('port', 0)
            
            # Check service in vulnerability database
            if service in self.VULNERABILITY_DB:
                service_vulns = self.VULNERABILITY_DB[service]
                
                for vuln in service_vulns:
                    # Check if port matches
                    if vuln['port'] == port or vuln['port'] == 0:
                        vulnerability = {
                            'name': vuln['name'],
                            'cve': vuln['cve'],
                            'severity': vuln['severity'],
                            'description': vuln['description'],
                            'impact': vuln['impact'],
                            'service': service,
                            'port': port,
                            'detected_version': result.get('version', 'Unknown'),
                            'risk_score': self.calculate_risk_score(vuln['severity'])
                        }
                        vulnerabilities.append(vulnerability)
                        
        # Sort by severity (Critical, High, Medium, Low)
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return vulnerabilities
        
    def calculate_risk_score(self, severity: str) -> int:
        """Calculate numeric risk score"""
        scores = {'Critical': 10, 'High': 8, 'Medium': 5, 'Low': 2}
        return scores.get(severity, 0)
        
    def get_vulnerability_details(self, vulnerability_name: str) -> Dict:
        """Get detailed information about a specific vulnerability"""
        for service_vulns in self.VULNERABILITY_DB.values():
            for vuln in service_vulns:
                if vuln['name'] == vulnerability_name:
                    return {
                        **vuln,
                        'mitigation': self.get_mitigation_steps(vuln['name']),
                        'references': self.get_references(vuln.get('cve')),
                        'exploit_available': self.check_exploit_availability(vuln['name'])
                    }
                    
        return {}
        
    def get_mitigation_steps(self, vulnerability_name: str) -> List[str]:
        """Get mitigation steps for a vulnerability"""
        mitigations = {
            'MS17-010 (EternalBlue)': [
                'Apply Microsoft security update MS17-010',
                'Disable SMBv1 protocol',
                'Block port 445 at network firewall',
                'Enable SMB signing'
            ],
            'SMBv1 Null Session': [
                'Disable null session access',
                'Restrict anonymous access',
                'Configure SMB security settings',
                'Use SMBv2 or SMBv3'
            ],
            'BlueKeep (CVE-2019-0708)': [
                'Apply Microsoft security update',
                'Enable Network Level Authentication',
                'Block port 3389 at firewall',
                'Use VPN for remote access'
            ],
            'MS08-067 (NetAPI)': [
                'Apply security update MS08-067',
                'Disable Server service if not needed',
                'Block ports 135-139 and 445',
                'Use host-based firewall'
            ]
        }
        
        return mitigations.get(vulnerability_name, [
            'Apply latest security patches',
            'Disable unnecessary service',
            'Restrict network access',
            'Monitor for suspicious activity'
        ])
        
    def get_references(self, cve_id: str) -> List[str]:
        """Get reference URLs for a CVE"""
        if not cve_id:
            return []
            
        return [
            f'https://nvd.nist.gov/vuln/detail/{cve_id}',
            f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}',
            f'https://www.cvedetails.com/cve/{cve_id}/'
        ]
        
    def check_exploit_availability(self, vulnerability_name: str) -> bool:
        """Check if exploit is publicly available"""
        available_exploits = [
            'MS17-010 (EternalBlue)',
            'MS08-067 (NetAPI)',
            'BlueKeep (CVE-2019-0708)'
        ]
        
        return vulnerability_name in available_exploits