"""
Mitigation engine for defense recommendations
"""

import json
import os
from typing import List, Dict

class MitigationEngine:
    """Engine for generating defense recommendations"""
    
    def __init__(self, rules_file: str = "defense/hardening_rules.json"):
        self.rules_file = rules_file
        self.rules = self.load_rules()
        
    def load_rules(self) -> Dict:
        """Load mitigation rules from file"""
        # Default rules if file doesn't exist
        default_rules = {
            'vulnerabilities': {
                'MS17-010 (EternalBlue)': {
                    'severity': 'Critical',
                    'mitigation': [
                        'Apply Microsoft security update MS17-010',
                        'Disable SMBv1 protocol',
                        'Block port 445 at network firewall',
                        'Enable SMB signing',
                        'Implement network segmentation'
                    ],
                    'root_cause': 'Unpatched SMBv1 implementation',
                    'category': 'Remote Code Execution'
                },
                'MS08-067 (NetAPI)': {
                    'severity': 'Critical',
                    'mitigation': [
                        'Apply security update MS08-067',
                        'Disable Server service if not needed',
                        'Block ports 135-139 and 445',
                        'Use host-based firewall',
                        'Enable Windows Firewall'
                    ],
                    'root_cause': 'Unpatched NetAPI service',
                    'category': 'Remote Code Execution'
                },
                'SMBv1 Null Session': {
                    'severity': 'High',
                    'mitigation': [
                        'Disable null session access',
                        'Restrict anonymous access in registry',
                        'Configure SMB security settings',
                        'Use SMBv2 or SMBv3',
                        'Implement access controls'
                    ],
                    'root_cause': 'Misconfigured SMB permissions',
                    'category': 'Information Disclosure'
                },
                'BlueKeep (CVE-2019-0708)': {
                    'severity': 'Critical',
                    'mitigation': [
                        'Apply Microsoft security update',
                        'Enable Network Level Authentication',
                        'Block port 3389 at firewall',
                        'Use VPN for remote access',
                        'Implement multi-factor authentication'
                    ],
                    'root_cause': 'Unpatched Remote Desktop Services',
                    'category': 'Remote Code Execution'
                }
            },
            'hardening_checklist': [
                {
                    'recommendation': 'Apply all Windows updates',
                    'category': 'Patch Management',
                    'priority': 'High',
                    'description': 'Keep system updated with latest security patches',
                    'implementation': [
                        'Enable Windows Update automatic updates',
                        'Check for updates monthly',
                        'Test updates in staging environment'
                    ]
                },
                {
                    'recommendation': 'Enable Windows Firewall',
                    'category': 'Network Security',
                    'priority': 'High',
                    'description': 'Configure host-based firewall rules',
                    'implementation': [
                        'Enable Windows Firewall',
                        'Configure inbound/outbound rules',
                        'Block unnecessary ports'
                    ]
                },
                {
                    'recommendation': 'Disable unnecessary services',
                    'category': 'System Hardening',
                    'priority': 'Medium',
                    'description': 'Reduce attack surface by disabling unused services',
                    'implementation': [
                        'Review running services',
                        'Disable Telnet, FTP if not needed',
                        'Disable SMBv1'
                    ]
                },
                {
                    'recommendation': 'Configure password policy',
                    'category': 'Access Control',
                    'priority': 'High',
                    'description': 'Implement strong password requirements',
                    'implementation': [
                        'Minimum password length: 12 characters',
                        'Password complexity requirements',
                        'Account lockout policy'
                    ]
                },
                {
                    'recommendation': 'Enable User Account Control',
                    'category': 'Privilege Management',
                    'priority': 'Medium',
                    'description': 'Prevent unauthorized system changes',
                    'implementation': [
                        'Set UAC to highest level',
                        'Require administrator approval',
                        'Enable secure desktop'
                    ]
                }
            ]
        }
        
        # Try to load from file, use defaults if not found
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    return json.load(f)
        except:
            pass
            
        return default_rules
        
    def generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate defense recommendations for vulnerabilities"""
        recommendations = []
        
        for vuln in vulnerabilities:
            vuln_name = vuln.get('name', '')
            
            if vuln_name in self.rules['vulnerabilities']:
                rule = self.rules['vulnerabilities'][vuln_name]
                
                recommendation = {
                    'vulnerability': vuln_name,
                    'severity': rule['severity'],
                    'category': rule.get('category', 'General'),
                    'root_cause': rule.get('root_cause', 'Not specified'),
                    'mitigation': rule['mitigation'],
                    'service': vuln.get('service', ''),
                    'port': vuln.get('port', 0),
                    'applied': False
                }
                
                recommendations.append(recommendation)
                
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        recommendations.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return recommendations
        
    def get_mitigation_details(self, vulnerability: str) -> Dict:
        """Get detailed mitigation information"""
        if vulnerability in self.rules['vulnerabilities']:
            return self.rules['vulnerabilities'][vulnerability]
            
        return {
            'severity': 'Unknown',
            'mitigation': ['No specific mitigation available'],
            'root_cause': 'Not specified',
            'category': 'General'
        }
        
    def get_hardening_checklist(self) -> List[Dict]:
        """Get system hardening checklist"""
        return self.rules.get('hardening_checklist', [])
        
    def get_hardening_details(self, recommendation: str) -> Dict:
        """Get details for a hardening recommendation"""
        for item in self.rules.get('hardening_checklist', []):
            if item.get('recommendation') == recommendation:
                return item
                
        return {
            'description': 'Details not available',
            'implementation': ['Implementation steps not specified']
        }
        
    def get_best_practices(self, vulnerability: str) -> List[str]:
        """Get security best practices for a vulnerability"""
        practices = {
            'MS17-010 (EternalBlue)': [
                'Regularly patch all systems',
                'Network segmentation for critical assets',
                'Monitor for SMB exploitation attempts',
                'Implement application whitelisting',
                'Regular security assessments'
            ],
            'MS08-067 (NetAPI)': [
                'Maintain patch management process',
                'Disable unnecessary Windows services',
                'Network access controls',
                'Log and monitor NetAPI access',
                'Regular vulnerability scanning'
            ],
            'General': [
                'Defense in depth strategy',
                'Least privilege principle',
                'Regular backups',
                'Security awareness training',
                'Incident response planning'
            ]
        }
        
        # Try to get specific practices, fall back to general
        for key in practices:
            if key in vulnerability:
                return practices[key]
                
        return practices['General']
        
    def save_rules(self, rules: Dict = None):
        """Save rules to file"""
        if rules is None:
            rules = self.rules
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
        
        with open(self.rules_file, 'w') as f:
            json.dump(rules, f, indent=2)