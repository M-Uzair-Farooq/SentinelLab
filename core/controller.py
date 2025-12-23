"""
Main controller for the framework
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any

from PyQt5.QtCore import QObject, pyqtSignal

from core.logger import FrameworkLogger
from recon.scanner import NetworkScanner
from recon.service_mapper import ServiceMapper
from exploit.exploit_controller import ExploitController
from defense.mitigation_engine import MitigationEngine

class FrameworkController(QObject):
    """Main controller coordinating all framework operations"""
    
    # Signals
    scan_completed = pyqtSignal(list)
    exploit_completed = pyqtSignal(bool, dict)
    defense_updated = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.logger = FrameworkLogger()
        self.scanner = NetworkScanner()
        self.service_mapper = ServiceMapper()
        self.exploit_controller = ExploitController()
        self.mitigation_engine = MitigationEngine()
        
        # Session data
        self.session_id = self.generate_session_id()
        self.target_ip = None
        self.scan_results = []
        self.vulnerabilities = []
        self.sessions = []
        self.recommendations = []
        
        self.logger.logger.info(f"Framework controller initialized. Session ID: {self.session_id}")
        
    def generate_session_id(self):
        """Generate unique session ID"""
        return f"SESS_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def validate_target(self, ip_address: str) -> bool:
        """Validate target IP address"""
        # Check for lab IP ranges
        lab_ranges = [
            '192.168.56.',  # VirtualBox host-only
            '10.0.',        # Internal lab
            '172.16.'       # Internal lab
        ]
        
        if not any(ip_address.startswith(prefix) for prefix in lab_ranges):
            self.logger.log_security_event(
                "INVALID_TARGET_RANGE",
                f"Attempt to scan non-lab IP: {ip_address}"
            )
            return False
            
        self.target_ip = ip_address
        return True
        
    def start_reconnaissance(self, ip_address: str):
        """Start REAL reconnaissance scan"""
        if not self.validate_target(ip_address):
            raise ValueError(f"Target IP {ip_address} not in allowed lab ranges")
            
        self.logger.log_scan_start(ip_address)
        
        # Perform REAL scan
        try:
            scan_results = self.scanner.scan_target(ip_address)
            self.scan_results = scan_results
            
            # Map services to vulnerabilities
            self.vulnerabilities = self.service_mapper.map_vulnerabilities(scan_results)
            
            # Check for REAL vulnerabilities using scanner
            for result in scan_results:
                if result.get('risk') in ['High', 'Critical']:
                    vuln_check = self.scanner.check_vulnerability(
                        ip_address, 
                        result['port'], 
                        result['service']
                    )
                    if vuln_check.get('vulnerable'):
                        # Add to vulnerabilities
                        self.vulnerabilities.append({
                            'name': vuln_check.get('name', f"{result['service']} Vulnerability"),
                            'severity': vuln_check.get('risk', 'High'),
                            'service': result['service'],
                            'port': result['port'],
                            'description': vuln_check.get('description', ''),
                            'real_check': True
                        })
            
            self.logger.logger.info(f"REAL scan found {len(scan_results)} open ports")
            self.logger.logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
            
            # Emit signal
            self.scan_completed.emit(scan_results)
            
            # Auto-generate defense recommendations
            if self.vulnerabilities:
                self.generate_defense_recommendations()
            
            return scan_results
            
        except Exception as e:
            self.logger.log_error("Reconnaissance", str(e))
            # Fallback to simulation for demo if real scan fails
            return self.fallback_simulation(ip_address)


    def map_vulnerabilities(self, scan_results: List[Dict]) -> List[Dict]:
        """Map scan results to known vulnerabilities"""
        vulnerabilities = self.service_mapper.map_vulnerabilities(scan_results)
        
        # Store in controller
        self.vulnerabilities = vulnerabilities
        
        # DEBUG
        self.logger.logger.info(f"Mapped {len(vulnerabilities)} vulnerabilities from scan results")
        
        return vulnerabilities
        
    def attempt_exploitation(self, exploit_name: str, port: int = 0) -> Dict:
        """Attempt controlled exploitation"""
        if not self.target_ip:
            raise ValueError("No target specified. Run reconnaissance first.")
            
        self.logger.log_exploit_attempt(self.target_ip, exploit_name)
        
        try:
            success, session_data = self.exploit_controller.execute_exploit(
                self.target_ip, exploit_name, port
            )
            
            if success:
                session_data['id'] = f"EXPLOIT_{datetime.now().strftime('%H%M%S')}"
                session_data['timestamp'] = datetime.now().isoformat()
                session_data['target'] = self.target_ip
                self.sessions.append(session_data)
                
                # AUTO-GENERATE DEFENSE RECOMMENDATIONS after successful exploit
                if self.vulnerabilities:
                    self.generate_defense_recommendations()
                else:
                    # If no vulnerabilities mapped yet, try to get them
                    if self.scan_results:
                        self.vulnerabilities = self.map_vulnerabilities(self.scan_results)
                        if self.vulnerabilities:
                            self.generate_defense_recommendations()
                    else:
                        # Create demo vulnerabilities for educational purposes
                        self.create_demo_vulnerabilities()
                        self.generate_defense_recommendations()
            
            self.logger.log_exploit_result(self.target_ip, exploit_name, success)
            self.exploit_completed.emit(success, session_data)
            
            return session_data
            
        except Exception as e:
            self.logger.log_error("Exploitation", str(e))
            raise
            
    def create_demo_vulnerabilities(self):
        """Create demo vulnerabilities for educational purposes"""
        self.logger.logger.info("Creating demo vulnerabilities for defense demonstration")
        
        self.vulnerabilities = [
            {
                'name': 'MS08-067 (NetAPI)',
                'severity': 'Critical',
                'service': 'MSRPC',
                'port': 135,
                'cve': 'CVE-2008-4250',
                'description': 'Remote Code Execution in Server Service',
                'impact': 'Allows remote attacker to take complete control of system',
                'risk_score': 10
            },
            {
                'name': 'MS17-010 (EternalBlue)',
                'severity': 'Critical',
                'service': 'SMB',
                'port': 445,
                'cve': 'CVE-2017-0143',
                'description': 'Remote Code Execution vulnerability in Microsoft SMBv1 server',
                'impact': 'Allows attacker to execute arbitrary code with SYSTEM privileges',
                'risk_score': 8
            },
            {
                'name': 'SMBv1 Null Session',
                'severity': 'High',
                'service': 'SMB',
                'port': 445,
                'cve': 'CVE-1999-0519',
                'description': 'Allows anonymous access to SMB shares',
                'impact': 'Information disclosure through unauthenticated access',
                'risk_score': 5
            }
        ]
        
    def generate_defense_recommendations(self) -> List[Dict]:
        """Generate defense recommendations based on findings"""
        # Ensure we have vulnerabilities to work with
        if not self.vulnerabilities:
            # Try to get vulnerabilities from scan results
            if self.scan_results:
                self.vulnerabilities = self.map_vulnerabilities(self.scan_results)
            else:
                # Create demo vulnerabilities for educational purposes
                self.create_demo_vulnerabilities()
                
                if not self.vulnerabilities:
                    self.logger.logger.warning("No vulnerabilities available for defense recommendations")
                    return []
        
        self.logger.logger.info(f"Generating defense recommendations for {len(self.vulnerabilities)} vulnerabilities")
        
        # Generate recommendations
        self.recommendations = self.mitigation_engine.generate_recommendations(
            self.vulnerabilities
        )
        
        self.logger.log_defense_recommendations(len(self.recommendations))
        
        # EMIT THE SIGNAL with recommendations
        self.logger.logger.info(f"Emitting defense_updated signal with {len(self.recommendations)} recommendations")
        self.defense_updated.emit(self.recommendations)
        
        return self.recommendations
        
    def add_session(self, session_data: Dict):
        """Add session to controller"""
        session_data['id'] = f"SESS_{len(self.sessions) + 1:03d}"
        session_data['timestamp'] = datetime.now().isoformat()
        self.sessions.append(session_data)
        
        # Auto-generate defense recommendations when session is added
        self.generate_defense_recommendations()
        
    def save_session(self, filename: str = None):
        """Save current session to file"""
        if filename is None:
            filename = f"session_{self.session_id}.json"
            
        session_data = {
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat(),
            'target_ip': self.target_ip,
            'scan_results': self.scan_results,
            'vulnerabilities': self.vulnerabilities,
            'sessions': self.sessions,
            'recommendations': self.recommendations
        }
        
        # Ensure data directory exists
        if not os.path.exists('data'):
            os.makedirs('data')
            
        with open(f'data/{filename}', 'w') as f:
            json.dump(session_data, f, indent=2, default=str)
            
        self.logger.logger.info(f"Session saved to data/{filename}")
        
    def load_session(self, filename: str):
        """Load session from file"""
        with open(filename, 'r') as f:
            session_data = json.load(f)
            
        self.session_id = session_data.get('session_id', self.generate_session_id())
        self.target_ip = session_data.get('target_ip')
        self.scan_results = session_data.get('scan_results', [])
        self.vulnerabilities = session_data.get('vulnerabilities', [])
        self.sessions = session_data.get('sessions', [])
        self.recommendations = session_data.get('recommendations', [])
        
        # Emit signals to update UI
        if self.scan_results:
            self.scan_completed.emit(self.scan_results)
            
        if self.recommendations:
            self.defense_updated.emit(self.recommendations)
            
        self.logger.logger.info(f"Session loaded from {filename}")
        
    def reset_session(self):
        """Reset current session"""
        self.session_id = self.generate_session_id()
        self.target_ip = None
        self.scan_results = []
        self.vulnerabilities = []
        self.sessions = []
        self.recommendations = []
        
        self.logger.logger.info("Session reset")
        
    def get_scan_summary(self) -> str:
        """Get scan summary for reports"""
        if not self.scan_results:
            return "No scan results available."
            
        open_ports = len(self.scan_results)
        high_risk = sum(1 for r in self.scan_results if r.get('risk') in ['High', 'Critical'])
        
        return f"""
        Scan Summary:
        • Target: {self.target_ip or 'Not specified'}
        • Open Ports: {open_ports}
        • High Risk Services: {high_risk}
        • Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
    def get_vulnerability_summary(self) -> str:
        """Get vulnerability summary for reports"""
        if not self.vulnerabilities:
            # Try to get from scan results
            if self.scan_results:
                self.vulnerabilities = self.map_vulnerabilities(self.scan_results)
                
        if not self.vulnerabilities:
            return "No vulnerabilities detected."
            
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in counts:
                counts[severity] += 1
                
        return f"""
        Vulnerability Summary:
        • Total Vulnerabilities: {len(self.vulnerabilities)}
        • Critical Severity: {counts['Critical']}
        • High Severity: {counts['High']}
        • Medium Severity: {counts['Medium']}
        • Low Severity: {counts['Low']}
        
        Top Vulnerabilities:
        {chr(10).join(f'• {v.get("name", "Unknown")} ({v.get("severity", "Low")})' 
                     for v in self.vulnerabilities[:5])}
        """
        
    def get_exploitation_summary(self) -> str:
        """Get exploitation summary for reports"""
        if not self.sessions:
            return "No exploitation attempts recorded."
            
        successful = sum(1 for s in self.sessions if s.get('success', False))
        
        return f"""
        Exploitation Summary:
        • Total Attempts: {len(self.sessions)}
        • Successful: {successful}
        • Success Rate: {(successful/len(self.sessions)*100):.1f}% if len(self.sessions) > 0 else 0
        
        Recent Sessions:
        {chr(10).join(f'• {s.get("id", "Unknown")}: {s.get("exploit", "Unknown")}' 
                     for s in self.sessions[-3:])}
        """
        
    def get_mitigation_summary(self) -> str:
        """Get mitigation summary for reports"""
        if not self.recommendations:
            # Try to generate recommendations
            self.generate_defense_recommendations()
            
        if not self.recommendations:
            return "No mitigation recommendations generated."
            
        critical_actions = sum(1 for r in self.recommendations if r.get('severity') in ['Critical', 'High'])
        
        return f"""
        Mitigation Recommendations:
        • Total Recommendations: {len(self.recommendations)}
        • Critical/High Priority Actions: {critical_actions}
        
        Key Recommendations:
        {chr(10).join(f'• {r.get("vulnerability", "Unknown")}: {r.get("mitigation", ["None"])[0][:60]}...' 
                     for r in self.recommendations[:5])}
        """
        
    def get_target(self) -> str:
        """Get current target"""
        return self.target_ip
        
    def get_vulnerabilities(self):
        """Get current vulnerabilities"""
        return self.vulnerabilities
        
    def get_recommendations(self):
        """Get current defense recommendations"""
        return self.recommendations
        
    def force_defense_generation(self):
        """Force generation of defense recommendations"""
        self.logger.logger.info("Forcing defense recommendations generation")
        return self.generate_defense_recommendations()
        
    def cleanup(self):
        """Cleanup resources"""
        self.logger.logger.info("Framework controller cleanup complete")