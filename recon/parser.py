"""
Parser for scan results
"""

import json
import re
from typing import Dict, List

class ScanParser:
    """Parse and structure scan results"""
    
    @staticmethod
    def parse_nmap_output(xml_output: str) -> List[Dict]:
        """
        Parse nmap XML output
        Note: This is a simplified version for educational purposes
        """
        results = []
        
        # Simplified parsing - in reality would use xml.etree.ElementTree
        # This simulates parsed results
        ports = re.findall(r'portid="(\d+)"', xml_output)
        services = re.findall(r'service name="([^"]+)"', xml_output)
        
        for i, port in enumerate(ports[:10]):  # Limit to 10 for demo
            service = services[i] if i < len(services) else 'unknown'
            
            result = {
                'port': int(port),
                'protocol': 'tcp',
                'service': service,
                'state': 'open',
                'risk': ScanParser.assess_risk(int(port), service)
            }
            
            results.append(result)
            
        return results
        
    @staticmethod
    def assess_risk(port: int, service: str) -> str:
        """Assess risk level based on port and service"""
        high_risk_ports = {135, 139, 445, 3389}
        high_risk_services = {'smb', 'netbios', 'rpc', 'ftp'}
        
        if port in high_risk_ports or service.lower() in high_risk_services:
            return 'High'
        elif port in {21, 23, 80, 443}:
            return 'Medium'
        else:
            return 'Low'
            
    @staticmethod
    def structure_results(raw_results: List[Dict]) -> List[Dict]:
        """Structure raw results for display"""
        structured = []
        
        for result in raw_results:
            structured_result = {
                'port': result.get('port', 0),
                'protocol': result.get('protocol', 'tcp'),
                'service': result.get('service', 'unknown').upper(),
                'version': result.get('version', ''),
                'state': result.get('state', 'unknown'),
                'risk': result.get('risk', 'Low'),
                'banner': result.get('banner', ''),
                'additional_info': result.get('info', {})
            }
            
            structured.append(structured_result)
            
        return structured
        
    @staticmethod
    def generate_summary(results: List[Dict]) -> Dict:
        """Generate scan summary"""
        if not results:
            return {'total': 0, 'open_ports': 0, 'risk_counts': {}}
            
        open_ports = len([r for r in results if r.get('state') == 'open'])
        
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        for result in results:
            risk = result.get('risk', 'Low')
            if risk in risk_counts:
                risk_counts[risk] += 1
                
        return {
            'total_ports_scanned': len(results),
            'open_ports': open_ports,
            'risk_distribution': risk_counts,
            'top_services': ScanParser.get_top_services(results)
        }
        
    @staticmethod
    def get_top_services(results: List[Dict], count: int = 5) -> List[str]:
        """Get most common services"""
        service_counts = {}
        for result in results:
            service = result.get('service', 'unknown')
            service_counts[service] = service_counts.get(service, 0) + 1
            
        sorted_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)
        return [service for service, count in sorted_services[:count]]