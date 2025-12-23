"""
Session management for the framework
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

class SessionManager:
    """Manages framework sessions"""
    
    def __init__(self, sessions_dir: str = "data/sessions"):
        self.sessions_dir = sessions_dir
        self.current_session = None
        self.sessions = []
        
        # Create directories if they don't exist
        os.makedirs(sessions_dir, exist_ok=True)
        
    def create_session(self, target_ip: str, description: str = "") -> str:
        """Create a new session"""
        session_id = f"SESS_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        session_data = {
            'id': session_id,
            'created': datetime.now().isoformat(),
            'target_ip': target_ip,
            'description': description,
            'scan_results': [],
            'vulnerabilities': [],
            'exploits': [],
            'recommendations': [],
            'status': 'active'
        }
        
        self.current_session = session_data
        self.sessions.append(session_data)
        
        # Save session
        self.save_session(session_id)
        
        return session_id
        
    def save_session(self, session_id: str = None):
        """Save session to file"""
        if session_id is None and self.current_session:
            session_id = self.current_session['id']
            
        if not session_id:
            raise ValueError("No session to save")
            
        session_data = self.get_session(session_id)
        if not session_data:
            raise ValueError(f"Session {session_id} not found")
            
        filename = os.path.join(self.sessions_dir, f"{session_id}.json")
        
        with open(filename, 'w') as f:
            json.dump(session_data, f, indent=2, default=str)
            
    def load_session(self, session_id: str) -> Dict:
        """Load session from file"""
        filename = os.path.join(self.sessions_dir, f"{session_id}.json")
        
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Session file {filename} not found")
            
        with open(filename, 'r') as f:
            session_data = json.load(f)
            
        self.current_session = session_data
        return session_data
        
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by ID"""
        if self.current_session and self.current_session['id'] == session_id:
            return self.current_session
            
        for session in self.sessions:
            if session['id'] == session_id:
                return session
                
        # Try to load from file
        try:
            return self.load_session(session_id)
        except:
            return None
            
    def update_session(self, updates: Dict):
        """Update current session"""
        if not self.current_session:
            raise ValueError("No active session")
            
        self.current_session.update(updates)
        self.save_session()
        
    def add_scan_results(self, results: List[Dict]):
        """Add scan results to current session"""
        if not self.current_session:
            raise ValueError("No active session")
            
        self.current_session['scan_results'] = results
        self.current_session['last_scan'] = datetime.now().isoformat()
        self.save_session()
        
    def add_vulnerability(self, vulnerability: Dict):
        """Add vulnerability to current session"""
        if not self.current_session:
            raise ValueError("No active session")
            
        if 'vulnerabilities' not in self.current_session:
            self.current_session['vulnerabilities'] = []
            
        self.current_session['vulnerabilities'].append(vulnerability)
        self.save_session()
        
    def add_exploit_result(self, exploit_data: Dict):
        """Add exploit result to current session"""
        if not self.current_session:
            raise ValueError("No active session")
            
        if 'exploits' not in self.current_session:
            self.current_session['exploits'] = []
            
        self.current_session['exploits'].append(exploit_data)
        self.save_session()
        
    def add_recommendation(self, recommendation: Dict):
        """Add recommendation to current session"""
        if not self.current_session:
            raise ValueError("No active session")
            
        if 'recommendations' not in self.current_session:
            self.current_session['recommendations'] = []
            
        self.current_session['recommendations'].append(recommendation)
        self.save_session()
        
    def list_sessions(self) -> List[Dict]:
        """List all sessions"""
        sessions = []
        
        # Load from files
        for filename in os.listdir(self.sessions_dir):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(self.sessions_dir, filename), 'r') as f:
                        session_data = json.load(f)
                        sessions.append({
                            'id': session_data.get('id'),
                            'created': session_data.get('created'),
                            'target_ip': session_data.get('target_ip'),
                            'description': session_data.get('description'),
                            'status': session_data.get('status', 'unknown')
                        })
                except:
                    continue
                    
        return sorted(sessions, key=lambda x: x.get('created', ''), reverse=True)
        
    def close_session(self):
        """Close current session"""
        if self.current_session:
            self.current_session['status'] = 'closed'
            self.current_session['closed'] = datetime.now().isoformat()
            self.save_session()
            self.current_session = None