"""
Main window for the framework
"""

import os
import sys
import threading
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QWidget, QStatusBar,
    QMessageBox, QMenuBar, QMenu, QAction, QLabel
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QIcon

# Import GUI tabs
from gui.attack_tab import AttackTab
from gui.defense_tab import DefenseTab
from gui.report_tab import ReportTab
from gui.styles import STYLESHEET

# Import core modules
from core.controller import FrameworkController
from core.logger import setup_logger

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger()
        self.controller = FrameworkController()
        
        # START MSF RPC DAEMON
        self.start_msfrpcd()
        
        self.init_ui()
        self.setup_connections()
        
    def start_msfrpcd(self):
        """Start Metasploit RPC daemon"""
        try:
            # Import here to avoid circular imports
            from exploit.exploit_controller import ExploitController
            self.exploit_controller = ExploitController()
            
            # Start in background thread
            def start_daemon():
                self.exploit_controller.start_msfrpcd()
            
            thread = threading.Thread(target=start_daemon)
            thread.daemon = True
            thread.start()
            
            # FIXED: Use logger directly, not logger.logger
            self.logger.info("Started MSF RPC daemon")
            
        except Exception as e:
            # FIXED: Use logger directly, not logger.logger
            self.logger.error(f"Failed to start MSF RPC: {e}")
            # Continue even if MSF RPC fails - framework will work without it
            self.logger.warning("Framework will run without Metasploit RPC capabilities")
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Attack-Defense Framework Powered by br4v0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Apply stylesheet
        self.setStyleSheet(STYLESHEET)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        # self.create_menu_bar()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        self.status_bar.addWidget(self.status_label)
        
        # Add a progress label to status bar
        self.progress_label = QLabel("")
        self.status_bar.addPermanentWidget(self.progress_label)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.attack_tab = AttackTab(self.controller)
        self.defense_tab = DefenseTab(self.controller)
        self.report_tab = ReportTab(self.controller)
        
        # Add tabs to widget
        self.tab_widget.addTab(self.attack_tab, "⚔️ Attack")
        self.tab_widget.addTab(self.defense_tab, "🛡️ Defense")
        self.tab_widget.addTab(self.report_tab, "📊 Reports")
        
        # Set tab colors
        self.tab_widget.setStyleSheet("""
            QTabBar::tab:first {
                background-color: #FF5722;
                color: white;
            }
            QTabBar::tab:nth-child(2) {
                background-color: #4CAF50;
                color: white;
            }
            QTabBar::tab:nth-child(3) {
                background-color: #2196F3;
                color: white;
            }
        """)
        
        # Add tab widget to layout
        main_layout.addWidget(self.tab_widget)
        
        # Add copyright label at bottom
        copyright_label = QLabel("© 2025  EHD Project ")
        copyright_label.setAlignment(Qt.AlignCenter)
        copyright_label.setStyleSheet("color: #777; font-size: 9pt; padding: 5px;")
        main_layout.addWidget(copyright_label)
        
        # Update status
        self.update_status("Framework initialized - Ready for operations", "success")
        
    def setup_connections(self):
        """Setup signal-slot connections"""
        # Connect controller signals
        self.controller.scan_completed.connect(self.on_scan_completed)
        self.controller.exploit_completed.connect(self.on_exploit_completed)
        self.controller.defense_updated.connect(self.on_defense_updated)
        
        # Connect tab signals
        if hasattr(self.attack_tab, 'scan_started'):
            self.attack_tab.scan_started.connect(self.on_scan_started)
        if hasattr(self.attack_tab, 'exploit_started'):
            self.attack_tab.exploit_started.connect(self.on_exploit_started)
        
        # Connect defense tab generate button
        self.defense_tab.generate_btn.clicked.connect(
            lambda: self.controller.generate_defense_recommendations()
        )
        
    def update_status(self, message, status_type="info", timeout=5000):
        """Update status bar message with color coding"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_label.setText(f"[{timestamp}] {message}")
        
        # Apply color based on status type
        colors = {
            "success": "#4CAF50",
            "warning": "#FF9800", 
            "error": "#F44336",
            "info": "#2196F3"
        }
        color = colors.get(status_type, "#2196F3")
        self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        
        # Clear message after timeout
        QTimer.singleShot(timeout, lambda: self.status_label.setText("Ready"))
        QTimer.singleShot(timeout, lambda: self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold;"))
        
    def update_progress(self, message):
        """Update progress label"""
        self.progress_label.setText(message)
        
    def on_scan_started(self):
        """Handle scan start"""
        self.update_status("Starting reconnaissance scan...", "info")
        self.update_progress("Scanning...")
        
    def on_exploit_started(self):
        """Handle exploit start"""
        self.update_status("Starting exploitation attempt...", "warning")
        self.update_progress("Exploiting...")
        
    def on_scan_completed(self, results):
        """Handle scan completion"""
        self.update_status(f"Scan completed: Found {len(results)} services", "success")
        self.update_progress("")
        self.attack_tab.update_results(results)
        self.defense_tab.update_vulnerabilities(results)
        
    def on_exploit_completed(self, success, session_data):
        """Handle exploit completion"""
        if success:
            self.update_status(f"Exploit successful! Session: {session_data.get('id', 'N/A')}", "success")
            
            # FORCE GENERATE DEFENSE RECOMMENDATIONS
            try:
                # Give a small delay for data to settle
                QTimer.singleShot(500, self.force_defense_generation)
            except Exception as e:
                self.logger.error(f"Error triggering defense generation: {e}")
        else:
            self.update_status("Exploit failed", "error")
            
        self.attack_tab.update_exploit_status(success, session_data)
    
    def force_defense_generation(self):
        """Force generation of defense recommendations"""
        try:
            # Switch to defense tab
            self.tab_widget.setCurrentIndex(1)
            
            # Generate recommendations
            if hasattr(self.controller, 'generate_defense_recommendations'):
                self.controller.generate_defense_recommendations()
            else:
                # Fallback: call defense tab directly
                self.defense_tab.generate_recommendations()
                
            self.update_status("Defense recommendations generated", "success")
        except Exception as e:
            self.logger.error(f"Failed to generate defense recommendations: {e}")
            self.update_status("Failed to generate defense recommendations", "error")

    def on_defense_updated(self, recommendations):
        """Handle defense updates"""
        self.update_status(f"Generated {len(recommendations)} defense recommendations", "success")
        self.defense_tab.update_recommendations(recommendations)
        
    def new_session(self):
        """Start a new session"""
        reply = QMessageBox.question(
            self, 'New Session',
            'Start a new session? Current data will be lost.',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.controller.reset_session()
            self.attack_tab.reset()
            self.defense_tab.reset()
            self.report_tab.reset()
            self.update_status("New session started", "success")
            
    def save_session(self):
        """Save current session"""
        try:
            filename = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.controller.save_session(filename)
            self.update_status(f"Session saved to data/{filename}", "success")
            QMessageBox.information(self, "Success", f"Session saved successfully!\n\nFile: {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save session: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save session: {str(e)}")
            
    def load_session(self):
        """Load a session from file"""
        from PyQt5.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Session", "data", "JSON Files (*.json)"
        )
        
        if filename:
            try:
                self.controller.load_session(filename)
                self.update_status(f"Session loaded: {os.path.basename(filename)}", "success")
                QMessageBox.information(self, "Success", f"Session loaded successfully!")
            except Exception as e:
                self.logger.error(f"Failed to load session: {e}")
                QMessageBox.critical(self, "Error", f"Failed to load session: {str(e)}")
                
    def export_report(self):
        """Export current report"""
        self.tab_widget.setCurrentIndex(2)  # Switch to Reports tab
        self.report_tab.generate_preview()
        QMessageBox.information(
            self, "Export Report", 
            "Switch to the Reports tab to generate and export your assessment report."
        )
        
    def show_settings(self):
        """Show settings dialog"""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Framework Settings")
        dialog.setGeometry(200, 200, 400, 300)
        
        layout = QVBoxLayout()
        
        # Add settings content
        layout.addWidget(QLabel("Framework Settings"))
        layout.addWidget(QLabel("Version: 1.0.0"))
        layout.addWidget(QLabel("Author: Student Project"))
        layout.addWidget(QLabel("Lab Network: 192.168.56.0/24"))
        
        # Add close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)
        
        dialog.setLayout(layout)
        dialog.exec_()
        
    def show_logs(self):
        """Show log viewer"""
        log_content = ""
        log_file = "logs/framework.log"
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    log_content = f.read()
            else:
                log_content = "No log file found. Logs will be created during operations."
        except Exception as e:
            log_content = f"Error reading log file: {str(e)}"
            
        # Create log viewer dialog
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Framework Logs")
        dialog.setGeometry(200, 200, 800, 600)
        
        layout = QVBoxLayout()
        
        text_edit = QTextEdit()
        text_edit.setPlainText(log_content)
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet("font-family: monospace; font-size: 10pt;")
        
        layout.addWidget(text_edit)
        
        # Add buttons
        button_layout = QVBoxLayout()
        refresh_btn = QPushButton("🔄 Refresh Logs")
        clear_btn = QPushButton("🗑️ Clear Logs")
        close_btn = QPushButton("Close")
        
        def refresh_logs():
            try:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        text_edit.setPlainText(f.read())
                else:
                    text_edit.setPlainText("No log file found.")
            except Exception as e:
                text_edit.setPlainText(f"Error: {str(e)}")
                
        def clear_logs():
            reply = QMessageBox.question(
                dialog, "Clear Logs",
                "Are you sure you want to clear all logs?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                try:
                    with open(log_file, 'w') as f:
                        f.write("")
                    text_edit.setPlainText("Logs cleared.")
                except Exception as e:
                    text_edit.setPlainText(f"Error clearing logs: {str(e)}")
                    
        refresh_btn.clicked.connect(refresh_logs)
        clear_btn.clicked.connect(clear_logs)
        close_btn.clicked.connect(dialog.close)
        
        button_layout.addWidget(refresh_btn)
        button_layout.addWidget(clear_btn)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        dialog.exec_()
        
    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>Educational Attack-Defense Framework v1.0</h2>
        
        <p>A GUI-based framework for demonstrating attack and defense techniques
        in controlled Windows lab environments.</p>
        
        <p><b>⚠️ FOR EDUCATIONAL USE ONLY ⚠️</b></p>
        
        <h3>Features:</h3>
        <ul>
        <li>• Automated reconnaissance</li>
        <li>• Vulnerability mapping</li>
        <li>• Controlled exploitation demo</li>
        <li>• Defense hardening recommendations</li>
        <li>• Report generation</li>
        </ul>
        
        <h3>Lab Requirements:</h3>
        <ul>
        <li>• Windows 7 VM (Target)</li>
        <li>• Kali Linux VM (Attacker)</li>
        <li>• Host-only network: 192.168.56.0/24</li>
        <li>• Isolated virtual environment</li>
        </ul>
        
        <p><b>Author:</b> Student Project<br>
        <b>Course:</b> Cybersecurity Program<br>
        <b>University:</b> Educational Institution</p>
        
        <p style="color: #777; font-size: 10pt;">
        This software is for educational purposes only. 
        Use only in authorized lab environments.
        </p>
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("About Attack-Defense Framework")
        msg.setTextFormat(Qt.RichText)
        msg.setText(about_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()
        
    def show_docs(self):
        """Show documentation"""
        docs_text = """
        <h2>Framework Documentation</h2>
        
        <h3>Quick Start:</h3>
        <ol>
        <li>1. Configure Windows 7 VM with IP: 192.168.56.101</li>
        <li>2. Configure Kali Linux VM with IP: 192.168.56.10</li>
        <li>3. Disable Windows Firewall on Windows 7</li>
        <li>4. Run framework and enter target IP</li>
        <li>5. Follow Attack → Defense → Report workflow</li>
        </ol>
        
        <h3>Attack Tab:</h3>
        <ul>
        <li>• Enter target IP address</li>
        <li>• Click "Start Reconnaissance" to scan</li>
        <li>• View discovered services and vulnerabilities</li>
        <li>• Select vulnerability and click "Attempt Exploitation"</li>
        </ul>
        
        <h3>Defense Tab:</h3>
        <ul>
        <li>• View vulnerability summary</li>
        <li>• Click "Generate Recommendations"</li>
        <li>• Review mitigation steps</li>
        <li>• Follow hardening checklist</li>
        </ul>
        
        <h3>Reports Tab:</h3>
        <ul>
        <li>• Generate assessment reports</li>
        <li>• Export as HTML/PDF</li>
        <li>• Customize report sections</li>
        </ul>
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Framework Documentation")
        msg.setTextFormat(Qt.RichText)
        msg.setText(docs_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()
        
    def show_quick_start(self):
        """Show quick start guide"""
        QMessageBox.information(
            self, "Quick Start Guide",
            "1. Set Windows 7 IP to 192.168.56.101\n"
            "2. Enter IP in Attack tab\n"
            "3. Click 'Start Reconnaissance'\n"
            "4. Review vulnerabilities\n"
            "5. Generate defense recommendations\n"
            "6. Create report\n\n"
            "⚠️ Use only in isolated lab environment!"
        )
        
    def closeEvent(self, event):
        """Handle window close event"""
        reply = QMessageBox.question(
            self, 'Exit Framework',
            'Are you sure you want to exit?\n\nUnsaved data will be lost.',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Stop MSF RPC daemon if running
                if hasattr(self, 'exploit_controller') and self.exploit_controller:
                    self.exploit_controller.stop_msfrpcd()
                
                self.controller.cleanup()
                self.logger.info("Framework shutting down...")
                event.accept()
            except Exception as e:
                self.logger.error(f"Error during cleanup: {e}")
                event.accept()
        else:
            event.ignore()