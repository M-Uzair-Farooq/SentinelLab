"""
Attack tab for reconnaissance and exploitation
"""

import json
import time
from datetime import datetime
from gui.meterpreter_shell import MeterpreterShell

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QProgressBar, QTreeWidget, QTreeWidgetItem,
    QSplitter, QComboBox, QHeaderView, QMessageBox, QGridLayout,
    QTabWidget, QScrollArea, QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QBrush

from core.logger import setup_logger
from recon.scanner import NetworkScanner
from exploit.exploit_controller import ExploitController
from gui.styles import COLORS

class AttackTab(QWidget):
    """Attack tab for reconnaissance and exploitation operations"""
    
    # Define signals
    scan_started = pyqtSignal()
    exploit_started = pyqtSignal()
    
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.logger = setup_logger()
        self.scanner = NetworkScanner()
        self.exploit_ctrl = ExploitController()
        self.init_ui()
        self.setup_connections()
        
    def init_ui(self):
        """Initialize the attack tab UI"""
        # Create a tab widget for the entire attack tab
        self.main_tab_widget = QTabWidget()
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.main_tab_widget)
        
        # Create the main reconnaissance/exploitation tab
        self.recon_tab = QWidget()
        self.setup_recon_tab()
        self.main_tab_widget.addTab(self.recon_tab, "🎯 Recon & Exploit")
        
        # Create the meterpreter shell tab
        self.meterpreter_shell = MeterpreterShell(self.exploit_ctrl)
        self.main_tab_widget.addTab(self.meterpreter_shell, "🐚 Meterpreter Shell")
        
        # Set tab styles
        self.main_tab_widget.setStyleSheet("""
            QTabBar::tab {
                padding: 8px 15px;
                margin-right: 2px;
                font-weight: bold;
                min-width: 150px;
            }
            QTabBar::tab:first {
                background-color: #2196F3;
                color: white;
            }
            QTabBar::tab:nth-child(2) {
                background-color: #9C27B0;
                color: white;
            }
            QTabBar::tab:selected {
                background-color: #1565C0;
                font-weight: bold;
            }
        """)
        
    def setup_recon_tab(self):
        """Setup the reconnaissance tab content"""
        # Create a scroll area for better viewing on smaller screens
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        recon_widget = QWidget()
        recon_layout = QVBoxLayout(recon_widget)
        
        # Top section: Target input
        target_group = QGroupBox("🎯 Target Configuration")
        target_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12pt;
                color: #FF9800;
                border: 2px solid #FF9800;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        
        target_layout = QGridLayout()
        
        # IP Address input
        target_layout.addWidget(QLabel("Target IP:"), 0, 0)
        self.target_ip_input = QLineEdit()
        self.target_ip_input.setPlaceholderText("e.g., 192.168.56.106 for Metasploitable")
        self.target_ip_input.setMaximumWidth(300)
        self.target_ip_input.setMinimumWidth(250)
        self.target_ip_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                font-size: 11pt;
                border: 1px solid #555;
                border-radius: 4px;
                background-color: #222;
                color: white;
            }
            QLineEdit:focus {
                border: 1px solid #2196F3;
            }
        """)
        target_layout.addWidget(self.target_ip_input, 0, 1)
        
        # Port Range input
        target_layout.addWidget(QLabel("Port Range:"), 0, 2)
        self.port_range_input = QLineEdit()
        self.port_range_input.setText("1-1000")
        self.port_range_input.setMaximumWidth(120)
        self.port_range_input.setMinimumWidth(100)
        self.port_range_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                font-size: 11pt;
                border: 1px solid #555;
                border-radius: 4px;
                background-color: #222;
                color: white;
            }
        """)
        target_layout.addWidget(self.port_range_input, 0, 3)
        
        # Scan button
        self.scan_button = QPushButton("🚀 Start Reconnaissance")
        self.scan_button.setMaximumWidth(220)
        self.scan_button.setMinimumWidth(200)
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 10px 15px;
                border-radius: 6px;
                font-size: 11pt;
                border: none;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
            QPushButton:disabled {
                background-color: #757575;
                color: #BBB;
            }
        """)
        target_layout.addWidget(self.scan_button, 0, 4)
        
        # Quick IP buttons
        target_layout.addWidget(QLabel("Quick Targets:"), 1, 0)
        
        quick_ip_layout = QHBoxLayout()
        
        # Metasploitable button
        self.quick_metasploitable_btn = QPushButton("192.168.56.106")
        self.quick_metasploitable_btn.setMaximumWidth(220)
        self.quick_metasploitable_btn.clicked.connect(lambda: self.set_ip("192.168.56.106"))
        self.quick_metasploitable_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                padding: 6px 10px;
                border-radius: 4px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        quick_ip_layout.addWidget(self.quick_metasploitable_btn)
        
        # Windows 7 button
        self.quick_win7_btn = QPushButton("192.168.56.113")
        self.quick_win7_btn.setMaximumWidth(220)
        self.quick_win7_btn.clicked.connect(lambda: self.set_ip("192.168.56.113"))
        self.quick_win7_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 6px 10px;
                border-radius: 4px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        quick_ip_layout.addWidget(self.quick_win7_btn)
        
        # Kali button (for testing)
        self.quick_kali_btn = QPushButton("192.168.56.112")
        self.quick_kali_btn.setMaximumWidth(180)
        self.quick_kali_btn.clicked.connect(lambda: self.set_ip("192.168.56.112"))
        self.quick_kali_btn.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: white;
                padding: 6px 10px;
                border-radius: 4px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: #616161;
            }
        """)
        quick_ip_layout.addWidget(self.quick_kali_btn)
        
        quick_ip_layout.addStretch()
        target_layout.addLayout(quick_ip_layout, 1, 1, 1, 4)
        
        target_group.setLayout(target_layout)
        recon_layout.addWidget(target_group)
        
        # Middle section: Results display with larger panels
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #555;
            }
            QSplitter::handle:hover {
                background-color: #777;
            }
        """)
        
        # Scan results table - LARGER PANEL
        results_group = QGroupBox("📡 Reconnaissance Results")
        results_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12pt;
                color: #2196F3;
                border: 2px solid #2196F3;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        results_layout = QVBoxLayout()
        
        # Create a frame for the table with scrollbars
        table_frame = QFrame()
        table_frame.setStyleSheet("""
            QFrame {
                border: 1px solid #444;
                border-radius: 4px;
                background-color: #1A1A1A;
            }
        """)
        table_layout = QVBoxLayout(table_frame)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)  # Added Platform column
        self.results_table.setHorizontalHeaderLabels([
            "Port", "Protocol", "Service", "Version", "State", "Risk", "Platform"
        ])
        
        # Style the table header
        header = self.results_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setDefaultAlignment(Qt.AlignCenter)
        
        # Set minimum column widths for better readability
        self.results_table.setMinimumHeight(250)
        self.results_table.setColumnWidth(0, 70)   # Port
        self.results_table.setColumnWidth(1, 90)   # Protocol
        self.results_table.setColumnWidth(2, 160)  # Service
        self.results_table.setColumnWidth(3, 250)  # Version
        self.results_table.setColumnWidth(4, 80)   # State
        self.results_table.setColumnWidth(5, 100)  # Risk
        self.results_table.setColumnWidth(6, 100)  # Platform
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #444;
                font-size: 11pt;
                selection-background-color: #333;
                selection-color: white;
                background-color: #1A1A1A;
                alternate-background-color: #222;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QHeaderView::section {
                background-color: #333;
                color: white;
                font-weight: bold;
                padding: 6px;
                border: 1px solid #555;
            }
            QTableWidget::item:selected {
                background-color: #1565C0;
            }
        """)
        
        table_layout.addWidget(self.results_table)
        results_layout.addWidget(table_frame)
        
        # Add scan summary label
        self.scan_summary_label = QLabel("No scan performed yet")
        self.scan_summary_label.setStyleSheet("""
            color: #FF9800;
            padding: 10px;
            font-size: 11pt;
            font-weight: bold;
            background-color: #222;
            border-radius: 4px;
            border: 1px solid #444;
        """)
        self.scan_summary_label.setAlignment(Qt.AlignCenter)
        results_layout.addWidget(self.scan_summary_label)
        
        results_group.setLayout(results_layout)
        splitter.addWidget(results_group)
        
        # Vulnerability tree - LARGER PANEL
        vuln_group = QGroupBox("⚠️ Identified Vulnerabilities")
        vuln_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12pt;
                color: #F44336;
                border: 2px solid #F44336;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        vuln_layout = QVBoxLayout()
        
        self.vuln_tree = QTreeWidget()
        self.vuln_tree.setHeaderLabels(["Vulnerability", "Severity", "Service", "Port", "CVE", "Platform"])
        self.vuln_tree.setMinimumHeight(200)
        
        # Set column widths
        self.vuln_tree.setColumnWidth(0, 280)  # Vulnerability
        self.vuln_tree.setColumnWidth(1, 100)  # Severity
        self.vuln_tree.setColumnWidth(2, 120)  # Service
        self.vuln_tree.setColumnWidth(3, 70)   # Port
        self.vuln_tree.setColumnWidth(4, 120)  # CVE
        self.vuln_tree.setColumnWidth(5, 100)  # Platform
        
        self.vuln_tree.setStyleSheet("""
            QTreeWidget {
                font-size: 11pt;
                background-color: #1A1A1A;
                border: 1px solid #444;
                border-radius: 4px;
            }
            QTreeWidget::item {
                padding: 6px;
                border-bottom: 1px solid #333;
            }
            QTreeWidget::item:selected {
                background-color: #B71C1C;
                color: white;
            }
            QHeaderView::section {
                background-color: #333;
                color: white;
                font-weight: bold;
                padding: 6px;
                border: 1px solid #555;
            }
        """)
        
        vuln_layout.addWidget(self.vuln_tree)
        
        # Vulnerability details - Larger text area
        self.vuln_details_label = QLabel("Select a vulnerability for details")
        self.vuln_details_label.setStyleSheet("""
            color: #CCC;
            padding: 12px;
            font-size: 11pt;
            background-color: #222;
            border-radius: 6px;
            border: 1px solid #444;
            min-height: 80px;
        """)
        self.vuln_details_label.setWordWrap(True)
        self.vuln_details_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        vuln_layout.addWidget(self.vuln_details_label)
        
        vuln_group.setLayout(vuln_layout)
        splitter.addWidget(vuln_group)
        
        # Exploitation panel - LARGER PANEL
        exploit_group = QGroupBox("💥 Exploitation")
        exploit_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12pt;
                color: #FF9800;
                border: 2px solid #FF9800;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        exploit_layout = QVBoxLayout()
        
        # Exploit selection with larger combo box
        exploit_select_layout = QHBoxLayout()
        exploit_select_layout.addWidget(QLabel("Select Exploit:"))
        
        self.exploit_combo = QComboBox()
        self.exploit_combo.setMinimumWidth(300)
        self.exploit_combo.setMaximumWidth(400)
        self.exploit_combo.addItems([
            "--- Windows Exploits ---",
            "MS17-010 (EternalBlue)",
            "MS08-067 (NetAPI)",
            "SMB Login Bruteforce",
            "--- Metasploitable Exploits ---",
            "vsftpd 2.3.4 Backdoor",
            "Samba usermap_script",
            "PHP CGI Argument Injection",
            "Telnet Login",
            "DistCC Daemon RCE",
            "UnrealIRCd Backdoor"
        ])
        self.exploit_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                font-size: 11pt;
                border: 1px solid #555;
                border-radius: 4px;
                background-color: #222;
                color: white;
                min-height: 30px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 8px solid white;
            }
            QComboBox QAbstractItemView {
                background-color: #222;
                color: white;
                selection-background-color: #1565C0;
                border: 1px solid #555;
            }
        """)
        exploit_select_layout.addWidget(self.exploit_combo)
        
        self.exploit_button = QPushButton("🚨 Attempt Exploitation")
        self.exploit_button.setMinimumWidth(200)
        self.exploit_button.setMaximumWidth(220)
        self.exploit_button.setEnabled(False)
        self.exploit_button.setStyleSheet("""
            QPushButton {
                background-color: #F44336;
                color: white;
                font-weight: bold;
                padding: 10px 15px;
                border-radius: 6px;
                font-size: 11pt;
                border: none;
            }
            QPushButton:hover {
                background-color: #D32F2F;
            }
            QPushButton:pressed {
                background-color: #C62828;
            }
            QPushButton:disabled {
                background-color: #757575;
                color: #BBB;
            }
        """)
        exploit_select_layout.addWidget(self.exploit_button)
        
        exploit_select_layout.addStretch()
        exploit_layout.addLayout(exploit_select_layout)
        
        # Session info - Larger display
        session_layout = QHBoxLayout()
        
        self.session_label = QLabel("🔒 No active session")
        self.session_label.setStyleSheet("""
            color: #FF9800;
            font-weight: bold;
            padding: 12px;
            background-color: #222;
            border-radius: 8px;
            border: 2px solid #555;
            font-size: 11pt;
            min-height: 60px;
        """)
        self.session_label.setAlignment(Qt.AlignCenter)
        session_layout.addWidget(self.session_label)
        
        session_layout.addStretch()
        
        # Session actions
        self.clear_session_btn = QPushButton("🗑️ Clear Session")
        self.clear_session_btn.clicked.connect(self.clear_session)
        self.clear_session_btn.setEnabled(False)
        self.clear_session_btn.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: white;
                padding: 10px 15px;
                border-radius: 6px;
                font-size: 11pt;
                border: none;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #424242;
            }
            QPushButton:disabled {
                background-color: #333;
                color: #666;
            }
        """)
        session_layout.addWidget(self.clear_session_btn)
        
        exploit_layout.addLayout(session_layout)
        
        # Exploit output - Larger text area
        self.exploit_output = QTextEdit()
        self.exploit_output.setReadOnly(True)
        self.exploit_output.setMinimumHeight(180)
        self.exploit_output.setMaximumHeight(220)
        self.exploit_output.setStyleSheet("""
            QTextEdit {
                font-family: 'Courier New', monospace;
                font-size: 10pt;
                background-color: #111;
                color: #0F0;
                border: 2px solid #444;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        exploit_layout.addWidget(self.exploit_output)
        
        exploit_group.setLayout(exploit_layout)
        splitter.addWidget(exploit_group)
        
        # Set splitter sizes for larger panels
        splitter.setSizes([400, 350, 300])
        
        recon_layout.addWidget(splitter, 1)  # Add stretch factor
        
        # Bottom section: Status and progress
        status_layout = QHBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimumHeight(25)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #444;
                border-radius: 6px;
                text-align: center;
                background-color: #222;
                color: white;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                border-radius: 4px;
            }
        """)
        status_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("🟢 Ready to scan")
        self.status_label.setStyleSheet("""
            color: #4CAF50;
            font-weight: bold;
            padding: 10px;
            font-size: 11pt;
            background-color: #222;
            border-radius: 6px;
            border: 1px solid #444;
            min-width: 250px;
        """)
        self.status_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.clear_button = QPushButton("🗑️ Clear Results")
        self.clear_button.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: white;
                padding: 10px 20px;
                border-radius: 6px;
                font-size: 11pt;
                border: none;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #424242;
            }
        """)
        self.clear_button.clicked.connect(self.clear_results)
        status_layout.addWidget(self.clear_button)
        
        recon_layout.addLayout(status_layout)
        
        # Set the scroll widget
        scroll.setWidget(recon_widget)
        
        # Add scroll area to recon tab
        recon_tab_layout = QVBoxLayout(self.recon_tab)
        recon_tab_layout.addWidget(scroll)
        
    def setup_connections(self):
        """Setup signal-slot connections"""
        self.scan_button.clicked.connect(self.start_scan)
        self.exploit_button.clicked.connect(self.attempt_exploit)
        self.vuln_tree.itemClicked.connect(self.on_vulnerability_selected)
        
        # Connect combo box to update button state
        self.exploit_combo.currentTextChanged.connect(self.update_exploit_button_state)
        
    def update_exploit_button_state(self, text):
        """Enable/disable exploit button based on selection"""
        # Don't enable for separator items
        if "---" in text:
            self.exploit_button.setEnabled(False)
        else:
            # Check if we have vulnerabilities in the tree
            has_vulns = self.vuln_tree.topLevelItemCount() > 0
            self.exploit_button.setEnabled(has_vulns)
        
    def set_ip(self, ip_address):
        """Set IP address from quick button"""
        self.target_ip_input.setText(ip_address)
        self.status_label.setText(f"🟡 IP set to {ip_address}")
        
        # Update status label color based on target type
        if "metasploitable" in ip_address.lower():
            self.status_label.setStyleSheet("""
                color: #9C27B0;
                font-weight: bold;
                padding: 10px;
                font-size: 11pt;
                background-color: #222;
                border-radius: 6px;
                border: 1px solid #444;
            """)
        elif "windows" in ip_address.lower():
            self.status_label.setStyleSheet("""
                color: #2196F3;
                font-weight: bold;
                padding: 10px;
                font-size: 11pt;
                background-color: #222;
                border-radius: 6px;
                border: 1px solid #444;
            """)
        else:
            self.status_label.setStyleSheet("""
                color: #4CAF50;
                font-weight: bold;
                padding: 10px;
                font-size: 11pt;
                background-color: #222;
                border-radius: 6px;
                border: 1px solid #444;
            """)
        
    def validate_ip(self, ip_address):
        """Validate IP address is in allowed range"""
        if not ip_address:
            return False, "❌ Please enter an IP address"
            
        # Basic IP validation
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False, "❌ Invalid IP format (should be X.X.X.X)"
            
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False, "❌ Invalid IP range (0-255)"
                    
            # Check for lab IP ranges
            if not (ip_address.startswith("192.168.56.") or 
                   ip_address.startswith("10.0.") or
                   ip_address.startswith("172.16.")):
                warning_msg = (
                    "⚠️  WARNING  ⚠️\n\n"
                    "IP address not in typical lab ranges:\n"
                    f"Target: {ip_address}\n\n"
                    "Allowed ranges:\n"
                    "• 192.168.56.0/24 (VirtualBox)\n"
                    "• 10.0.0.0/24 (Internal)\n"
                    "• 172.16.0.0/24 (Internal)\n\n"
                    "Ensure this is a controlled lab environment!"
                )
                
                reply = QMessageBox.warning(
                    self, '⚠️ Security Warning',
                    warning_msg,
                    QMessageBox.Cancel,
                    QMessageBox.Cancel
                )
                
                if reply == QMessageBox.Cancel:
                    return False, "Scan cancelled by user"
                    
            return True, "✅ Valid IP address"
            
        except ValueError:
            return False, "❌ Invalid IP format (numbers only)"
            
    def start_scan(self):
        """Start reconnaissance scan"""
        ip_address = self.target_ip_input.text().strip()
        
        valid, message = self.validate_ip(ip_address)
        if not valid:
            QMessageBox.critical(self, "❌ Error", message)
            return
            
        # Emit scan started signal
        self.scan_started.emit()
            
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText("🟡 Scanning target...")
        self.scan_button.setEnabled(False)
        self.exploit_button.setEnabled(False)
        
        # Start scan in separate thread
        self.scan_thread = ScanThread(ip_address, self.port_range_input.text())
        self.scan_thread.scan_completed.connect(self.on_scan_completed)
        self.scan_thread.error_occurred.connect(self.on_scan_error)
        self.scan_thread.progress_update.connect(self.on_scan_progress)
        self.scan_thread.start()
        
    def on_scan_progress(self, progress):
        """Handle scan progress updates"""
        if progress == "complete":
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
        else:
            self.status_label.setText(f"🟡 {progress}")
            
    def on_scan_completed(self, results):
        """Handle scan completion"""
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        
        # Update scan summary
        open_ports = len(results)
        high_risk = sum(1 for r in results if r.get('risk') in ['High', 'Critical'])
        
        self.scan_summary_label.setText(
            f"🔍 Scan completed: {open_ports} open ports | {high_risk} high-risk services"
        )
        self.status_label.setText(f"✅ Scan completed: Found {open_ports} services")
        
        # Update results table
        self.update_results_table(results)
        
        # Update vulnerability tree
        self.update_vulnerability_tree(results)
        
        # Enable exploit button if vulnerabilities found
        if self.vuln_tree.topLevelItemCount() > 0:
            current_text = self.exploit_combo.currentText()
            if "---" not in current_text:
                self.exploit_button.setEnabled(True)
            self.status_label.setText(f"✅ Found {self.vuln_tree.topLevelItemCount()} vulnerabilities")
            
    def on_scan_error(self, error):
        """Handle scan error"""
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        self.status_label.setText("❌ Scan failed")
        self.scan_summary_label.setText("Scan failed - Check connection and IP")
        QMessageBox.critical(self, "❌ Scan Error", str(error))
        
    def update_results_table(self, results):
        """Update the results table with scan data"""
        self.results_table.setRowCount(len(results))
        
        for i, result in enumerate(results):
            # Get data
            port = str(result.get('port', ''))
            protocol = result.get('protocol', 'tcp')
            service = result.get('service', 'Unknown')
            version = result.get('version', '')
            state = result.get('state', 'open')
            risk = result.get('risk', 'Low')
            
            # Platform detection
            platform = 'Unknown'
            service_lower = service.lower()
            if any(x in service_lower for x in ['ftp', 'ssh', 'telnet', 'apache', 'php', 'mysql']):
                platform = 'Linux'
            elif any(x in service_lower for x in ['smb', 'netbios', 'msrpc', 'microsoft']):
                platform = 'Windows'
            
            # Create items
            port_item = QTableWidgetItem(port)
            proto_item = QTableWidgetItem(protocol.upper())
            service_item = QTableWidgetItem(service.upper())
            version_item = QTableWidgetItem(version)
            state_item = QTableWidgetItem(state.upper())
            risk_item = QTableWidgetItem(risk)
            platform_item = QTableWidgetItem(platform)
            
            # Set alignments
            port_item.setTextAlignment(Qt.AlignCenter)
            proto_item.setTextAlignment(Qt.AlignCenter)
            state_item.setTextAlignment(Qt.AlignCenter)
            risk_item.setTextAlignment(Qt.AlignCenter)
            platform_item.setTextAlignment(Qt.AlignCenter)
            
            # Set colors based on risk
            if risk == 'Critical':
                risk_color = QColor('#D32F2F')
                bg_color = QBrush(QColor('#330000'))
                row_bg_color = QBrush(QColor('#1A0000'))
            elif risk == 'High':
                risk_color = QColor('#F44336')
                bg_color = QBrush(QColor('#330000'))
                row_bg_color = QBrush(QColor('#220000'))
            elif risk == 'Medium':
                risk_color = QColor('#FF9800')
                bg_color = QBrush(QColor('#332200'))
                row_bg_color = QBrush(QColor('#221100'))
            else:
                risk_color = QColor('#4CAF50')
                bg_color = QBrush(QColor('#003300'))
                row_bg_color = QBrush(QColor('#002200'))
            
            # Apply risk color to risk item
            risk_item.setForeground(risk_color)
            risk_item.setBackground(bg_color)
            
            # Apply platform color
            if platform == 'Windows':
                platform_item.setForeground(QColor('#2196F3'))
            elif platform == 'Linux':
                platform_item.setForeground(QColor('#9C27B0'))
            
            # Add items to table
            self.results_table.setItem(i, 0, port_item)
            self.results_table.setItem(i, 1, proto_item)
            self.results_table.setItem(i, 2, service_item)
            self.results_table.setItem(i, 3, version_item)
            self.results_table.setItem(i, 4, state_item)
            self.results_table.setItem(i, 5, risk_item)
            self.results_table.setItem(i, 6, platform_item)
            
            # Apply background color to all cells in the row (except risk cell)
            if risk in ['Critical', 'High', 'Medium']:
                for col in range(7):
                    if col != 5:  # Skip risk column
                        item = self.results_table.item(i, col)
                        if item:
                            item.setBackground(row_bg_color)
    
        self.results_table.resizeColumnsToContents()
        
    def update_vulnerability_tree(self, results):
        """Update vulnerability tree with identified vulnerabilities"""
        self.vuln_tree.clear()
        
        # Map services to vulnerabilities
        vulnerabilities = self.controller.map_vulnerabilities(results)
        
        for vuln in vulnerabilities:
            item = QTreeWidgetItem(self.vuln_tree)
            item.setText(0, vuln.get('name', 'Unknown'))
            item.setText(1, vuln.get('severity', 'Low'))
            item.setText(2, vuln.get('service', ''))
            item.setText(3, str(vuln.get('port', '')))
            item.setText(4, vuln.get('cve', 'N/A'))
            
            # Platform detection
            platform = vuln.get('platform', 'Unknown')
            if 'windows' in vuln.get('name', '').lower() or 'ms' in vuln.get('name', '').lower():
                platform = 'Windows'
            elif any(x in vuln.get('name', '').lower() for x in ['ftp', 'samba', 'php', 'telnet', 'distcc', 'irc']):
                platform = 'Linux'
            item.setText(5, platform)
            
            # Store full vulnerability data
            item.setData(0, Qt.UserRole, vuln)
            
            # Color code by severity and platform
            severity = vuln.get('severity', 'Low')
            if severity == 'Critical':
                for col in range(6):
                    item.setForeground(col, QColor('#FF5252'))
                    item.setBackground(col, QBrush(QColor('#330000')))
            elif severity == 'High':
                for col in range(6):
                    item.setForeground(col, QColor('#FF9800'))
                    item.setBackground(col, QBrush(QColor('#332200')))
            elif severity == 'Medium':
                for col in range(6):
                    item.setForeground(col, QColor('#FFEB3B'))
                    item.setBackground(col, QBrush(QColor('#333300')))
            else:
                for col in range(6):
                    if col == 5:  # Platform column
                        if platform == 'Windows':
                            item.setForeground(col, QColor('#2196F3'))
                        elif platform == 'Linux':
                            item.setForeground(col, QColor('#9C27B0'))
                    else:
                        item.setForeground(col, QColor('#8BC34A'))
                    
        # Auto-select first vulnerability if any
        if self.vuln_tree.topLevelItemCount() > 0:
            self.vuln_tree.setCurrentItem(self.vuln_tree.topLevelItem(0))
            self.on_vulnerability_selected(self.vuln_tree.topLevelItem(0), 0)
            
    def on_vulnerability_selected(self, item, column):
        """Handle vulnerability selection"""
        vuln_data = item.data(0, Qt.UserRole)
        if vuln_data:
            # Add exploit recommendations
            exploit_recs = []
            vuln_name = vuln_data.get('name', '').lower()
            
            if any(x in vuln_name for x in ['vsftpd', 'ftp']):
                exploit_recs.append("vsftpd 2.3.4 Backdoor")
            if any(x in vuln_name for x in ['samba', 'smb']):
                exploit_recs.append("Samba usermap_script")
            if any(x in vuln_name for x in ['telnet']):
                exploit_recs.append("Telnet Login")
            if any(x in vuln_name for x in ['php']):
                exploit_recs.append("PHP CGI Argument Injection")
            if any(x in vuln_name for x in ['ms17', 'eternalblue']):
                exploit_recs.append("MS17-010 (EternalBlue)")
            if any(x in vuln_name for x in ['ms08', 'netapi']):
                exploit_recs.append("MS08-067 (NetAPI)")
            
            exploit_text = "<br><b>Recommended Exploits:</b> " + ", ".join(exploit_recs) if exploit_recs else ""
            
            details = (
                f"<b>{vuln_data.get('name', 'Unknown')}</b><br>"
                f"<b>Severity:</b> {vuln_data.get('severity', 'Low')}<br>"
                f"<b>Service:</b> {vuln_data.get('service', '')}:{vuln_data.get('port', '')}<br>"
                f"<b>CVE:</b> {vuln_data.get('cve', 'N/A')}<br>"
                f"<b>Description:</b> {vuln_data.get('description', '')}<br>"
                f"<b>Impact:</b> {vuln_data.get('impact', '')}"
                f"{exploit_text}"
            )
            self.vuln_details_label.setText(details)
            
    def attempt_exploit(self):
        """Attempt controlled exploitation"""
        selected_item = self.vuln_tree.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "⚠️ Warning", "Please select a vulnerability first")
            return
            
        # Get selected exploit from combo box
        exploit_name = self.exploit_combo.currentText()
        if "---" in exploit_name:
            QMessageBox.warning(self, "⚠️ Warning", "Please select a valid exploit from the dropdown")
            return
            
        # Get port from selected vulnerability
        port = 0
        port_text = selected_item.text(3)
        if port_text.isdigit():
            port = int(port_text)
        
        # If no port from vulnerability OR it's wrong for the exploit, use defaults
        if port == 0 or self.is_wrong_port_for_exploit(exploit_name, port):
            # Use correct default ports for each exploit
            if 'vsftpd' in exploit_name.lower():
                port = 21
            elif 'samba' in exploit_name.lower():
                port = 139  # Samba default port
            elif 'telnet' in exploit_name.lower():
                port = 23
            elif 'php' in exploit_name.lower():
                port = 80
            elif 'distcc' in exploit_name.lower():
                port = 3632
            elif 'irc' in exploit_name.lower():
                port = 6667
            elif any(x in exploit_name.lower() for x in ['ms17', 'ms08', 'smb']):
                port = 445  # SMB port for Windows exploits
        
        # Emit exploit started signal
        self.exploit_started.emit()
            
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText(f"🟡 Attempting: {exploit_name}")
        self.exploit_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] 🔥 Starting {exploit_name} exploit...")
        self.exploit_output.append(f"[*] Target: {self.target_ip_input.text().strip()}:{port}")
        
        # Start exploit in separate thread
        self.exploit_thread = ExploitThread(
            self.target_ip_input.text().strip(),
            exploit_name,
            port
        )
        self.exploit_thread.exploit_completed.connect(self.on_exploit_completed)
        self.exploit_thread.output_received.connect(self.on_exploit_output)
        self.exploit_thread.start()

    def is_wrong_port_for_exploit(self, exploit_name, port):
        """Check if port is wrong for the selected exploit"""
        exploit_name = exploit_name.lower()
        
        if 'vsftpd' in exploit_name and port != 21:
            return True
        elif 'samba' in exploit_name and port not in [139, 445]:
            return True
        elif 'telnet' in exploit_name and port != 23:
            return True
        elif 'php' in exploit_name and port != 80:
            return True
        elif 'distcc' in exploit_name and port != 3632:
            return True
        elif 'irc' in exploit_name and port != 6667:
            return True
        elif any(x in exploit_name for x in ['ms17', 'ms08', 'smb']) and port != 445:
            return True
        
        return False
        
    def on_exploit_completed(self, success, session_data):
        """Handle exploit completion"""
        self.progress_bar.setVisible(False)
        
        if success:
            platform = session_data.get('platform', 'unknown')
            session_type = session_data.get('session_type', 'unknown')
            
            self.status_label.setText(f"✅ {platform.capitalize()} exploit successful!")
            
            if platform == 'linux':
                # Special handling for vsftpd
                if session_data.get('vsftpd', False):
                    self.session_label.setText(
                        f"🟢 VSFTPD BACKDOOR ACTIVE\n"
                        f"Backdoor port: 6200\n"
                        f"User: {session_data.get('user', 'root')}\n"
                        f"Shell ready on port 6200"
                    )
                else:
                    self.session_label.setText(
                        f"🟢 LINUX SHELL ACTIVE\n"
                        f"Session: {session_data.get('id', 'N/A')}\n"
                        f"User: {session_data.get('user', 'root')}\n"
                        f"Type: {session_type}"
                    )
            else:
                self.session_label.setText(
                    f"🟢 WINDOWS SESSION ACTIVE\n"
                    f"Session: {session_data.get('id', 'N/A')}\n"
                    f"User: {session_data.get('user', 'SYSTEM')}\n"
                    f"Privilege: {session_data.get('privilege', 'High')}"
                )
            
            self.session_label.setStyleSheet("""
                color: #4CAF50;
                font-weight: bold;
                padding: 12px;
                background-color: #003300;
                border-radius: 8px;
                border: 2px solid #4CAF50;
                font-size: 11pt;
                min-height: 60px;
            """)
            self.clear_session_btn.setEnabled(True)
            
            # Switch to meterpreter shell tab
            self.main_tab_widget.setCurrentIndex(1)
            
            # Set session in shell
            self.meterpreter_shell.set_session(session_data)
            
            # Add to controller
            self.controller.add_session(session_data)
            
        else:
            self.status_label.setText("❌ Exploit failed")
            self.session_label.setText("🔒 No active session")
            self.session_label.setStyleSheet("""
                color: #FF9800;
                font-weight: bold;
                padding: 12px;
                background-color: #333;
                border-radius: 8px;
                border: 2px solid #555;
                font-size: 11pt;
                min-height: 60px;
            """)

    def on_exploit_output(self, message):
        """Handle exploit output messages"""
        self.exploit_output.append(message)
        # Auto-scroll to bottom
        scrollbar = self.exploit_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def clear_session(self):
        """Clear current session"""
        self.session_label.setText("🔒 No active session")
        self.session_label.setStyleSheet("""
            color: #FF9800;
            font-weight: bold;
            padding: 12px;
            background-color: #333;
            border-radius: 8px;
            border: 2px solid #555;
            font-size: 11pt;
            min-height: 60px;
        """)
        self.clear_session_btn.setEnabled(False)
        self.exploit_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] Session cleared")
        self.status_label.setText("🟢 Session cleared")
        
    def update_results(self, results):
        """Update with results from controller"""
        self.update_results_table(results)
        self.update_vulnerability_tree(results)
        
    def update_exploit_status(self, success, session_data):
        """Update exploit status"""
        self.on_exploit_completed(success, session_data)
        
    def clear_results(self):
        """Clear all results"""
        reply = QMessageBox.question(
            self, "🗑️ Clear Results",
            "Clear all scan and exploit results?\n\nThis will reset the Attack tab.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.results_table.setRowCount(0)
            self.vuln_tree.clear()
            self.exploit_output.clear()
            self.session_label.setText("🔒 No active session")
            self.session_label.setStyleSheet("""
                color: #FF9800;
                font-weight: bold;
                padding: 12px;
                background-color: #333;
                border-radius: 8px;
                border: 2px solid #555;
                font-size: 11pt;
                min-height: 60px;
            """)
            self.exploit_button.setEnabled(False)
            self.clear_session_btn.setEnabled(False)
            self.status_label.setText("🟢 Ready to scan")
            self.scan_summary_label.setText("No scan performed yet")
            self.vuln_details_label.setText("Select a vulnerability for details")
            
    def reset(self):
        """Reset the tab"""
        self.clear_results()
        self.target_ip_input.clear()


class ScanThread(QThread):
    """Thread for running scans"""
    
    scan_completed = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    progress_update = pyqtSignal(str)
    
    def __init__(self, target_ip, port_range="1-1000"):
        super().__init__()
        self.target_ip = target_ip
        self.port_range = port_range
        self.scanner = NetworkScanner()
        
    def run(self):
        """Run the scan"""
        try:
            self.progress_update.emit("Initializing scan...")
            
            # Simulate scanning stages for educational purposes
            stages = [
                "Validating target...",
                "Checking connectivity...",
                f"Scanning ports {self.port_range}...",
                "Identifying services...",
                "Analyzing results...",
                "Checking for vulnerabilities..."
            ]
            
            for stage in stages:
                self.progress_update.emit(stage)
                time.sleep(0.5)
            
            results = self.scanner.scan_target(self.target_ip)
            
            self.progress_update.emit("complete")
            self.scan_completed.emit(results)
            
        except Exception as e:
            self.error_occurred.emit(str(e))


class ExploitThread(QThread):
    """Thread for running exploits"""
    
    exploit_completed = pyqtSignal(bool, dict)
    output_received = pyqtSignal(str)
    
    def __init__(self, target_ip, exploit_name, port):
        super().__init__()
        self.target_ip = target_ip
        self.exploit_name = exploit_name
        self.port = port
        self.exploit_ctrl = ExploitController()
        
    def run(self):
        """Run the exploit"""
        try:
            # Show which exploit we're running
            self.output_received.emit(f"[*] Selected Exploit: {self.exploit_name}")
            self.output_received.emit(f"[*] Target: {self.target_ip}:{self.port or 'auto'}")
            
            # Platform detection for status messages
            is_windows = any(x in self.exploit_name.lower() for x in ['ms17', 'ms08', 'eternalblue', 'netapi'])
            is_linux = any(x in self.exploit_name.lower() for x in ['ftp', 'samba', 'php', 'telnet', 'distcc', 'irc'])
            
            if is_windows:
                self.output_received.emit("[*] Platform: Windows")
            elif is_linux:
                self.output_received.emit("[*] Platform: Linux/Metasploitable")
            
            # Simulate exploit stages
            stages = [
                f"Preparing {self.exploit_name}...",
                f"Connecting to {self.target_ip}:{self.port or 'default'}...",
                "Crafting payload...",
                "Sending exploit...",
                "Waiting for response...",
                "Establishing foothold..."
            ]
            
            for stage in stages:
                self.output_received.emit(f"[*] {stage}")
                time.sleep(0.8)
            
            # Pass the port to execute_exploit
            success, session_data = self.exploit_ctrl.execute_exploit(
                self.target_ip, self.exploit_name, self.port
            )
            
            if success:
                self.output_received.emit(f"[+] Exploit successful!")
                self.output_received.emit(f"[+] Session ID: {session_data.get('id', 'N/A')}")
                self.output_received.emit(f"[+] User: {session_data.get('user', 'N/A')}")
                self.output_received.emit(f"[+] Platform: {session_data.get('platform', 'Unknown')}")
                self.output_received.emit(f"[+] Session Type: {session_data.get('session_type', 'Unknown')}")
                
                # Special message for vsftpd
                if session_data.get('vsftpd', False):
                    self.output_received.emit(f"[+] VSFTPD Backdoor active on port 6200")
                    self.output_received.emit(f"[+] Connect manually: nc {self.target_ip} 6200")
            else:
                error_msg = session_data.get('error', 'Target may be patched or service not vulnerable')
                self.output_received.emit(f"[-] Exploit failed: {error_msg}")
                
            self.exploit_completed.emit(success, session_data)
            
        except Exception as e:
            self.output_received.emit(f"[-] Error: {str(e)}")
            self.exploit_completed.emit(False, {})