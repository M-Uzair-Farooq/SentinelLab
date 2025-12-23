"""
Report tab for generating assessment reports
"""

import os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QTextEdit, QPushButton, QComboBox, QFileDialog,
    QListWidget, QListWidgetItem, QCheckBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from core.logger import setup_logger

class ReportTab(QWidget):
    """Report generation tab"""
    
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.logger = setup_logger()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the report tab UI"""
        main_layout = QVBoxLayout()
        
        # Report configuration
        config_group = QGroupBox("Report Configuration")
        config_layout = QVBoxLayout()
        
        # Report type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Report Type:"))
        
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems([
            "Full Assessment Report",
            "Executive Summary",
            "Technical Deep Dive",
            "Remediation Plan"
        ])
        type_layout.addWidget(self.report_type_combo)
        
        type_layout.addStretch()
        config_layout.addLayout(type_layout)
        
        # Sections to include
        sections_layout = QVBoxLayout()
        sections_layout.addWidget(QLabel("Include Sections:"))
        
        self.sections_list = QListWidget()
        sections = [
            "Executive Summary",
            "Methodology",
            "Reconnaissance Findings",
            "Vulnerability Analysis",
            "Exploitation Results",
            "Risk Assessment",
            "Mitigation Recommendations",
            "Hardening Checklist",
            "Appendices"
        ]
        
        for section in sections:
            item = QListWidgetItem(section)
            item.setCheckState(Qt.Checked)
            self.sections_list.addItem(item)
            
        sections_layout.addWidget(self.sections_list)
        config_layout.addLayout(sections_layout)
        
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        # Report preview
        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout()
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        preview_layout.addWidget(self.report_preview)
        
        preview_group.setLayout(preview_layout)
        main_layout.addWidget(preview_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("Generate Preview")
        self.generate_btn.clicked.connect(self.generate_preview)
        button_layout.addWidget(self.generate_btn)
        
        self.export_pdf_btn = QPushButton("Export as PDF")
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        button_layout.addWidget(self.export_pdf_btn)
        
        self.export_html_btn = QPushButton("Export as HTML")
        self.export_html_btn.clicked.connect(self.export_html)
        button_layout.addWidget(self.export_html_btn)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_report)
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        main_layout.addLayout(button_layout)
        
        self.setLayout(main_layout)
        
    def generate_preview(self):
        """Generate report preview"""
        report_type = self.report_type_combo.currentText()
        
        self.report_preview.clear()
        
        # Generate report header
        header = f"""
        ╔{'═' * 70}╗
        ║{'EDUCATIONAL ATTACK-DEFENSE FRAMEWORK - ASSESSMENT REPORT'.center(70)}║
        ╠{'═' * 70}╣
        ║ Report Type: {report_type:<56}║
        ║ Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<56}║
        ║ Assessment Target: {self.controller.get_target() or 'Not specified':<46}║
        ╚{'═' * 70}╝
        
        """
        
        self.report_preview.append(header)
        
        # Add selected sections
        for i in range(self.sections_list.count()):
            item = self.sections_list.item(i)
            if item.checkState() == Qt.Checked:
                self.add_section_preview(item.text())
                
    def add_section_preview(self, section_name):
        """Add a section to the preview"""
        self.report_preview.append(f"\n{'=' * 80}")
        self.report_preview.append(f"Section: {section_name}")
        self.report_preview.append(f"{'=' * 80}\n")
        
        # Add placeholder content based on section
        if section_name == "Executive Summary":
            content = """
            This report summarizes the findings from the educational attack-defense
            assessment conducted on the target system. The assessment followed a
            structured methodology including reconnaissance, vulnerability mapping,
            controlled exploitation demonstration, and defensive recommendations.
            
            Key Findings:
            • System exhibits multiple known vulnerabilities
            • Several services are running outdated versions
            • Security configurations require hardening
            • Defense-in-depth measures needed
            
            Risk Level: MEDIUM
            
            Immediate Actions Recommended:
            1. Apply all security patches
            2. Disable unnecessary services
            3. Implement network segmentation
            4. Enable logging and monitoring
            """
            
        elif section_name == "Methodology":
            content = """
            Assessment Methodology:
            
            1. Reconnaissance Phase:
               • Port scanning and service enumeration
               • OS fingerprinting and version detection
               • Network service mapping
            
            2. Vulnerability Analysis:
               • Service-to-vulnerability mapping
               • Risk prioritization (CVSS-based)
               • Proof-of-concept validation
            
            3. Defense Planning:
               • Mitigation strategy development
               • Hardening checklist creation
               • Security control recommendations
            
            Tools Used:
            • Custom Educational Framework
            • Network scanners
            • Vulnerability databases
            
            Scope Limitations:
            • Educational lab environment only
            • No destructive testing
            • No lateral movement attempts
            """
            
        elif section_name == "Reconnaissance Findings":
            content = self.controller.get_scan_summary()
            
        elif section_name == "Vulnerability Analysis":
            content = self.controller.get_vulnerability_summary()
            
        elif section_name == "Exploitation Results":
            content = self.controller.get_exploitation_summary()
            
        elif section_name == "Risk Assessment":
            content = """
            Risk Assessment Matrix:
            
            High Risk (Immediate Action Required):
            • SMBv1 vulnerabilities (MS17-010)
            • Unauthenticated services
            • Default credentials in use
            
            Medium Risk (Address within 30 days):
            • Outdated software versions
            • Unnecessary open ports
            • Weak encryption protocols
            
            Low Risk (Address in next maintenance):
            • Information disclosure
            • Default configurations
            • Missing security headers
            
            Overall Risk Score: 6.8/10 (MEDIUM)
            
            Factors Considered:
            • Exploit availability
            • Impact severity
            • Attack complexity
            • Security controls present
            """
            
        elif section_name == "Mitigation Recommendations":
            content = self.controller.get_mitigation_summary()
            
        elif section_name == "Hardening Checklist":
            content = """
            Windows 7 Hardening Checklist:
            
            [✓] 1. Apply all Windows updates
            [ ] 2. Disable SMBv1 protocol
            [ ] 3. Enable Windows Firewall
            [ ] 4. Configure audit policies
            [ ] 5. Remove unnecessary services
            [ ] 6. Implement password policy
            [ ] 7. Enable User Account Control
            [ ] 8. Configure antivirus software
            [ ] 9. Set up event logging
            [ ] 10. Regular backup configuration
            
            Priority Legend:
            ● High Priority (Complete within 24h)
            ● Medium Priority (Complete within 7 days)
            ● Low Priority (Complete within 30 days)
            """
            
        elif section_name == "Appendices":
            content = """
            Appendices:
            
            A. Glossary of Terms
            B. Reference Materials
            C. Tool Command References
            D. Additional Resources
            E. Contact Information
            
            References:
            1. MITRE ATT&CK Framework
            2. NIST Cybersecurity Framework
            3. CIS Windows 7 Benchmarks
            4. Microsoft Security Guidelines
            """
            
        else:
            content = f"Content for {section_name} will be generated based on assessment data."
            
        self.report_preview.append(content)
        
    def export_pdf(self):
        """Export report as PDF"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export PDF Report", "", "PDF Files (*.pdf)"
        )
        
        if file_path:
            try:
                # This would use reportlab to generate PDF
                QMessageBox.information(
                    self, "Success",
                    f"PDF report would be saved to: {file_path}\n\n"
                    "(PDF generation requires reportlab library)"
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export PDF: {str(e)}")
                
    def export_html(self):
        """Export report as HTML"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export HTML Report", "", "HTML Files (*.html)"
        )
        
        if file_path:
            try:
                # Generate HTML report
                html_content = self.generate_html_report()
                
                with open(file_path, 'w') as f:
                    f.write(html_content)
                    
                QMessageBox.information(
                    self, "Success",
                    f"HTML report saved to: {file_path}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export HTML: {str(e)}")
                
    def generate_html_report(self):
        """Generate HTML report content"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Attack-Defense Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2b2b2b; color: white; padding: 20px; text-align: center; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #0078d7; background: #f5f5f5; }}
        .finding {{ background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 4px; }}
        .recommendation {{ background: #d4edda; padding: 10px; margin: 10px 0; border-radius: 4px; }}
        .risk-high {{ color: #dc3545; font-weight: bold; }}
        .risk-medium {{ color: #ffc107; font-weight: bold; }}
        .risk-low {{ color: #28a745; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Educational Attack-Defense Framework</h1>
        <h2>Security Assessment Report</h2>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><em>For Educational Use Only - Lab Environment</em></p>
    </div>
    
    <div class="section">
        <h3>⚠️ Important Notice</h3>
        <p>This report is generated for educational purposes only. All testing was conducted in a controlled lab environment with explicit authorization.</p>
    </div>
    
    <!-- Report content would be dynamically inserted here -->
    
    <div class="section">
        <h3>Conclusion</h3>
        <p>The assessment demonstrates the importance of regular security assessments and proactive defense measures. By implementing the recommendations in this report, the security posture of the target system can be significantly improved.</p>
    </div>
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; color: #666;">
        <p>Generated by Educational Attack-Defense Framework v1.0</p>
        <p>Cybersecurity Project - University Program</p>
    </footer>
</body>
</html>
        """
        
    def clear_report(self):
        """Clear the report preview"""
        self.report_preview.clear()
        
    def reset(self):
        """Reset the tab"""
        self.clear_report()