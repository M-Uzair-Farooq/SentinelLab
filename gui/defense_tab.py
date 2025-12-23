"""
Simplified Defense tab for mitigation recommendations
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QBrush

from core.logger import setup_logger
from defense.mitigation_engine import MitigationEngine
from gui.styles import COLORS

class DefenseTab(QWidget):
    """Simplified Defense tab showing only vulnerability-specific recommendations"""
    
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.logger = setup_logger()
        self.mitigation_engine = MitigationEngine()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the simplified defense tab UI"""
        main_layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("🛡️ DEFENSE RECOMMENDATIONS")
        header_label.setStyleSheet("""
            QLabel {
                font-size: 16pt;
                font-weight: bold;
                color: #4CAF50;
                padding: 10px;
                text-align: center;
            }
        """)
        main_layout.addWidget(header_label)
        
        # Description
        desc_label = QLabel("Based on vulnerabilities found during reconnaissance")
        desc_label.setStyleSheet("""
            QLabel {
                color: #777;
                font-style: italic;
                text-align: center;
                padding: 5px;
            }
        """)
        main_layout.addWidget(desc_label)
        
        # Vulnerability summary table
        summary_group = QGroupBox("📊 Vulnerability Summary")
        summary_layout = QVBoxLayout()
        
        self.summary_label = QLabel("No vulnerabilities detected. Run reconnaissance first.")
        self.summary_label.setStyleSheet("color: #FF9800; padding: 10px; font-weight: bold;")
        summary_layout.addWidget(self.summary_label)
        
        summary_group.setLayout(summary_layout)
        main_layout.addWidget(summary_group)
        
        # Defense recommendations tree
        recommendations_group = QGroupBox("🛡️ Defense Recommendations")
        recommendations_layout = QVBoxLayout()
        
        self.recommendations_tree = QTreeWidget()
        self.recommendations_tree.setHeaderLabels([
            "Vulnerability", "Severity", "Port", "Defense Action"
        ])
        self.recommendations_tree.setColumnWidth(0, 200)  # Vulnerability
        self.recommendations_tree.setColumnWidth(1, 80)   # Severity
        self.recommendations_tree.setColumnWidth(2, 60)   # Port
        self.recommendations_tree.setColumnWidth(3, 350)  # Defense Action
        
        recommendations_layout.addWidget(self.recommendations_tree)
        recommendations_group.setLayout(recommendations_layout)
        main_layout.addWidget(recommendations_group)
        
        # Details panel
        details_group = QGroupBox("📝 Defense Details")
        details_layout = QVBoxLayout()
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(200)
        self.details_text.setStyleSheet("""
            QTextEdit {
                font-size: 10pt;
                background-color: #222;
                color: #CCC;
                border: 1px solid #444;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        self.details_text.setHtml("""
            <h3 style='color: #4CAF50;'>Select a vulnerability to view defense details</h3>
            <p>Click on any vulnerability in the list above to see detailed defense instructions.</p>
            <p><b>Educational Note:</b> These recommendations are for Windows 7 lab environments only.</p>
        """)
        
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        main_layout.addWidget(details_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("🔄 Generate Recommendations")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        self.generate_btn.clicked.connect(self.generate_recommendations)
        button_layout.addWidget(self.generate_btn)
        
        self.export_btn = QPushButton("💾 Export to File")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        self.export_btn.clicked.connect(self.export_recommendations)
        button_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #616161;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_recommendations)
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        main_layout.addLayout(button_layout)
        
        # Connect tree selection
        self.recommendations_tree.itemClicked.connect(self.on_recommendation_selected)
        
        self.setLayout(main_layout)
        
    def update_vulnerabilities(self, scan_results):
        """Update with vulnerabilities from scan"""
        self.scan_results = scan_results
        self.generate_recommendations()
        
    def generate_recommendations(self):
        """Generate defense recommendations based on scanned vulnerabilities"""
        # Try to get vulnerabilities
        vulnerabilities = []
        
        # 1. Try to get from controller
        if hasattr(self.controller, 'vulnerabilities') and self.controller.vulnerabilities:
            vulnerabilities = self.controller.vulnerabilities
        
        # 2. If not available, try to map from scan results
        elif hasattr(self, 'scan_results') and self.scan_results:
            vulnerabilities = self.controller.map_vulnerabilities(self.scan_results)
        
        # 3. If still not available, show message
        if not vulnerabilities:
            self.summary_label.setText("❌ No vulnerabilities found. Run reconnaissance first.")
            self.summary_label.setStyleSheet("color: #F44336; padding: 10px; font-weight: bold;")
            QMessageBox.warning(self, "No Data", "No vulnerabilities available. Please run reconnaissance scan first.")
            return
        
        # Update summary
        self.update_summary(vulnerabilities)
        
        # Clear existing recommendations
        self.recommendations_tree.clear()
        
        # Generate and display recommendations
        recommendations = self.mitigation_engine.generate_recommendations(vulnerabilities)
        
        for rec in recommendations:
            item = QTreeWidgetItem(self.recommendations_tree)
            
            # Vulnerability name
            item.setText(0, rec.get('vulnerability', 'Unknown'))
            
            # Severity with icon
            severity = rec.get('severity', 'Low')
            severity_icon = "🔴" if severity == 'Critical' else "🟠" if severity == 'High' else "🟡" if severity == 'Medium' else "🟢"
            item.setText(1, f"{severity_icon} {severity}")
            
            # Port
            item.setText(2, str(rec.get('port', '')))
            
            # First defense action
            mitigations = rec.get('mitigation', ['No defense available'])
            first_action = mitigations[0] if mitigations else 'No defense available'
            item.setText(3, first_action)
            
            # Store full data for details
            item.setData(0, Qt.UserRole, rec)
            
            # Color coding based on severity
            if severity == 'Critical':
                for col in range(4):
                    item.setForeground(col, QColor('#FF5252'))
            elif severity == 'High':
                for col in range(4):
                    item.setForeground(col, QColor('#FF9800'))
            elif severity == 'Medium':
                for col in range(4):
                    item.setForeground(col, QColor('#FFEB3B'))
            else:
                for col in range(4):
                    item.setForeground(col, QColor('#8BC34A'))
        
        # Auto-select first item
        if self.recommendations_tree.topLevelItemCount() > 0:
            self.recommendations_tree.setCurrentItem(self.recommendations_tree.topLevelItem(0))
            self.on_recommendation_selected(self.recommendations_tree.topLevelItem(0), 0)
        
    def update_summary(self, vulnerabilities):
        """Update vulnerability summary"""
        if not vulnerabilities:
            self.summary_label.setText("No vulnerabilities detected")
            return
        
        # Count by severity
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in counts:
                counts[severity] += 1
        
        total = sum(counts.values())
        self.summary_label.setText(
            f"✅ Found {total} vulnerabilities: "
            f"{counts['Critical']} Critical • {counts['High']} High • "
            f"{counts['Medium']} Medium • {counts['Low']} Low"
        )
        self.summary_label.setStyleSheet("color: #4CAF50; padding: 10px; font-weight: bold;")
    
    def on_recommendation_selected(self, item, column):
        """Handle recommendation selection"""
        rec_data = item.data(0, Qt.UserRole)
        if rec_data:
            vulnerability = rec_data.get('vulnerability', 'Unknown')
            details = self.mitigation_engine.get_mitigation_details(vulnerability)
            
            html_content = f"""
            <h3 style='color: #2196F3;'>{vulnerability}</h3>
            
            <table style='border-collapse: collapse; width: 100%; margin: 10px 0;'>
                <tr>
                    <td style='padding: 5px; font-weight: bold; color: #FF9800;'>Severity:</td>
                    <td style='padding: 5px;'>{rec_data.get('severity', 'Unknown')}</td>
                </tr>
                <tr>
                    <td style='padding: 5px; font-weight: bold; color: #FF9800;'>Service:</td>
                    <td style='padding: 5px;'>{rec_data.get('service', 'Unknown')}</td>
                </tr>
                <tr>
                    <td style='padding: 5px; font-weight: bold; color: #FF9800;'>Port:</td>
                    <td style='padding: 5px;'>{rec_data.get('port', 'Unknown')}</td>
                </tr>
                <tr>
                    <td style='padding: 5px; font-weight: bold; color: #FF9800;'>CVE:</td>
                    <td style='padding: 5px;'>{rec_data.get('cve', 'Not specified')}</td>
                </tr>
            </table>
            
            <h4 style='color: #4CAF50;'>📖 Vulnerability Description:</h4>
            <p style='background-color: #333; padding: 10px; border-radius: 4px;'>
                {rec_data.get('description', 'No description available')}
            </p>
            
            <h4 style='color: #4CAF50;'>⚠️ Impact:</h4>
            <p style='background-color: #332200; padding: 10px; border-radius: 4px; color: #FF9800;'>
                {rec_data.get('impact', 'No impact information available')}
            </p>
            
            <h4 style='color: #4CAF50;'>🛡️ Defense Actions:</h4>
            <ol style='background-color: #223322; padding: 15px 30px; border-radius: 4px;'>
            """
            
            # Add defense actions
            mitigations = details.get('mitigation_steps', ['No defense steps available'])
            for i, step in enumerate(mitigations, 1):
                html_content += f"<li style='margin: 8px 0;'>{step}</li>"
            
            html_content += """
            </ol>
            
            <h4 style='color: #4CAF50;'>🔧 Root Cause:</h4>
            <p style='background-color: #222233; padding: 10px; border-radius: 4px;'>
                """ + details.get('root_cause', 'Not specified') + """
            </p>
            """
            
            self.details_text.setHtml(html_content)
    
    def export_recommendations(self):
        """Export defense recommendations to file"""
        if self.recommendations_tree.topLevelItemCount() == 0:
            QMessageBox.warning(self, "No Data", "No recommendations to export. Generate recommendations first.")
            return
        
        from PyQt5.QtWidgets import QFileDialog
        import os
        from datetime import datetime
        
        # Create reports directory if it doesn't exist
        if not os.path.exists('reports'):
            os.makedirs('reports')
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Defense Report", 
            f"reports/defense_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                report_content = self.generate_report_text()
                
                with open(filename, 'w') as f:
                    f.write(report_content)
                
                QMessageBox.information(
                    self, "Export Successful",
                    f"Defense report exported to:\n{filename}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Error: {str(e)}")
    
    def generate_report_text(self):
        """Generate text report of defense recommendations"""
        from datetime import datetime
        
        report = f"""
{'=' * 70}
DEFENSE RECOMMENDATIONS REPORT
{'=' * 70}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: {self.controller.get_target() or 'Not specified'}
For Educational Use Only - Windows 7 Lab Environment
{'=' * 70}

SUMMARY
{'-' * 70}
{self.summary_label.text()}

DETAILED DEFENSE RECOMMENDATIONS
{'-' * 70}
"""
        
        # Add each vulnerability and its defense
        for i in range(self.recommendations_tree.topLevelItemCount()):
            item = self.recommendations_tree.topLevelItem(i)
            rec_data = item.data(0, Qt.UserRole)
            
            if rec_data:
                report += f"\n{i+1}. {rec_data.get('vulnerability', 'Unknown')}\n"
                report += f"   Severity: {rec_data.get('severity', 'Unknown')}\n"
                report += f"   Service/Port: {rec_data.get('service', 'Unknown')}/{rec_data.get('port', 'Unknown')}\n"
                report += f"   Description: {rec_data.get('description', 'No description')}\n"
                report += f"   Impact: {rec_data.get('impact', 'No impact info')}\n"
                report += f"   Defense Actions:\n"
                
                details = self.mitigation_engine.get_mitigation_details(rec_data.get('vulnerability', ''))
                for j, step in enumerate(details.get('mitigation_steps', ['No defense steps']), 1):
                    report += f"     {j}. {step}\n"
                
                report += "-" * 70
        
        report += f"""

GENERAL WINDOWS 7 DEFENSE BEST PRACTICES
{'-' * 70}
1. Apply all Windows security updates regularly
2. Enable and configure Windows Firewall
3. Disable unnecessary services (SMBv1, NetBIOS, etc.)
4. Use strong passwords and account policies
5. Enable User Account Control (UAC)
6. Regularly review system logs
7. Use antivirus software
8. Implement network segmentation

{'=' * 70}
END OF REPORT
{'=' * 70}
        """
        
        return report
    
    def clear_recommendations(self):
        """Clear all recommendations"""
        reply = QMessageBox.question(
            self, "Clear Recommendations",
            "Clear all defense recommendations?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.recommendations_tree.clear()
            self.details_text.setHtml("""
                <h3 style='color: #4CAF50;'>Select a vulnerability to view defense details</h3>
                <p>Click on any vulnerability in the list above to see detailed defense instructions.</p>
                <p><b>Educational Note:</b> These recommendations are for Windows 7 lab environments only.</p>
            """)
            self.summary_label.setText("No vulnerabilities detected. Run reconnaissance first.")
            self.summary_label.setStyleSheet("color: #FF9800; padding: 10px; font-weight: bold;")
    
    def update_recommendations(self, recommendations):
        """Update with recommendations from controller"""
        # This method is kept for compatibility with controller signals
        if recommendations:
            # Convert recommendations to vulnerabilities format if needed
            vulnerabilities = []
            for rec in recommendations:
                vulnerabilities.append({
                    'name': rec.get('vulnerability', 'Unknown'),
                    'severity': rec.get('severity', 'Low'),
                    'service': rec.get('service', ''),
                    'port': rec.get('port', 0),
                    'description': f"Requires defense: {rec.get('vulnerability', '')}",
                    'impact': 'System compromise if not mitigated'
                })
            
            self.update_summary(vulnerabilities)
            
            # Display recommendations
            self.recommendations_tree.clear()
            for rec in recommendations:
                item = QTreeWidgetItem(self.recommendations_tree)
                item.setText(0, rec.get('vulnerability', 'Unknown'))
                
                severity = rec.get('severity', 'Low')
                severity_icon = "🔴" if severity == 'Critical' else "🟠" if severity == 'High' else "🟡" if severity == 'Medium' else "🟢"
                item.setText(1, f"{severity_icon} {severity}")
                
                item.setText(2, str(rec.get('port', '')))
                
                mitigations = rec.get('mitigation', ['No defense available'])
                first_action = mitigations[0] if mitigations else 'No defense available'
                item.setText(3, first_action)
                
                item.setData(0, Qt.UserRole, rec)
    
    def reset(self):
        """Reset the tab"""
        self.clear_recommendations()