#!/usr/bin/env python3

import sys
import os
import warnings

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Suppress unnecessary warnings
warnings.filterwarnings('ignore')

from PyQt5.QtWidgets import QApplication, QMessageBox
from gui.main_window import MainWindow
from core.logger import setup_logger

def main():
    """Main application entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                          EHD Project                          ║
    ║                    Attack-Defense Framework                   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Setup logging
    logger = setup_logger()
    logger.info("Framework starting...")
    
    # Create Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("Attack-Defense Framework")
    app.setApplicationVersion("6.9")
    
    # Show disclaimer
    disclaimer = QMessageBox()
    disclaimer.setWindowTitle("⚠️ SECURITY DISCLAIMER")
    disclaimer.setText("""
    
    This framework is designed By:
    • Noor ul Hassan 
    • Uzair Farooq
    • Ramla Khan
    
    By proceeding, you agree:
    1. Use only in isolated virtual labs
    2. Never test on production systems
    3. Follow all applicable laws
    4. Accept full responsibility for use
    
    """)
    disclaimer.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
    disclaimer.setDefaultButton(QMessageBox.Cancel)
    
    if disclaimer.exec() == QMessageBox.Ok:
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    else:
        logger.info("User declined disclaimer - exiting")
        sys.exit(0)

if __name__ == "__main__":
    main()