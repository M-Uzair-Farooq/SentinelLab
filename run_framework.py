#!/usr/bin/env python3
"""
Launch script for Attack-Defense Framework
"""

import sys
import os
import subprocess

def check_and_install():
    """Check and install requirements"""
    try:
        import PyQt5
        print("✓ PyQt5 is installed")
    except ImportError:
        print("Installing PyQt5...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PyQt5"])
    
    try:
        import yaml
        print("✓ PyYAML is installed")
    except ImportError:
        print("Installing PyYAML...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml"])

def main():
    print("\n" + "="*60)
    print("EDUCATIONAL ATTACK-DEFENSE FRAMEWORK")
    print("="*60)
    
    # Check requirements
    check_and_install()
    
    # Run main application
    from main import main as app_main
    app_main()

if __name__ == "__main__":
    main()