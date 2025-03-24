#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess

def create_directory_structure():
    """Create the necessary directory structure for the IDPS system."""
    print("Creating directory structure...")
    
    # Create main directories
    directories = [
        "./lab",           # Directory to be monitored
        "./logs",          # Directory for log files
        "./config"         # Directory for configuration files (optional)
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
        else:
            print(f"Directory already exists: {directory}")

def create_log_files():
    """Create and initialize log files."""
    print("Setting up log files...")
    
    log_files = [
        "./logs/file_log.txt",
        "./logs/network_log.txt",
        "./logs/process_log.txt",
        "./logs/anomaly_log.txt"
    ]
    
    for log_file in log_files:
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write("# IDPS Log File - Created on: " + 
                        subprocess.check_output(['date']).decode().strip() + "\n")
            print(f"Created log file: {log_file}")
        else:
            print(f"Log file already exists: {log_file}")

def install_dependencies():
    """Install required Python packages."""
    print("Installing dependencies...")
    
    required_packages = [
        "watchdog",
        "psutil",
        "numpy",
        "scikit-learn"
    ]
    
    for package in required_packages:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def create_sample_files():
    """Create some sample files in the monitored directory for testing."""
    print("Creating sample files for testing...")
    
    sample_files = [
        "./lab/sample_text.txt",
        "./lab/sample_data.dat"
    ]
    
    for sample_file in sample_files:
        with open(sample_file, 'w') as f:
            f.write("This is a sample file for testing the IDPS system.\n")
        print(f"Created sample file: {sample_file}")

def main():
    parser = argparse.ArgumentParser(description="Setup script for IDPS system")
    parser.add_argument("--skip-deps", action="store_true", help="Skip installing dependencies")
    parser.add_argument("--create-samples", action="store_true", help="Create sample files for testing")
    args = parser.parse_args()
    
    create_directory_structure()
    create_log_files()
    
    if not args.skip_deps:
        install_dependencies()
    else:
        print("Skipping dependency installation as requested.")
    
    if args.create_samples:
        create_sample_files()
    
    print("\nSetup complete! You can now run the IDPS system with: python idps.py")

if __name__ == "__main__":
    main() 