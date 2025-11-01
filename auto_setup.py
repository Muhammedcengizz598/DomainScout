"""
DomainScout Pro - Automated Setup Script
Automatically installs all required dependencies
"""
import subprocess
import sys
import os
from pathlib import Path

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║           DOMAINSCOUT PRO - AUTO INSTALLER            ║
    ║              Premium Domain Intelligence              ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Ensure Python 3.8+ is installed"""
    version = sys.version_info
    print(f"[INFO] Python Version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("[ERROR] Python 3.8 or higher required!")
        sys.exit(1)
    print("[OK] Python version compatible")

def install_dependencies():
    """Install all required packages"""
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    if not requirements_file.exists():
        print("[ERROR] requirements.txt not found!")
        sys.exit(1)
    
    print("\n[INFO] Installing dependencies...")
    print("[INFO] This may take a few minutes...\n")
    
    try:
        subprocess.check_call([
            sys.executable, 
            "-m", 
            "pip", 
            "install", 
            "--upgrade", 
            "pip"
        ])
        print("[OK] Pip upgraded successfully\n")
        
        subprocess.check_call([
            sys.executable,
            "-m",
            "pip",
            "install",
            "-r",
            str(requirements_file)
        ])
        print("\n[OK] All dependencies installed successfully!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Installation failed: {e}")
        return False

def create_directories():
    """Create necessary project directories"""
    base_path = Path(__file__).parent
    directories = [
        "data",
        "data/json_exports",
        "data/csv_exports",
        "data/html_reports",
        "data/pdf_reports",
        "logs",
        "cache"
    ]
    
    print("\n[INFO] Creating project directories...")
    for directory in directories:
        dir_path = base_path / directory
        dir_path.mkdir(parents=True, exist_ok=True)
    print("[OK] Project structure created")

def main():
    print_banner()
    print("[START] DomainScout Pro Setup\n")
    
    check_python_version()
    
    if install_dependencies():
        create_directories()
        print("\n" + "="*60)
        print("[SUCCESS] Setup completed successfully!")
        print("="*60)
        print("\nTo start DomainScout Pro, run:")
        print("  python domainscout_pro.py")
        print("\n")
    else:
        print("\n[FAILED] Setup incomplete. Please check errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
