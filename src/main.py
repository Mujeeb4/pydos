#!/usr/bin/env python3
"""
Real-Time DDoS Detection System - Main Entry Point
BSIT Information Security Project

This is the unified entry point for all system operations.
Run this script to access all features through an interactive menu.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the application banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║        Real-Time DDoS Detection System v1.0                    ║
║        BSIT Information Security Project                       ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def print_menu():
    """Print the main menu"""
    menu = f"""
{Colors.BOLD}Main Menu:{Colors.END}

{Colors.GREEN}[1]{Colors.END} Start DDoS Detector (CLI Dashboard)
{Colors.GREEN}[2]{Colors.END} Start Web Dashboard
{Colors.GREEN}[3]{Colors.END} Setup Guide (Run Detector + Dashboard + Attack Simulation)
{Colors.GREEN}[4]{Colors.END} Simulate Attack (Quick Launch)
{Colors.GREEN}[5]{Colors.END} View System Configuration
{Colors.GREEN}[6]{Colors.END} View Logs
{Colors.GREEN}[7]{Colors.END} Clean Firewall Rules (Linux only)
{Colors.GREEN}[8]{Colors.END} Check System Status
{Colors.GREEN}[9]{Colors.END} Run Tests
{Colors.GREEN}[0]{Colors.END} Exit

{Colors.YELLOW}Note:{Colors.END} Options 1, 3, 4, and 7 require {Colors.BOLD}Linux{Colors.END} and {Colors.BOLD}root/sudo{Colors.END} access.
      On Windows, only options 2, 5, 6, 8, and 9 work fully.
"""
    print(menu)

def check_platform():
    """Check if running on Linux"""
    is_linux = platform.system() == 'Linux'
    if not is_linux:
        print(f"{Colors.YELLOW}⚠️  Warning: Running on {platform.system()}{Colors.END}")
        print(f"{Colors.YELLOW}   Full functionality requires Linux for packet sniffing and iptables.{Colors.END}")
        print(f"{Colors.CYAN}   See docs/WINDOWS_TESTING_GUIDE.md for setup instructions.{Colors.END}\n")
    return is_linux

def check_root():
    """Check if running with root/sudo privileges"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows doesn't have geteuid
        return False

def get_project_root():
    """Get the project root directory"""
    return Path(__file__).parent.parent

def open_new_terminal(command, title=""):
    """Open a new terminal window and run a command"""
    system = platform.system()
    project_root = get_project_root()
    
    try:
        if system == 'Linux':
            # Try different terminal emulators
            terminals = [
                ['gnome-terminal', '--', 'bash', '-c'],
                ['xterm', '-hold', '-e'],
                ['konsole', '-e'],
                ['xfce4-terminal', '-e']
            ]
            
            full_command = f'cd "{project_root}" && {command}; exec bash'
            
            for term_cmd in terminals:
                try:
                    if title:
                        if 'gnome-terminal' in term_cmd:
                            subprocess.Popen(term_cmd + [f'{full_command}'], 
                                           stdout=subprocess.DEVNULL, 
                                           stderr=subprocess.DEVNULL)
                        else:
                            subprocess.Popen(term_cmd + [f'{full_command}'],
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
                    else:
                        subprocess.Popen(term_cmd + [f'{full_command}'],
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
                    return True
                except FileNotFoundError:
                    continue
            return False
            
        elif system == 'Windows':
            # Windows PowerShell with proper escaping
            # Change directory and run command, then wait
            ps_command = f"Set-Location '{project_root}'; {command}; Write-Host '`nPress Enter to close...'; Read-Host"
            
            subprocess.Popen(
                ['powershell.exe', '-NoExit', '-Command', ps_command],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                cwd=str(project_root)
            )
            return True
            
        elif system == 'Darwin':  # macOS
            # macOS Terminal
            script = f'cd "{project_root}" && {command}'
            subprocess.Popen(['osascript', '-e', 
                            f'tell app "Terminal" to do script "{script}"'])
            return True
    except Exception as e:
        print(f"{Colors.RED}Error opening terminal: {e}{Colors.END}")
        return False
    
    return False

def run_detector():
    """Start the DDoS detector"""
    print(f"\n{Colors.CYAN}Starting DDoS Detector...{Colors.END}")
    
    if platform.system() != 'Linux':
        print(f"{Colors.RED}Error: DDoS detector requires Linux to run.{Colors.END}")
        print(f"{Colors.YELLOW}Please use VirtualBox with Ubuntu or see docs/WINDOWS_TESTING_GUIDE.md{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    if not check_root():
        print(f"{Colors.RED}Error: DDoS detector requires root/sudo privileges.{Colors.END}")
        print(f"{Colors.YELLOW}Please run: sudo python3 src/main.py{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    detector_path = Path(__file__).parent / "ddos_detector.py"
    
    print(f"{Colors.GREEN}✓ Platform: Linux{Colors.END}")
    print(f"{Colors.GREEN}✓ Permissions: Root{Colors.END}")
    print(f"{Colors.YELLOW}Starting detector... Press Ctrl+C to stop{Colors.END}\n")
    
    try:
        subprocess.run([sys.executable, str(detector_path)])
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Detector stopped.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def run_dashboard():
    """Start the web dashboard"""
    print(f"\n{Colors.CYAN}Starting Web Dashboard...{Colors.END}")
    
    dashboard_path = Path(__file__).parent / "dashboard.py"
    
    # Use platform-appropriate path
    if platform.system() == 'Windows':
        cmd = f'python "{dashboard_path}"'
    else:
        cmd = f'{sys.executable} {dashboard_path}'
    
    print(f"{Colors.GREEN}Dashboard will be available at: http://localhost:5001{Colors.END}")
    print(f"{Colors.YELLOW}Starting server... Press Ctrl+C to stop{Colors.END}\n")
    
    try:
        subprocess.run([sys.executable, str(dashboard_path)])
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Dashboard stopped.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def run_both():
    """Automatically launch detector, dashboard, and provide attack simulation option"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}Launch Complete Testing Environment{Colors.END}")
    print("=" * 70)
    
    if platform.system() != 'Linux':
        print(f"\n{Colors.YELLOW}⚠️  Running on {platform.system()}{Colors.END}")
        print(f"{Colors.CYAN}The detector requires Linux (packet sniffing needs admin access).{Colors.END}")
        print(f"{Colors.YELLOW}For full functionality, use VirtualBox with Ubuntu.{Colors.END}\n")
        
        print(f"{Colors.BOLD}Windows Options:{Colors.END}")
        print(f"{Colors.GREEN}[1]{Colors.END} Launch Web Dashboard (works on Windows)")
        print(f"{Colors.GREEN}[2]{Colors.END} Launch Demo Mode (simulated detector for testing)")
        print(f"{Colors.GREEN}[0]{Colors.END} Back to menu\n")
        
        choice = input(f"{Colors.CYAN}Select option: {Colors.END}").strip()
        
        if choice == '1':
            print(f"\n{Colors.GREEN}✓ Launching web dashboard in new window...{Colors.END}")
            # Use python instead of sys.executable for clarity
            if open_new_terminal('python src\\dashboard.py', "Web Dashboard"):
                print(f"{Colors.GREEN}✓ Dashboard started! Access at: http://localhost:5001{Colors.END}")
                print(f"{Colors.CYAN}Note: Dashboard will show 'detector not started' until you run detector on Linux{Colors.END}")
            else:
                print(f"{Colors.RED}✗ Failed to open new terminal{Colors.END}")
        
        elif choice == '2':
            print(f"\n{Colors.GREEN}✓ Launching demo mode...{Colors.END}")
            print(f"\n{Colors.CYAN}Terminal 1: Dashboard{Colors.END}")
            if open_new_terminal('python src\\dashboard.py', "Dashboard"):
                print(f"{Colors.GREEN}  ✓ Dashboard launched at http://localhost:5001{Colors.END}")
            
            import time
            time.sleep(2)
            
            print(f"\n{Colors.CYAN}Terminal 2: Demo Traffic Generator{Colors.END}")
            # Create a simple demo script
            demo_script = '''
import time
import random
from datetime import datetime

print("="*70)
print("DEMO MODE - Simulated Traffic Monitor")
print("This simulates what the detector shows on Linux")
print("="*70)
print()

ips = ["192.168.1.100", "192.168.1.101", "10.0.0.50", "172.16.0.10"]

for i in range(20):
    ip = random.choice(ips)
    packets = random.randint(10, 150)
    syn = random.randint(5, 80)
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] Traffic from {ip:15} - Packets: {packets:3} SYN: {syn:2}")
    
    if packets > 100:
        print(f"  ⚠️  WARNING: High traffic from {ip}")
    if syn > 50:
        print(f"  🚨 ALERT: SYN flood detected from {ip}!")
    
    time.sleep(1)

print("\nDemo complete! On Linux, the real detector monitors actual network traffic.")
input("Press Enter to close...")
'''
            
            demo_file = get_project_root() / 'demo_traffic.py'
            with open(demo_file, 'w') as f:
                f.write(demo_script)
            
            if open_new_terminal('python demo_traffic.py', "Demo Traffic"):
                print(f"{Colors.GREEN}  ✓ Demo traffic generator launched{Colors.END}")
            
            print(f"\n{Colors.GREEN}✓ Demo mode started!{Colors.END}")
            print(f"{Colors.CYAN}This simulates what you'd see on Linux.{Colors.END}")
            print(f"{Colors.YELLOW}For real detection, use Ubuntu Linux.{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    if not check_root():
        print(f"\n{Colors.RED}Error: This option requires root/sudo privileges.{Colors.END}")
        print(f"{Colors.YELLOW}Please run: sudo python3 src/main.py{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"""
{Colors.BOLD}This will automatically launch:{Colors.END}

  {Colors.GREEN}✓{Colors.END} Terminal 1: DDoS Detector (monitors traffic)
  {Colors.GREEN}✓{Colors.END} Terminal 2: Web Dashboard (http://localhost:5001)
  
{Colors.YELLOW}After they start, you can optionally launch an attack simulation.{Colors.END}
""")
    
    confirm = input(f"\n{Colors.CYAN}Launch detector and dashboard? (yes/no): {Colors.END}").strip().lower()
    
    if confirm != 'yes':
        print(f"{Colors.YELLOW}Cancelled.{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"\n{Colors.CYAN}Launching components...{Colors.END}\n")
    
    # Launch detector
    print(f"{Colors.YELLOW}[1/2]{Colors.END} Opening DDoS Detector...")
    if open_new_terminal('sudo python3 src/ddos_detector.py', "DDoS Detector"):
        print(f"{Colors.GREEN}  ✓ Detector launched{Colors.END}")
    else:
        print(f"{Colors.RED}  ✗ Failed to launch detector{Colors.END}")
    
    import time
    time.sleep(1)
    
    # Launch dashboard
    print(f"{Colors.YELLOW}[2/2]{Colors.END} Opening Web Dashboard...")
    if open_new_terminal('python3 src/dashboard.py', "Web Dashboard"):
        print(f"{Colors.GREEN}  ✓ Dashboard launched{Colors.END}")
        print(f"{Colors.GREEN}  ✓ Access at: http://localhost:5001{Colors.END}")
    else:
        print(f"{Colors.RED}  ✗ Failed to launch dashboard{Colors.END}")
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Components launched successfully!{Colors.END}")
    print(f"\n{Colors.CYAN}Wait a few seconds for them to start, then you can simulate an attack.{Colors.END}")
    
    # Ask about attack simulation
    attack = input(f"\n{Colors.CYAN}Launch attack simulation now? (yes/no): {Colors.END}").strip().lower()
    
    if attack == 'yes':
        print(f"\n{Colors.BOLD}Attack Types:{Colors.END}")
        print(f"{Colors.GREEN}[1]{Colors.END} SYN Flood")
        print(f"{Colors.GREEN}[2]{Colors.END} Packet Flood")
        print(f"{Colors.GREEN}[3]{Colors.END} UDP Flood")
        
        choice = input(f"\n{Colors.CYAN}Select attack type (1-3): {Colors.END}").strip()
        
        attack_types = {'1': 'syn', '2': 'packet', '3': 'udp'}
        attack_type = attack_types.get(choice, 'syn')
        
        target = input(f"{Colors.CYAN}Enter target IP (default: 127.0.0.1): {Colors.END}").strip() or "127.0.0.1"
        count = input(f"{Colors.CYAN}Enter packet count (default: 200): {Colors.END}").strip() or "200"
        
        print(f"\n{Colors.YELLOW}Launching {attack_type.upper()} flood attack...{Colors.END}")
        
        attack_cmd = f'sudo python3 scripts/simulate_attack.py --target {target} --type {attack_type} --count {count}'
        
        if open_new_terminal(attack_cmd, "Attack Simulation"):
            print(f"{Colors.GREEN}✓ Attack simulation launched!{Colors.END}")
            print(f"{Colors.CYAN}Check the detector terminal and web dashboard for results.{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Failed to launch attack simulation{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
    
    print(f"""
{Colors.BOLD}To run a complete test with detector, dashboard, and attack simulation,
you need THREE separate terminal windows:{Colors.END}

{Colors.CYAN}┌─ Terminal 1: DDoS Detector ────────────────────────────────────────┐{Colors.END}
{Colors.GREEN}│ sudo python3 src/ddos_detector.py                                  │{Colors.END}
{Colors.CYAN}│ Purpose: Monitors network traffic and detects attacks              │{Colors.END}
{Colors.CYAN}│ Note: Must run with sudo for packet sniffing                       │{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────────┘{Colors.END}

{Colors.CYAN}┌─ Terminal 2: Web Dashboard ────────────────────────────────────────┐{Colors.END}
{Colors.GREEN}│ python3 src/dashboard.py                                            │{Colors.END}
{Colors.CYAN}│ Purpose: Web interface at http://localhost:5001                     │{Colors.END}
{Colors.CYAN}│ Note: No sudo needed, just run as normal user                      │{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────────┘{Colors.END}

{Colors.CYAN}┌─ Terminal 3: Attack Simulation ────────────────────────────────────┐{Colors.END}
{Colors.GREEN}│ sudo python3 scripts/simulate_attack.py --target 127.0.0.1 \\       │{Colors.END}
{Colors.GREEN}│                                      --type syn --count 200         │{Colors.END}
{Colors.CYAN}│ Purpose: Generates attack traffic to test the detector             │{Colors.END}
{Colors.CYAN}│ Note: Must run with sudo, run AFTER detector and dashboard start   │{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────────┘{Colors.END}

{Colors.YELLOW}{Colors.BOLD}Step-by-Step:{Colors.END}
  1. Open Terminal 1 → Run detector (keeps running)
  2. Open Terminal 2 → Run dashboard (keeps running)
  3. Open Terminal 3 → Run attack simulation (generates traffic)
  4. Watch Terminal 1 for attack detection
  5. Check http://localhost:5001 in browser for web dashboard view

{Colors.GREEN}{Colors.BOLD}Quick Copy Commands:{Colors.END}

{Colors.BOLD}Terminal 1 (Detector):{Colors.END}
  cd "{get_project_root()}"
  sudo python3 src/ddos_detector.py

{Colors.BOLD}Terminal 2 (Dashboard):{Colors.END}
  cd "{get_project_root()}"
  python3 src/dashboard.py

{Colors.BOLD}Terminal 3 (Attack - wait for others to start first):{Colors.END}
  cd "{get_project_root()}"
  sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --type syn --count 200

{Colors.CYAN}💡 Tip:{Colors.END} Use Ctrl+C to stop detector or dashboard when done.
{Colors.CYAN}💡 Tip:{Colors.END} Attack simulation runs once and exits automatically.
""")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def simulate_attack():
    """Run attack simulation in a new terminal"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}Attack Simulation - Quick Launch{Colors.END}")
    print("=" * 70)
    
    if platform.system() != 'Linux':
        print(f"\n{Colors.RED}Error: Attack simulation requires Linux.{Colors.END}")
        print(f"{Colors.YELLOW}Please use VirtualBox with Ubuntu or see docs/WINDOWS_TESTING_GUIDE.md{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    if not check_root():
        print(f"\n{Colors.RED}Error: Attack simulation requires root/sudo privileges.{Colors.END}")
        print(f"{Colors.YELLOW}Please run: sudo python3 src/main.py{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"""
{Colors.CYAN}This will launch the attack simulation in a NEW terminal window.{Colors.END}
{Colors.GREEN}Your detector and dashboard (if running) will continue running.{Colors.END}

{Colors.YELLOW}Tip: Use option [3] to launch detector + dashboard + attack all at once.{Colors.END}
""")
    
    script_path = get_project_root() / "scripts" / "simulate_attack.py"
    
    print(f"\n{Colors.BOLD}Attack Types:{Colors.END}")
    print(f"{Colors.GREEN}[1]{Colors.END} SYN Flood")
    print(f"{Colors.GREEN}[2]{Colors.END} Packet Flood")
    print(f"{Colors.GREEN}[3]{Colors.END} UDP Flood")
    print(f"{Colors.GREEN}[0]{Colors.END} Back to main menu")
    
    choice = input(f"\n{Colors.CYAN}Select attack type: {Colors.END}").strip()
    
    if choice == '0':
        return
    
    attack_types = {'1': 'syn', '2': 'packet', '3': 'udp'}
    attack_type = attack_types.get(choice, 'syn')
    
    target = input(f"{Colors.CYAN}Enter target IP (default: 127.0.0.1): {Colors.END}").strip() or "127.0.0.1"
    count = input(f"{Colors.CYAN}Enter packet count (default: 200): {Colors.END}").strip() or "200"
    
    print(f"\n{Colors.YELLOW}Launching {attack_type.upper()} flood attack in new terminal...{Colors.END}")
    print(f"{Colors.YELLOW}Target: {target}, Count: {count}{Colors.END}\n")
    
    attack_cmd = f'sudo python3 scripts/simulate_attack.py --target {target} --type {attack_type} --count {count}'
    
    if open_new_terminal(attack_cmd, "Attack Simulation"):
        print(f"{Colors.GREEN}✓ Attack simulation launched in new terminal!{Colors.END}")
        print(f"{Colors.CYAN}Check the detector terminal and web dashboard for results.{Colors.END}")
    else:
        print(f"{Colors.RED}✗ Failed to open new terminal{Colors.END}")
        print(f"{Colors.YELLOW}Fallback: Running in current terminal...{Colors.END}\n")
        
        try:
            subprocess.run([
                sys.executable, 
                str(script_path),
                '--target', target,
                '--type', attack_type,
                '--count', count
            ])
            print(f"\n{Colors.GREEN}✓ Attack simulation completed!{Colors.END}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Attack stopped.{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def view_config():
    """View system configuration"""
    print(f"\n{Colors.CYAN}System Configuration{Colors.END}")
    print("=" * 60)
    
    config_path = get_project_root() / "config" / "config.py"
    
    try:
        with open(config_path, 'r') as f:
            content = f.read()
            # Extract key settings
            lines = content.split('\n')
            for line in lines:
                if '=' in line and not line.strip().startswith('#'):
                    if any(keyword in line for keyword in ['THRESHOLD', 'INTERFACE', 'PORT', 'HOST', 'WINDOW']):
                        print(f"{Colors.GREEN}{line.strip()}{Colors.END}")
        
        print("\n" + "=" * 60)
        print(f"\n{Colors.YELLOW}To edit configuration:{Colors.END}")
        print(f"{Colors.CYAN}  nano config/config.py{Colors.END}")
        
    except FileNotFoundError:
        print(f"{Colors.RED}Config file not found at: {config_path}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error reading config: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def view_logs():
    """View system logs"""
    print(f"\n{Colors.CYAN}System Logs{Colors.END}")
    print("=" * 60)
    
    logs_dir = get_project_root() / "logs"
    
    print(f"\n{Colors.BOLD}Available log files:{Colors.END}")
    log_files = [
        ('ddos_events.log', 'All system events'),
        ('ddos_attacks.log', 'Attack-specific logs'),
        ('ddos_system.log', 'System operations'),
        ('ddos_events.json', 'JSON structured logs')
    ]
    
    for i, (filename, description) in enumerate(log_files, 1):
        log_path = logs_dir / filename
        if log_path.exists():
            size = log_path.stat().st_size / 1024  # KB
            print(f"{Colors.GREEN}[{i}]{Colors.END} {filename:25} - {description} ({size:.1f} KB)")
        else:
            print(f"{Colors.YELLOW}[{i}]{Colors.END} {filename:25} - {description} (not created yet)")
    
    print(f"{Colors.GREEN}[0]{Colors.END} Back to main menu")
    
    choice = input(f"\n{Colors.CYAN}Select log to view (last 20 lines): {Colors.END}").strip()
    
    if choice == '0' or not choice:
        return
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(log_files):
            log_path = logs_dir / log_files[idx][0]
            
            if log_path.exists():
                print(f"\n{Colors.CYAN}=== {log_files[idx][0]} (last 20 lines) ==={Colors.END}\n")
                
                with open(log_path, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-20:]:
                        print(line.rstrip())
            else:
                print(f"{Colors.YELLOW}Log file not created yet. Run the detector first.{Colors.END}")
    except (ValueError, IndexError):
        print(f"{Colors.RED}Invalid selection.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error reading log: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def clean_firewall():
    """Clean firewall rules"""
    print(f"\n{Colors.CYAN}Clean Firewall Rules{Colors.END}")
    
    if platform.system() != 'Linux':
        print(f"{Colors.RED}Error: This option only works on Linux.{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    if not check_root():
        print(f"{Colors.RED}Error: This option requires root/sudo privileges.{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}⚠️  This will remove ALL iptables rules!{Colors.END}")
    confirm = input(f"{Colors.CYAN}Are you sure? (yes/no): {Colors.END}").strip().lower()
    
    if confirm != 'yes':
        print(f"{Colors.YELLOW}Cancelled.{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    script_path = get_project_root() / "scripts" / "unblock_all.sh"
    
    try:
        if script_path.exists():
            subprocess.run(['bash', str(script_path)], check=True)
            print(f"{Colors.GREEN}✓ Firewall rules cleared successfully.{Colors.END}")
        else:
            # Fallback: run iptables directly
            subprocess.run(['iptables', '-F'], check=True)
            print(f"{Colors.GREEN}✓ Firewall rules flushed successfully.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def check_status():
    """Check system status"""
    print(f"\n{Colors.CYAN}System Status{Colors.END}")
    print("=" * 60)
    
    # Platform check
    print(f"\n{Colors.BOLD}Platform:{Colors.END}")
    system = platform.system()
    if system == 'Linux':
        print(f"  {Colors.GREEN}✓ Operating System: {system}{Colors.END}")
    else:
        print(f"  {Colors.YELLOW}⚠  Operating System: {system} (Linux required for full functionality){Colors.END}")
    
    # Python version
    print(f"\n{Colors.BOLD}Python:{Colors.END}")
    py_version = platform.python_version()
    if tuple(map(int, py_version.split('.'))) >= (3, 8):
        print(f"  {Colors.GREEN}✓ Version: {py_version}{Colors.END}")
    else:
        print(f"  {Colors.RED}✗ Version: {py_version} (3.8+ required){Colors.END}")
    
    # Check if running with sudo
    print(f"\n{Colors.BOLD}Permissions:{Colors.END}")
    if check_root():
        print(f"  {Colors.GREEN}✓ Running as root/sudo{Colors.END}")
    else:
        print(f"  {Colors.YELLOW}⚠  Not running as root (required for detector and iptables){Colors.END}")
    
    # Check dependencies
    print(f"\n{Colors.BOLD}Dependencies:{Colors.END}")
    dependencies = ['scapy', 'flask', 'rich']
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"  {Colors.GREEN}✓ {dep}{Colors.END}")
        except ImportError:
            print(f"  {Colors.RED}✗ {dep} (not installed){Colors.END}")
    
    # Check file structure
    print(f"\n{Colors.BOLD}Project Structure:{Colors.END}")
    project_root = get_project_root()
    dirs = ['src', 'config', 'scripts', 'docs', 'logs', 'tests']
    for dir_name in dirs:
        dir_path = project_root / dir_name
        if dir_path.exists():
            print(f"  {Colors.GREEN}✓ {dir_name}/{Colors.END}")
        else:
            print(f"  {Colors.RED}✗ {dir_name}/ (missing){Colors.END}")
    
    # Check config file
    print(f"\n{Colors.BOLD}Configuration:{Colors.END}")
    config_path = project_root / "config" / "config.py"
    if config_path.exists():
        print(f"  {Colors.GREEN}✓ config/config.py{Colors.END}")
    else:
        print(f"  {Colors.RED}✗ config/config.py (missing){Colors.END}")
    
    # Overall status
    print("\n" + "=" * 60)
    if system == 'Linux' and check_root():
        print(f"{Colors.GREEN}{Colors.BOLD}✓ System ready for full operation!{Colors.END}")
    elif system == 'Linux':
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠  Run with sudo for full functionality{Colors.END}")
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠  Use Linux VM for full testing (see docs/WINDOWS_TESTING_GUIDE.md){Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def run_tests():
    """Run tests"""
    print(f"\n{Colors.CYAN}Run Tests{Colors.END}")
    print("=" * 60)
    
    tests_dir = get_project_root() / "tests"
    
    if not tests_dir.exists():
        print(f"{Colors.YELLOW}Tests directory not found.{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"\n{Colors.YELLOW}Note: Test suite is ready but tests need to be implemented.{Colors.END}")
    print(f"{Colors.CYAN}See tests/README.md for testing guidelines.{Colors.END}\n")
    
    # Check for pytest
    try:
        import pytest
        print(f"{Colors.GREEN}✓ pytest is installed{Colors.END}")
        
        confirm = input(f"\n{Colors.CYAN}Run pytest? (yes/no): {Colors.END}").strip().lower()
        if confirm == 'yes':
            print(f"\n{Colors.CYAN}Running pytest...{Colors.END}\n")
            subprocess.run(['pytest', str(tests_dir), '-v'])
    except ImportError:
        print(f"{Colors.YELLOW}⚠  pytest not installed{Colors.END}")
        print(f"{Colors.CYAN}Install with: pip install pytest{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

def main():
    """Main application loop"""
    # Check platform once at start
    is_linux = check_platform()
    
    while True:
        clear_screen()
        print_banner()
        print_menu()
        
        choice = input(f"{Colors.CYAN}Enter your choice: {Colors.END}").strip()
        
        if choice == '1':
            run_detector()
        elif choice == '2':
            run_dashboard()
        elif choice == '3':
            run_both()
        elif choice == '4':
            simulate_attack()
        elif choice == '5':
            view_config()
        elif choice == '6':
            view_logs()
        elif choice == '7':
            clean_firewall()
        elif choice == '8':
            check_status()
        elif choice == '9':
            run_tests()
        elif choice == '0':
            print(f"\n{Colors.GREEN}Thank you for using DDoS Detection System!{Colors.END}")
            print(f"{Colors.CYAN}Good luck with your project! 🚀{Colors.END}\n")
            sys.exit(0)
        else:
            print(f"{Colors.RED}Invalid choice. Please try again.{Colors.END}")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Program interrupted by user.{Colors.END}")
        print(f"{Colors.GREEN}Goodbye! 🚀{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Unexpected error: {e}{Colors.END}")
        sys.exit(1)
