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
import time
import shutil

# Add src directory to path for imports
PROJECT_ROOT = Path(__file__).parent.resolve()  # FIXED: main.py IS at root
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

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
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        Real-Time DDoS Detection System v1.0                  ║
║        BSIT Information Security Project                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def print_menu():
    """Print the main menu"""
    menu = f"""
{Colors.BOLD}Main Menu:{Colors.END}

{Colors.GREEN}[1]{Colors.END} Start DDoS Detector (CLI Dashboard)
{Colors.GREEN}[2]{Colors.END} Start Web Dashboard
{Colors.GREEN}[3]{Colors.END} Launch Complete Environment (Detector + Dashboard + Attack Sim)
{Colors.GREEN}[4]{Colors.END} Simulate Attack (Quick Launch)
{Colors.GREEN}[5]{Colors.END} View System Configuration
{Colors.GREEN}[6]{Colors.END} View Logs
{Colors.GREEN}[7]{Colors.END} Clean Firewall Rules (Linux only)
{Colors.GREEN}[8]{Colors.END} Check System Status
{Colors.GREEN}[9]{Colors.END} Run Tests
{Colors.GREEN}[0]{Colors.END} Exit

{Colors.YELLOW}Note:{Colors.END} Options 1, 3, 4, and 7 require {Colors.BOLD}Linux{Colors.END} and {Colors.BOLD}root/sudo{Colors.END} access.
      Option 3 runs components in background processes for reliability.
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

def get_python_executable():
    """Get the correct Python executable (prefer venv if available)"""
    venv_python = PROJECT_ROOT / 'venv' / 'bin' / 'python3'
    if venv_python.exists():
        return str(venv_python)
    return sys.executable

def open_new_terminal(command, title="DDoS Tool", use_sudo=False):
    """Open a new terminal window to run a command"""
    # Build command with cd to project root
    full_cmd = f'cd "{PROJECT_ROOT}" && '
    if use_sudo:
        full_cmd += f'sudo {command}'
    else:
        full_cmd += command
    
    # Add exec bash to keep terminal open after command
    full_cmd += '; exec bash'
    
    # Try xterm first (most reliable, always available on Linux)
    if shutil.which("xterm"):
        try:
            cmd = ["xterm", "-T", title, "-hold", "-e", f"bash -c '{full_cmd}'"]
            subprocess.Popen(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            print(f"{Colors.GREEN}✓ Launched using xterm{Colors.END}")
            time.sleep(0.5)
            return True
        except Exception as e:
            print(f"{Colors.YELLOW}xterm failed: {e}{Colors.END}")
    
    # Try gnome-terminal with simpler approach (avoid dbus issues)
    if shutil.which("gnome-terminal"):
        try:
            cmd = ["gnome-terminal", "--", "bash", "-c", full_cmd]
            subprocess.Popen(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            print(f"{Colors.GREEN}✓ Launched using gnome-terminal{Colors.END}")
            time.sleep(0.5)
            return True
        except Exception as e:
            print(f"{Colors.YELLOW}gnome-terminal failed: {e}{Colors.END}")
    
    # Try other terminals
    other_terminals = [
        ("konsole", ["konsole", "-e", "bash", "-c", full_cmd]),
        ("xfce4-terminal", ["xfce4-terminal", "-e", f"bash -c '{full_cmd}'"]),
        ("terminator", ["terminator", "-e", f"bash -c '{full_cmd}'"]),
        ("kitty", ["kitty", "bash", "-c", full_cmd]),
    ]
    
    for term_name, cmd in other_terminals:
        if shutil.which(term_name):
            try:
                subprocess.Popen(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                print(f"{Colors.GREEN}✓ Launched using {term_name}{Colors.END}")
                time.sleep(0.5)
                return True
            except Exception:
                continue
    
    # Final fallback - print command for manual execution
    print(f"{Colors.RED}✗ No suitable terminal emulator found{Colors.END}")
    print(f"{Colors.YELLOW}Please run this command manually in a new terminal:{Colors.END}")
    print(f"{Colors.CYAN}{full_cmd}{Colors.END}")
    return False


def start_background_process(command, name, wait_time=2):
    """Start a background process and return the process object
    
    Args:
        command: Command to run
        name: Human-readable name for the process
        wait_time: Time to wait for process to start
        
    Returns:
        subprocess.Popen or None: Process object if successful
    """
    try:
        print(f"{Colors.YELLOW}Starting {name}...{Colors.END}")
        
        # Split command if it's a string
        if isinstance(command, str):
            # Use shell=True for complex commands with pipes/redirection
            if '|' in command or '>' in command or '<' in command:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    cwd=str(PROJECT_ROOT),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            else:
                # Split command for better process management
                cmd_parts = command.split()
                process = subprocess.Popen(
                    cmd_parts,
                    cwd=str(PROJECT_ROOT),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
        else:
            process = subprocess.Popen(
                command,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        
        # Wait a bit for the process to start
        time.sleep(wait_time)
        
        # Check if process is still running
        if process.poll() is None:
            print(f"{Colors.GREEN}✓ {name} started successfully{Colors.END}")
            return process
        else:
            # Process exited, check for errors
            stdout, stderr = process.communicate()
            if stderr:
                print(f"{Colors.RED}✗ {name} failed to start: {stderr.decode().strip()}{Colors.END}")
            else:
                print(f"{Colors.RED}✗ {name} exited immediately{Colors.END}")
            return None
            
    except Exception as e:
        print(f"{Colors.RED}✗ Error starting {name}: {e}{Colors.END}")
        return None


def run_detector():
    """Start the DDoS detector in current terminal"""
    print(f"\n{Colors.CYAN}Starting DDoS Detector...{Colors.END}")
    
    if platform.system() != 'Linux':
        print(f"{Colors.RED}Error: DDoS detector requires Linux to run.{Colors.END}")
        print(f"{Colors.YELLOW}Please use VirtualBox with Ubuntu or see docs/WINDOWS_TESTING_GUIDE.md{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    if not check_root():
        print(f"{Colors.RED}Error: DDoS detector requires root/sudo privileges.{Colors.END}")
        print(f"{Colors.YELLOW}Please run: sudo python3 main.py{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    detector_path = SRC_DIR / "detector.py"
    
    if not detector_path.exists():
        print(f"{Colors.RED}Error: detector.py not found at {detector_path}{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"{Colors.GREEN}✓ Platform: Linux{Colors.END}")
    print(f"{Colors.GREEN}✓ Permissions: Root{Colors.END}")
    print(f"{Colors.YELLOW}Starting detector... Press Ctrl+C to stop{Colors.END}\n")
    
    try:
        python_exec = get_python_executable()
        subprocess.run([python_exec, str(detector_path)])
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Detector stopped.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")


def run_dashboard():
    """Start the web dashboard in current terminal"""
    print(f"\n{Colors.CYAN}Starting Web Dashboard...{Colors.END}")
    
    dashboard_path = SRC_DIR / "dashboard.py"
    
    if not dashboard_path.exists():
        print(f"{Colors.RED}Error: dashboard.py not found at {dashboard_path}{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"{Colors.GREEN}Dashboard will be available at: http://localhost:5001{Colors.END}")
    print(f"{Colors.YELLOW}Starting server... Press Ctrl+C to stop{Colors.END}\n")
    
    try:
        python_exec = get_python_executable()
        subprocess.run([python_exec, str(dashboard_path)])
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Dashboard stopped.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")


def run_both():
    """Launch detector, dashboard, and attack simulation in separate terminal windows"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}Launch Complete Testing Environment{Colors.END}")
    print("=" * 70)
    
    if platform.system() != 'Linux':
        print(f"\n{Colors.YELLOW}⚠️  Running on {platform.system()}{Colors.END}")
        print(f"{Colors.CYAN}The detector requires Linux (packet sniffing needs admin access).{Colors.END}")
        print(f"{Colors.YELLOW}For full functionality, use VirtualBox with Ubuntu.{Colors.END}\n")
        
        print(f"{Colors.BOLD}Windows Options:{Colors.END}")
        print(f"{Colors.GREEN}[1]{Colors.END} Launch Web Dashboard (works on Windows)")
        print(f"{Colors.GREEN}[0]{Colors.END} Back to menu\n")
        
        choice = input(f"{Colors.CYAN}Select option: {Colors.END}").strip()
        
        if choice == '1':
            run_dashboard()
        
        return
    
    if not check_root():
        print(f"\n{Colors.RED}Error: This option requires root/sudo privileges.{Colors.END}")
        print(f"{Colors.YELLOW}Please run: sudo python3 main.py{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"""
{Colors.BOLD}This will launch components in separate terminal windows:{Colors.END}

  {Colors.GREEN}✓{Colors.END} DDoS Detector (new terminal with live dashboard)
  {Colors.GREEN}✓{Colors.END} Web Dashboard (new terminal at http://localhost:5001)
  {Colors.GREEN}✓{Colors.END} Attack Simulation (optional, new terminal)
  
{Colors.YELLOW}Each component runs in its own window for easy monitoring.{Colors.END}
""")
    
    confirm = input(f"\n{Colors.CYAN}Start detector and dashboard? (yes/no): {Colors.END}").strip().lower()
    
    if confirm != 'yes':
        print(f"{Colors.YELLOW}Cancelled.{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"\n{Colors.CYAN}Launching components in separate terminals...{Colors.END}\n")
    
    # Get the Python executable
    python_exec = get_python_executable()
    
    # Prepare commands for terminal launch
    # Important: Use full path to python executable from venv
    detector_cmd = f'sudo "{python_exec}" src/detector.py'
    dashboard_cmd = f'"{python_exec}" src/dashboard.py'
    
    # Launch DDoS Detector in new terminal
    print(f"{Colors.YELLOW}Launching DDoS Detector in new terminal...{Colors.END}")
    if not open_new_terminal(detector_cmd, "DDoS Detector", use_sudo=False):
        print(f"{Colors.RED}Failed to launch detector terminal{Colors.END}")
        print(f"{Colors.YELLOW}Try running manually: {detector_cmd}{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"{Colors.GREEN}✓ DDoS Detector launched in new terminal{Colors.END}")
    time.sleep(2)  # Wait for detector to initialize
    
    # Launch Web Dashboard in new terminal
    print(f"{Colors.YELLOW}Launching Web Dashboard in new terminal...{Colors.END}")
    if not open_new_terminal(dashboard_cmd, "Web Dashboard", use_sudo=False):
        print(f"{Colors.RED}Failed to launch dashboard terminal{Colors.END}")
        print(f"{Colors.YELLOW}Try running manually: {dashboard_cmd}{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"{Colors.GREEN}✓ Web Dashboard launched in new terminal{Colors.END}")
    print(f"{Colors.GREEN}🌐 Dashboard will be available at: http://localhost:5001{Colors.END}")
    time.sleep(2)
    
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
        
        # Import utilities for IP detection
        try:
            from utils import get_network_interfaces
        except ImportError:
            get_network_interfaces = None
        
        # Interactive target IP selection
        print(f"\n{Colors.BOLD}Select Target IP:{Colors.END}")
        print(f"{Colors.GREEN}[1]{Colors.END} Loopback (127.0.0.1) - for basic testing")
        print(f"{Colors.GREEN}[2]{Colors.END} Network Interface IP - for realistic testing")
        print(f"{Colors.GREEN}[3]{Colors.END} Custom IP")
        
        target_choice = input(f"\n{Colors.CYAN}Select target (default: 2): {Colors.END}").strip() or '2'
        
        if target_choice == '1':
            target_ip = "127.0.0.1"
            print(f"{Colors.YELLOW}⚠️  Note: Loopback attacks may not be detected by default{Colors.END}")
            print(f"{Colors.YELLOW}   Enable ALLOW_LOOPBACK_DETECTION in config.py for testing{Colors.END}")
        elif target_choice == '2':
            # Auto-detect network IP
            target_ip = "127.0.0.1"  # Default fallback
            if get_network_interfaces:
                interfaces = get_network_interfaces()
                network_ips = [iface for iface in interfaces 
                             if iface['status'] == 'up' and not iface['name'].startswith('lo')]
                if network_ips and 'ip' in network_ips[0]:
                    target_ip = network_ips[0]['ip']
                else:
                    # Fallback: try to get IP from default interface
                    target_ip = "192.168.1.100"
            print(f"{Colors.GREEN}Using target IP: {target_ip}{Colors.END}")
        else:
            target_ip = input(f"{Colors.CYAN}Enter target IP: {Colors.END}").strip() or "127.0.0.1"
        
        # Launch attack simulation in new terminal
        attack_cmd = f'sudo "{python_exec}" scripts/simulate_attack.py --target {target_ip} --type {attack_type} --count 200'
        
        print(f"\n{Colors.YELLOW}Launching {attack_type.upper()} flood attack in new terminal...{Colors.END}")
        if open_new_terminal(attack_cmd, f"{attack_type.upper()} Attack", use_sudo=False):
            print(f"{Colors.GREEN}✓ Attack simulation launched in new terminal!{Colors.END}")
        else:
            print(f"{Colors.RED}Failed to launch attack terminal{Colors.END}")
            print(f"{Colors.YELLOW}Try running manually: {attack_cmd}{Colors.END}")
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}✓ All components launched successfully!{Colors.END}")
    print(f"\n{Colors.CYAN}Components are running in separate terminal windows:{Colors.END}")
    print(f"  {Colors.GREEN}•{Colors.END} DDoS Detector - Monitor live traffic")
    print(f"  {Colors.GREEN}•{Colors.END} Web Dashboard - http://localhost:5001")
    if attack == 'yes':
        print(f"  {Colors.GREEN}•{Colors.END} Attack Simulation - Sending packets")
    
    print(f"\n{Colors.YELLOW}Close each terminal window manually when done.{Colors.END}")
    print(f"{Colors.CYAN}Check the detector terminal for attack alerts!{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to return to main menu...{Colors.END}")


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
        print(f"{Colors.YELLOW}Please run: sudo python3 main.py{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    script_path = PROJECT_ROOT / "scripts" / "simulate_attack.py"
    
    if not script_path.exists():
        print(f"{Colors.RED}Error: simulate_attack.py not found at {script_path}{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    print(f"""
{Colors.CYAN}This will launch the attack simulation in a NEW terminal window.{Colors.END}
{Colors.GREEN}Your detector and dashboard (if running) will continue running.{Colors.END}

{Colors.YELLOW}Tip: Use option [3] to launch detector + dashboard + attack all at once.{Colors.END}
""")
    
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
    
    python_exec = get_python_executable()
    attack_cmd = f'sudo "{python_exec}" scripts/simulate_attack.py --target {target} --type {attack_type} --count {count}'
    
    if open_new_terminal(attack_cmd, "Attack Simulation"):
        print(f"{Colors.GREEN}✓ Attack simulation launched in new terminal!{Colors.END}")
        print(f"{Colors.CYAN}Check the detector terminal and web dashboard for results.{Colors.END}")
    else:
        print(f"{Colors.RED}✗ Failed to open new terminal{Colors.END}")
        print(f"{Colors.YELLOW}Fallback: Running in current terminal...{Colors.END}\n")
        
        try:
            subprocess.run([
                "sudo",  # Attack script requires root privileges
                python_exec, 
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
    
    # Import after adding to path
    try:
        from utils import get_network_interfaces, get_default_network_interface
        from config.config import NETWORK_INTERFACE
    except ImportError as e:
        print(f"{Colors.RED}Import error: {e}{Colors.END}")
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        return
    
    # Show detected network interfaces
    print(f"\n{Colors.BOLD}Network Interfaces:{Colors.END}")
    interfaces = get_network_interfaces()
    if interfaces:
        for iface in interfaces:
            status_color = Colors.GREEN if iface['status'] == 'up' else Colors.RED
            status_icon = "🟢" if iface['status'] == 'up' else "🔴"
            selected = " (SELECTED)" if iface['name'] == NETWORK_INTERFACE else ""
            print(f"  {status_icon} {iface['name']:<20} "
                  f"Status: {status_color}{iface['status']:<10}{Colors.END} "
                  f"Type: {iface['type']}{Colors.BOLD}{selected}{Colors.END}")
        
        default_iface = get_default_network_interface()
        print(f"\n{Colors.CYAN}Auto-detected interface: {Colors.BOLD}{default_iface}{Colors.END}")
        print(f"{Colors.CYAN}Currently using: {Colors.BOLD}{NETWORK_INTERFACE}{Colors.END}")
    else:
        print(f"{Colors.YELLOW}  No interfaces detected{Colors.END}")
    
    config_path = PROJECT_ROOT / "config" / "config.py"
    
    try:
        if not config_path.exists():
            print(f"\n{Colors.RED}Config file not found at: {config_path}{Colors.END}")
        else:
            print(f"\n{Colors.BOLD}Configuration Settings:{Colors.END}")
            with open(config_path, 'r') as f:
                content = f.read()
                # Extract key settings
                lines = content.split('\n')
                for line in lines:
                    if '=' in line and not line.strip().startswith('#'):
                        if any(keyword in line for keyword in ['THRESHOLD', 'PORT', 'HOST', 'WINDOW', 'ENABLE']):
                            print(f"{Colors.GREEN}  {line.strip()}{Colors.END}")
            
            print("\n" + "=" * 60)
            print(f"\n{Colors.YELLOW}To edit configuration:{Colors.END}")
            print(f"{Colors.CYAN}  nano config/config.py{Colors.END}")
        
    except Exception as e:
        print(f"{Colors.RED}Error reading config: {e}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")


def view_logs():
    """View system logs"""
    print(f"\n{Colors.CYAN}System Logs{Colors.END}")
    print("=" * 60)
    
    logs_dir = PROJECT_ROOT / "logs"
    
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
    
    script_path = PROJECT_ROOT / "scripts" / "unblock_all.sh"
    
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
    python_exec = get_python_executable()
    if tuple(map(int, py_version.split('.'))) >= (3, 8):
        print(f"  {Colors.GREEN}✓ Version: {py_version}{Colors.END}")
        print(f"  {Colors.GREEN}✓ Executable: {python_exec}{Colors.END}")
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
    dirs = ['src', 'config', 'scripts', 'docs', 'logs', 'tests']
    for dir_name in dirs:
        dir_path = PROJECT_ROOT / dir_name
        if dir_path.exists():
            print(f"  {Colors.GREEN}✓ {dir_name}/{Colors.END}")
        else:
            print(f"  {Colors.RED}✗ {dir_name}/ (missing){Colors.END}")
    
    # Check key files
    print(f"\n{Colors.BOLD}Key Files:{Colors.END}")
    key_files = [
        ('config/config.py', 'Configuration'),
        ('src/detector.py', 'Detector'),
        ('src/dashboard.py', 'Dashboard'),
        ('scripts/simulate_attack.py', 'Attack Simulator')
    ]
    
    for file_path, description in key_files:
        full_path = PROJECT_ROOT / file_path
        if full_path.exists():
            print(f"  {Colors.GREEN}✓ {file_path:30} - {description}{Colors.END}")
        else:
            print(f"  {Colors.RED}✗ {file_path:30} - {description} (missing){Colors.END}")
    
    # Overall status
    print("\n" + "=" * 60)
    if system == 'Linux' and check_root():
        print(f"{Colors.GREEN}{Colors.BOLD}✓ System ready for full operation!{Colors.END}")
    elif system == 'Linux':
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠  Run with sudo for full functionality{Colors.END}")
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠  Use Linux VM for full testing (see docs/WINDOWS_TESTING_GUIDE.md){Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

if __name__ == "__main__":
    while True:
        clear_screen()
        print_banner()
        print_menu()
        
        choice = input(f"{Colors.CYAN}Select an option (0-9): {Colors.END}").strip()
        
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
            # Placeholder for test suite
            print(f"\n{Colors.CYAN}Running test suite...{Colors.END}")
            # Here you would call your test functions
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        elif choice == '0':
            print(f"\n{Colors.CYAN}Exiting. Goodbye!{Colors.END}\n")
            break
        else:
            print(f"{Colors.RED}Invalid option. Please try again.{Colors.END}")
            time.sleep(2)

