"""
Phase 3, 4 & 6: Detection + Mitigation + Logging & Monitoring - Complete System
Real-Time DDoS Detection System

This script detects DDoS attacks in real-time by:
- Tracking packet counts per IP address
- Detecting SYN flood attacks
- Using threshold-based rules
- Implementing 5-second time windows
- Thread-safe counting with locks
- Automatic IP blocking using iptables (Phase 4)
- Comprehensive logging and monitoring (Phase 6)
- Beautiful CLI dashboard with Rich library
"""

import threading
from collections import defaultdict
from scapy.all import IP, TCP, UDP, sniff
from mitigator import Mitigator
from logger import get_logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from datetime import datetime
import time
import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import configuration from central config file
try:
    from config.config import (
        NETWORK_INTERFACE,
        PACKET_THRESHOLD,
        SYN_THRESHOLD,
        TIME_WINDOW
    )
except ImportError:
    # Fallback defaults if config not available
    NETWORK_INTERFACE = "wlp1s0"
    PACKET_THRESHOLD = 100
    SYN_THRESHOLD = 50
    TIME_WINDOW = 5.0

# --- DATA STRUCTURES ---
# Use locks to make dictionary access thread-safe
counts_lock = threading.Lock()
ip_packet_counts = defaultdict(int)
ip_syn_counts = defaultdict(int)

# File lock for stats.json to prevent corruption
stats_file_lock = threading.Lock()

# Cache of blocked IPs to avoid repeated lock acquisition
blocked_ips_cache = set()
blocked_cache_lock = threading.Lock()

# --- MITIGATION MODULE ---
# Initialize the IP blocking module
mitigator = Mitigator()

# Track attacked IPs to prevent duplicate attack counting
attacked_ips_this_window = set()
attacked_ips_lock = threading.Lock()

# --- LOGGING MODULE (Phase 6) ---
# Initialize comprehensive logging
logger = get_logger()
logger.log_system_event("Initializing DDoS Detection System")
logger.log_threshold_config(PACKET_THRESHOLD, SYN_THRESHOLD, TIME_WINDOW)

# --- RICH CONSOLE (Phase 6) ---
# Initialize Rich console for beautiful CLI output
console = Console()

# Statistics tracking
stats = {
    "total_packets": 0,
    "total_attacks_detected": 0,
    "start_time": datetime.now()
}

def create_dashboard() -> Table:
    """
    Create a beautiful dashboard table for displaying traffic statistics.
    
    Returns:
        Table: Rich table with current statistics
    """
    # Main statistics table
    table = Table(title="🛡️  Real-Time Traffic Monitor", 
                  title_style="bold cyan",
                  show_header=True,
                  header_style="bold magenta",
                  border_style="blue")
    
    table.add_column("IP Address", style="cyan", width=18)
    table.add_column("Packets", justify="right", style="green", width=10)
    table.add_column("SYN Count", justify="right", style="yellow", width=10)
    table.add_column("Status", justify="center", style="bold", width=15)
    
    with counts_lock:
        if ip_packet_counts:
            # Sort by packet count descending, show top 15
            sorted_ips = sorted(ip_packet_counts.items(), 
                              key=lambda x: x[1], reverse=True)[:15]
            
            for ip, count in sorted_ips:
                syn_count = ip_syn_counts.get(ip, 0)
                
                # Determine status
                if mitigator.is_blocked(ip):
                    status = "[red]🔒 BLOCKED[/red]"
                    row_style = "dim"
                elif count > PACKET_THRESHOLD or syn_count > SYN_THRESHOLD:
                    status = "[red]⚠️  ALERT[/red]"
                    row_style = "bold red"
                elif count > PACKET_THRESHOLD * 0.7 or syn_count > SYN_THRESHOLD * 0.7:
                    status = "[yellow]⚡ WARNING[/yellow]"
                    row_style = "yellow"
                else:
                    status = "[green]✓ Normal[/green]"
                    row_style = ""
                
                table.add_row(
                    ip,
                    str(count),
                    str(syn_count),
                    status,
                    style=row_style
                )
        else:
            table.add_row("No traffic", "-", "-", "[dim]Idle[/dim]")
    
    return table


def create_status_panel() -> Panel:
    """
    Create a status panel with system information.
    
    Returns:
        Panel: Rich panel with system status
    """
    uptime = datetime.now() - stats["start_time"]
    uptime_str = str(uptime).split('.')[0]  # Remove microseconds
    
    status_text = Text()
    status_text.append("System Status\n", style="bold underline cyan")
    status_text.append(f"Interface: ", style="bold")
    status_text.append(f"{NETWORK_INTERFACE}\n", style="cyan")
    status_text.append(f"Uptime: ", style="bold")
    status_text.append(f"{uptime_str}\n", style="green")
    status_text.append(f"Total Packets: ", style="bold")
    status_text.append(f"{stats['total_packets']:,}\n", style="yellow")
    status_text.append(f"Attacks Detected: ", style="bold")
    status_text.append(f"{stats['total_attacks_detected']}\n", style="red")
    status_text.append(f"Blocked IPs: ", style="bold")
    status_text.append(f"{mitigator.get_blocked_count()}\n", style="red")
    
    return Panel(status_text, title="📊 System Info", border_style="green")


def create_thresholds_panel() -> Panel:
    """
    Create a panel showing configured thresholds.
    
    Returns:
        Panel: Rich panel with threshold configuration
    """
    threshold_text = Text()
    threshold_text.append("Detection Thresholds\n", style="bold underline magenta")
    threshold_text.append(f"Packet Limit: ", style="bold")
    threshold_text.append(f"{PACKET_THRESHOLD} per {TIME_WINDOW}s\n", style="cyan")
    threshold_text.append(f"SYN Limit: ", style="bold")
    threshold_text.append(f"{SYN_THRESHOLD} per {TIME_WINDOW}s\n", style="cyan")
    threshold_text.append(f"Time Window: ", style="bold")
    threshold_text.append(f"{TIME_WINDOW} seconds", style="cyan")
    
    return Panel(threshold_text, title="⚙️  Configuration", border_style="yellow")


# Global timer reference for proper cleanup
reset_timer = None
shutdown_flag = threading.Event()

def reset_counts():
    """Resets the traffic counters every TIME_WINDOW seconds and displays dashboard"""
    global ip_packet_counts, ip_syn_counts, attacked_ips_this_window, reset_timer
    
    if shutdown_flag.is_set():
        return  # Stop if shutdown requested
    
    with counts_lock:
        if ip_packet_counts:
            # Log traffic summary
            summary_data = {
                "unique_ips": len(ip_packet_counts),
                "total_packets": sum(ip_packet_counts.values()),
                "total_syn": sum(ip_syn_counts.values()),
                "top_talker": max(ip_packet_counts.items(), key=lambda x: x[1])[0]
            }
            logger.log_traffic_summary(summary_data)
            
            # Write stats to JSON file for web dashboard with file lock
            try:
                stats_data = {
                    'packet_counts': dict(sorted(ip_packet_counts.items(), 
                                                key=lambda x: x[1], reverse=True)[:10]),
                    'blocked_ips': list(mitigator.get_blocked_ips()),
                    'total_packets': stats['total_packets'],
                    'attacks_detected': stats['total_attacks_detected'],
                    'timestamp': datetime.now().isoformat(),
                    'detector_running': True
                }
                with stats_file_lock:
                    with open('stats.json', 'w') as f:
                        json.dump(stats_data, f, indent=2)
            except Exception as e:
                logger.log_error(f"Failed to write stats.json: {e}", e)
        
        # Clear counts for next window
        ip_packet_counts.clear()
        ip_syn_counts.clear()
    
    # Clear attacked IPs tracking for new window
    with attacked_ips_lock:
        attacked_ips_this_window.clear()
    
    # Schedule this function to run again if not shutting down
    if not shutdown_flag.is_set():
        reset_timer = threading.Timer(TIME_WINDOW, reset_counts)
        reset_timer.daemon = True
        reset_timer.start()

def process_packet(packet):
    """This function is called for every packet sniffed"""
    
    # Update total packet count
    stats["total_packets"] += 1
    
    # Check if it's an IP packet
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Basic packet validation
        if not src_ip or src_ip == "0.0.0.0":
            return
        
        # Check blocked IPs cache first (faster than acquiring mitigator lock)
        with blocked_cache_lock:
            if src_ip in blocked_ips_cache:
                return
        
        # Variables to track if attack detected
        packet_flood_detected = False
        syn_flood_detected = False
        current_packet_count = 0
        current_syn_count = 0
        
        # Update counts with thread lock AND check thresholds atomically
        with counts_lock:
            ip_packet_counts[src_ip] += 1
            current_packet_count = ip_packet_counts[src_ip]
            
            # Check for SYN packets (potential SYN flood)
            if packet.haslayer(TCP) and packet[TCP].flags == 'S':
                ip_syn_counts[src_ip] += 1
                current_syn_count = ip_syn_counts[src_ip]
            else:
                current_syn_count = ip_syn_counts[src_ip]
            
            # Check thresholds inside lock to prevent race condition
            packet_flood_detected = current_packet_count > PACKET_THRESHOLD
            syn_flood_detected = current_syn_count > SYN_THRESHOLD
        
        # Now handle attacks outside the lock
        attack_detected = False
        
        # Check if this IP already triggered an attack this window
        with attacked_ips_lock:
            if src_ip in attacked_ips_this_window:
                # Already counted this IP's attack in this window
                return
            
            if packet_flood_detected or syn_flood_detected:
                # Mark this IP as having attacked in this window
                attacked_ips_this_window.add(src_ip)
                attack_detected = True
        
        if not attack_detected:
            return
        
        # Increment attack counter only once per IP per window
        stats["total_attacks_detected"] += 1
        
        # Determine attack type
        if packet_flood_detected and syn_flood_detected:
            attack_type = "PACKET_FLOOD + SYN_FLOOD"
        elif packet_flood_detected:
            attack_type = "PACKET_FLOOD"
        else:
            attack_type = "SYN_FLOOD"
        
        # Log the attack
        logger.log_attack_detected(
            ip_address=src_ip,
            attack_type=attack_type,
            threshold=PACKET_THRESHOLD if packet_flood_detected else SYN_THRESHOLD,
            current_count=current_packet_count if packet_flood_detected else current_syn_count,
            additional_info={
                "destination_ip": dst_ip,
                "destination_port": packet[TCP].dport if packet.haslayer(TCP) else None,
                "time_window": TIME_WINDOW,
                "packet_count": current_packet_count,
                "syn_count": current_syn_count
            }
        )
        
        console.print(f"\n[bold red]🚨 ALERT: {attack_type} detected from {src_ip}[/bold red]")
        if packet_flood_detected:
            console.print(f"[yellow]   Packet Count: {current_packet_count} (threshold: {PACKET_THRESHOLD})[/yellow]")
        if syn_flood_detected:
            console.print(f"[yellow]   SYN Count: {current_syn_count} (threshold: {SYN_THRESHOLD})[/yellow]")
        console.print()
        
        # Phase 4: Call mitigation module to block IP
        success = mitigator.block_ip(src_ip)
        
        # Update blocked IPs cache
        if success:
            with blocked_cache_lock:
                blocked_ips_cache.add(src_ip)
        
        # Log the blocking action (only once)
        logger.log_ip_blocked(src_ip, attack_type, success)

if __name__ == "__main__":
    # Display startup banner
    console.print("\n[bold cyan]" + "="*70 + "[/bold cyan]")
    console.print("[bold cyan]DDoS DETECTION & MITIGATION SYSTEM[/bold cyan]", justify="center")
    console.print("[bold cyan]Phase 3, 4 & 6 COMPLETE - Full System[/bold cyan]", justify="center")
    console.print("[bold cyan]" + "="*70 + "[/bold cyan]\n")
    
    # Display configuration
    console.print(create_status_panel())
    console.print(create_thresholds_panel())
    
    console.print("\n[bold green]🛡️  Mitigation: ENABLED[/bold green] (iptables)")
    console.print("[bold yellow]� Logging: ENABLED[/bold yellow] (logs/ directory)")
    console.print("[bold yellow]⚠️  Warning: Malicious IPs will be automatically blocked![/bold yellow]")
    console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")
    
    logger.log_system_event("DDoS Detection System fully initialized")
    
    # Start the count reset timer
    console.print(f"[cyan]Starting {TIME_WINDOW}s traffic monitoring...[/cyan]\n")
    reset_thread = threading.Timer(TIME_WINDOW, reset_counts)
    reset_thread.daemon = True
    reset_thread.start()
    
    # Start live dashboard in a separate thread
    def display_dashboard():
        """Display live updating dashboard"""
        try:
            with Live(create_dashboard(), refresh_per_second=2, console=console) as live:
                while True:
                    time.sleep(0.5)
                    live.update(create_dashboard())
        except KeyboardInterrupt:
            pass
    
    # Start dashboard thread
    dashboard_thread = threading.Thread(target=display_dashboard, daemon=True)
    dashboard_thread.start()
    
    try:
        console.print(f"[green]Monitoring traffic on {NETWORK_INTERFACE}...[/green]\n")
        logger.log_system_event(f"Started monitoring on interface: {NETWORK_INTERFACE}")
        
        # Start packet sniffing
        sniff(iface=NETWORK_INTERFACE, prn=process_packet, store=0)
        
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Shutting down...[/bold yellow]\n")
        logger.log_system_event("Shutdown initiated by user")
        
        # Display final statistics
        console.print("[bold cyan]" + "="*70 + "[/bold cyan]")
        console.print("[bold cyan]Final Statistics[/bold cyan]", justify="center")
        console.print("[bold cyan]" + "="*70 + "[/bold cyan]\n")
        
        uptime = datetime.now() - stats["start_time"]
        
        final_stats = {
            "uptime": str(uptime).split('.')[0],
            "total_packets": stats['total_packets'],
            "attacks_detected": stats['total_attacks_detected'],
            "ips_blocked": mitigator.get_blocked_count()
        }
        
        stats_table = Table(show_header=False, border_style="cyan")
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Uptime", final_stats["uptime"])
        stats_table.add_row("Total Packets Processed", f"{final_stats['total_packets']:,}")
        stats_table.add_row("Attacks Detected", str(final_stats['attacks_detected']))
        stats_table.add_row("IPs Blocked", str(final_stats['ips_blocked']))
        
        console.print(stats_table)
        
        if mitigator.get_blocked_count() > 0:
            console.print(f"\n[red]Blocked IPs:[/red]")
            for ip in mitigator.get_blocked_ips():
                console.print(f"  [red]🔒 {ip}[/red]")
        
        # Log shutdown with stats
        logger.log_shutdown(final_stats)
        
        # Display log file locations
        console.print("\n[bold yellow]� Log Files:[/bold yellow]")
        log_summary = logger.get_log_summary()
        for key, value in log_summary.items():
            if not key.endswith("_size"):
                size_key = f"{key}_size"
                size = log_summary.get(size_key, "")
                console.print(f"  [cyan]{key}:[/cyan] {value} {size}")
        
        console.print("\n[bold green]✅ Shutdown complete![/bold green]\n")
        
    except PermissionError:
        console.print("\n[bold red]❌ ERROR: Permission denied![/bold red]")
        console.print("[yellow]Run this script with sudo:[/yellow]")
        console.print("  [cyan]source venv/bin/activate[/cyan]")
        console.print(f"  [cyan]sudo $(which python3) ddos_detector.py[/cyan]\n")
        logger.log_error("Permission denied - requires root privileges")
        
    except Exception as e:
        console.print(f"\n[bold red]❌ ERROR: {e}[/bold red]")
        console.print("[yellow]Make sure:[/yellow]")
        console.print(f"  1. Network interface '{NETWORK_INTERFACE}' exists (check with: ip a)")
        console.print("  2. You have root privileges (run with sudo)\n")
        logger.log_error(f"Runtime error: {e}", e)


