"""
Advanced DDoS/DoS Detection System - Unified Detector

This is the SINGLE detection engine that handles:
- DoS Detection: Per-IP threshold monitoring (single source attacks)
- DDoS Detection: Aggregate threshold monitoring (distributed attacks)
- IP Spike Detection: Sudden appearance of many new source IPs
- Low-and-Slow Detection: Many sources each under threshold
- ICMP/UDP/SYN Flood Detection: Protocol-specific attack patterns

All configuration is loaded from config/config.py for clean separation.

Usage:
    sudo python3 src/detector.py

Author: PyDOS Project
"""

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Set, List, Tuple, Optional, Any
import time
import json
import sys
from pathlib import Path

# Third-party imports
from scapy.all import IP, TCP, UDP, ICMP, sniff
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# CONFIGURATION - All settings loaded from config/config.py
try:
    from config.config import (
        # Network
        NETWORK_INTERFACE,
        ALLOW_LOOPBACK_DETECTION,
        TIME_WINDOW,
        # Per-IP thresholds (DoS)
        PACKET_THRESHOLD,
        SYN_THRESHOLD,
        UDP_THRESHOLD,
        ICMP_THRESHOLD,
        # Aggregate thresholds (DDoS)
        AGGREGATE_PACKET_THRESHOLD,
        AGGREGATE_SYN_THRESHOLD,
        AGGREGATE_UDP_THRESHOLD,
        AGGREGATE_ICMP_THRESHOLD,
        # IP Spike detection
        NEW_IP_SPIKE_THRESHOLD,
        # Low-and-slow detection
        LOW_SLOW_MIN_SOURCES,
        LOW_SLOW_PER_IP_MAX,
        LOW_SLOW_AGGREGATE_MIN,
        # Feature flags
        ENABLE_AUTO_BLOCKING,
    )
    CONFIG_LOADED = True
except ImportError as e:
    print(f"[WARNING] Could not load config: {e}")
    print("[WARNING] Using default values")
    CONFIG_LOADED = False
    # Fallback defaults
    NETWORK_INTERFACE = "eth0"
    ALLOW_LOOPBACK_DETECTION = True
    TIME_WINDOW = 5.0
    PACKET_THRESHOLD = 100
    SYN_THRESHOLD = 50
    UDP_THRESHOLD = 50
    ICMP_THRESHOLD = 50
    AGGREGATE_PACKET_THRESHOLD = 1000
    AGGREGATE_SYN_THRESHOLD = 500
    AGGREGATE_UDP_THRESHOLD = 500
    AGGREGATE_ICMP_THRESHOLD = 300
    NEW_IP_SPIKE_THRESHOLD = 50
    LOW_SLOW_MIN_SOURCES = 20
    LOW_SLOW_PER_IP_MAX = 50
    LOW_SLOW_AGGREGATE_MIN = 500
    ENABLE_AUTO_BLOCKING = True

# Import local modules
from mitigator import Mitigator
from logger import get_logger
from utils import is_private_or_localhost


# DATA CLASSES

@dataclass
class Alert:
    """Represents a detection alert (DoS or DDoS)"""
    timestamp: datetime
    attack_type: str
    source_ip: str  # Single IP for DoS, "DISTRIBUTED" for DDoS
    severity: str  # 'low', 'medium', 'high', 'critical'
    description: str
    packet_count: int
    threshold: int
    source_count: int = 1
    additional_info: Dict[str, Any] = field(default_factory=dict)


# UNIFIED DETECTOR CLASS
class UnifiedDetector:
    """
    Advanced unified detection engine for both DoS and DDoS attacks.
    
    This class consolidates all detection logic into a single, well-organized
    component that handles per-IP monitoring, aggregate monitoring, and
    pattern-based detection.
    """
    
    def __init__(self):
        """Initialize the detector with all counters and components."""
        # Thread safety
        self.lock = threading.RLock()
        
        # Per-IP counters (DoS detection)
        self.ip_packet_counts: Dict[str, int] = defaultdict(int)
        self.ip_syn_counts: Dict[str, int] = defaultdict(int)
        self.ip_udp_counts: Dict[str, int] = defaultdict(int)
        self.ip_icmp_counts: Dict[str, int] = defaultdict(int)
        
        # Aggregate counters (DDoS detection)
        self.total_packets = 0
        self.total_syn = 0
        self.total_udp = 0
        self.total_icmp = 0
        
        # IP tracking for spike detection
        self.known_ips: Set[str] = set()
        self.window_new_ips: Set[str] = set()
        self.window_all_ips: Set[str] = set()
        
        # Attack tracking (prevent duplicate alerts per window)
        self.dos_alerts_this_window: Set[str] = set()  # IPs that triggered DoS alerts
        self.ddos_alerts_this_window: Set[str] = set()  # DDoS alert types triggered
        
        # Statistics
        self.stats = {
            "total_packets_all_time": 0,
            "dos_attacks_detected": 0,
            "ddos_attacks_detected": 0,
            "ips_blocked": 0,
            "start_time": datetime.now()
        }
        
        # Components
        self.mitigator = Mitigator()
        self.logger = get_logger()
        self.console = Console()
        
        # Blocked IPs cache for fast lookup
        self.blocked_ips_cache: Set[str] = set()
        
        # All alerts history
        self.alerts: List[Alert] = []
        
        # Window management
        self.window_start = datetime.now()
        self.shutdown_flag = threading.Event()
        
        # Log initialization
        self.logger.log_system_event("Unified Detector initialized")
        self.logger.log_system_event(f"DoS Thresholds - Packets: {PACKET_THRESHOLD}, SYN: {SYN_THRESHOLD}, UDP: {UDP_THRESHOLD}, ICMP: {ICMP_THRESHOLD}")
        self.logger.log_system_event(f"DDoS Thresholds - Packets: {AGGREGATE_PACKET_THRESHOLD}, SYN: {AGGREGATE_SYN_THRESHOLD}, UDP: {AGGREGATE_UDP_THRESHOLD}")
        self.logger.log_system_event(f"IP Spike Threshold: {NEW_IP_SPIKE_THRESHOLD} new IPs per window")
    
    # PACKET PROCESSING
    def process_packet(self, packet) -> None:
        """
        Process a single captured packet.
        
        This is the main entry point called by the sniffer for each packet.
        It updates counters and checks for both DoS and DDoS attacks.
        """
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Validate IP
        if not src_ip or src_ip == "0.0.0.0":
            return
        
        # Skip private/loopback unless testing
        if not ALLOW_LOOPBACK_DETECTION and is_private_or_localhost(src_ip):
            return
        
        # Skip already blocked IPs
        if src_ip in self.blocked_ips_cache:
            return
        
        # Determine packet type
        packet_type = self._get_packet_type(packet)
        
        with self.lock:
            # Update all counters
            self._update_counters(src_ip, packet_type)
            
            # Check for DoS attack (per-IP thresholds)
            self._check_dos_attack(src_ip, dst_ip, packet)
            
            # Check for DDoS attacks (aggregate thresholds)
            self._check_ddos_attacks()
    
    def _get_packet_type(self, packet) -> str:
        """Determine the type of packet."""
        if packet.haslayer(TCP):
            if packet[TCP].flags == 'S':
                return 'syn'
            return 'tcp'
        elif packet.haslayer(UDP):
            return 'udp'
        elif packet.haslayer(ICMP):
            return 'icmp'
        return 'other'
    
    def _update_counters(self, src_ip: str, packet_type: str) -> None:
        """Update all packet counters."""
        # Per-IP counters
        self.ip_packet_counts[src_ip] += 1
        
        if packet_type == 'syn':
            self.ip_syn_counts[src_ip] += 1
            self.total_syn += 1
        elif packet_type == 'udp':
            self.ip_udp_counts[src_ip] += 1
            self.total_udp += 1
        elif packet_type == 'icmp':
            self.ip_icmp_counts[src_ip] += 1
            self.total_icmp += 1
        
        # Aggregate counters
        self.total_packets += 1
        self.stats["total_packets_all_time"] += 1
        
        # IP tracking
        self.window_all_ips.add(src_ip)
        if src_ip not in self.known_ips:
            self.window_new_ips.add(src_ip)
    
    # DoS DETECTION (Per-IP)
    def _check_dos_attack(self, src_ip: str, dst_ip: str, packet) -> None:
        """Check if a single IP exceeds per-IP thresholds (DoS attack)."""
        # Skip if already alerted this window
        if src_ip in self.dos_alerts_this_window:
            return
        
        # Get current counts
        packet_count = self.ip_packet_counts[src_ip]
        syn_count = self.ip_syn_counts[src_ip]
        udp_count = self.ip_udp_counts[src_ip]
        icmp_count = self.ip_icmp_counts[src_ip]
        
        # Check thresholds
        attack_types = []
        if packet_count > PACKET_THRESHOLD:
            attack_types.append("PACKET_FLOOD")
        if syn_count > SYN_THRESHOLD:
            attack_types.append("SYN_FLOOD")
        if udp_count > UDP_THRESHOLD:
            attack_types.append("UDP_FLOOD")
        if icmp_count > ICMP_THRESHOLD:
            attack_types.append("ICMP_FLOOD")
        
        if not attack_types:
            return
        
        # Attack detected!
        self.dos_alerts_this_window.add(src_ip)
        self.stats["dos_attacks_detected"] += 1
        
        attack_type = " + ".join(attack_types)
        
        # Create alert
        alert = Alert(
            timestamp=datetime.now(),
            attack_type=f"DoS: {attack_type}",
            source_ip=src_ip,
            severity=self._calculate_severity(packet_count, PACKET_THRESHOLD),
            description=f"DoS attack from {src_ip}",
            packet_count=packet_count,
            threshold=PACKET_THRESHOLD,
            additional_info={
                "syn_count": syn_count,
                "udp_count": udp_count,
                "icmp_count": icmp_count,
                "destination_ip": dst_ip
            }
        )
        self.alerts.append(alert)
        
        # Log and display
        self._display_dos_alert(src_ip, attack_type, packet_count, syn_count, udp_count, icmp_count)
        self.logger.log_attack_detected(src_ip, attack_type, PACKET_THRESHOLD, packet_count)
        
        # Block the IP
        if ENABLE_AUTO_BLOCKING:
            self._block_ip(src_ip, attack_type)
    
    def _display_dos_alert(self, ip: str, attack_type: str, packets: int, 
                           syn: int, udp: int, icmp: int) -> None:
        """Display DoS alert in console."""
        self.console.print(f"\n[bold red]🚨 DoS ALERT: {attack_type} from {ip}[/bold red]")
        self.console.print(f"[yellow]   Packets: {packets}/{PACKET_THRESHOLD} | SYN: {syn}/{SYN_THRESHOLD} | UDP: {udp}/{UDP_THRESHOLD} | ICMP: {icmp}/{ICMP_THRESHOLD}[/yellow]\n")
    
    # DDoS DETECTION (Aggregate)
    def _check_ddos_attacks(self) -> None:
        """Check for distributed attacks using aggregate thresholds."""
        self._check_aggregate_syn_flood()
        self._check_aggregate_udp_flood()
        self._check_aggregate_icmp_flood()
        self._check_aggregate_packet_flood()
        self._check_ip_spike()
        self._check_low_and_slow()
    
    def _check_aggregate_syn_flood(self) -> None:
        """Check for distributed SYN flood."""
        if 'ddos_syn' in self.ddos_alerts_this_window:
            return
        if self.total_syn <= AGGREGATE_SYN_THRESHOLD:
            return
        
        self.ddos_alerts_this_window.add('ddos_syn')
        self._trigger_ddos_alert(
            "DISTRIBUTED_SYN_FLOOD",
            self.total_syn,
            AGGREGATE_SYN_THRESHOLD,
            f"Distributed SYN flood from {len(self.window_all_ips)} sources"
        )
    
    def _check_aggregate_udp_flood(self) -> None:
        """Check for distributed UDP flood."""
        if 'ddos_udp' in self.ddos_alerts_this_window:
            return
        if self.total_udp <= AGGREGATE_UDP_THRESHOLD:
            return
        
        self.ddos_alerts_this_window.add('ddos_udp')
        self._trigger_ddos_alert(
            "DISTRIBUTED_UDP_FLOOD",
            self.total_udp,
            AGGREGATE_UDP_THRESHOLD,
            f"Distributed UDP flood from {len(self.window_all_ips)} sources"
        )
    
    def _check_aggregate_icmp_flood(self) -> None:
        """Check for distributed ICMP flood."""
        if 'ddos_icmp' in self.ddos_alerts_this_window:
            return
        if self.total_icmp <= AGGREGATE_ICMP_THRESHOLD:
            return
        
        self.ddos_alerts_this_window.add('ddos_icmp')
        self._trigger_ddos_alert(
            "DISTRIBUTED_ICMP_FLOOD",
            self.total_icmp,
            AGGREGATE_ICMP_THRESHOLD,
            f"Distributed ICMP flood from {len(self.window_all_ips)} sources"
        )
    
    def _check_aggregate_packet_flood(self) -> None:
        """Check for distributed packet flood."""
        if 'ddos_packet' in self.ddos_alerts_this_window:
            return
        if self.total_packets <= AGGREGATE_PACKET_THRESHOLD:
            return
        
        self.ddos_alerts_this_window.add('ddos_packet')
        self._trigger_ddos_alert(
            "DISTRIBUTED_PACKET_FLOOD",
            self.total_packets,
            AGGREGATE_PACKET_THRESHOLD,
            f"Distributed packet flood from {len(self.window_all_ips)} sources"
        )
    
    def _check_ip_spike(self) -> None:
        """Check for sudden spike in new source IPs (botnet indicator)."""
        if 'ip_spike' in self.ddos_alerts_this_window:
            return
        if len(self.window_new_ips) <= NEW_IP_SPIKE_THRESHOLD:
            return
        
        self.ddos_alerts_this_window.add('ip_spike')
        elapsed = (datetime.now() - self.window_start).total_seconds()
        rate = len(self.window_new_ips) / max(elapsed, 0.1)
        
        self._trigger_ddos_alert(
            "IP_SPIKE_ATTACK",
            len(self.window_new_ips),
            NEW_IP_SPIKE_THRESHOLD,
            f"Sudden spike of {len(self.window_new_ips)} new IPs ({rate:.1f}/sec)"
        )
    
    def _check_low_and_slow(self) -> None:
        """Check for low-and-slow attacks (many sources under threshold)."""
        if 'low_slow' in self.ddos_alerts_this_window:
            return
        
        # Count sources with low traffic
        low_traffic_sources = sum(
            1 for count in self.ip_packet_counts.values()
            if 0 < count <= LOW_SLOW_PER_IP_MAX
        )
        
        if (low_traffic_sources >= LOW_SLOW_MIN_SOURCES and
            self.total_packets >= LOW_SLOW_AGGREGATE_MIN):
            
            self.ddos_alerts_this_window.add('low_slow')
            avg = self.total_packets / max(len(self.ip_packet_counts), 1)
            
            self._trigger_ddos_alert(
                "LOW_AND_SLOW_ATTACK",
                self.total_packets,
                LOW_SLOW_AGGREGATE_MIN,
                f"Low-and-slow: {low_traffic_sources} sources, ~{avg:.0f} packets each"
            )
    
    def _trigger_ddos_alert(self, attack_type: str, current: int, 
                            threshold: int, description: str) -> None:
        """Trigger a DDoS alert."""
        self.stats["ddos_attacks_detected"] += 1
        
        alert = Alert(
            timestamp=datetime.now(),
            attack_type=f"DDoS: {attack_type}",
            source_ip="DISTRIBUTED",
            severity=self._calculate_severity(current, threshold),
            description=description,
            packet_count=current,
            threshold=threshold,
            source_count=len(self.window_all_ips),
            additional_info={
                "unique_ips": len(self.window_all_ips),
                "new_ips": len(self.window_new_ips),
                "top_sources": self._get_top_sources(5)
            }
        )
        self.alerts.append(alert)
        
        # Display alert
        self.console.print(f"\n[bold red on yellow]🚨🚨 DDoS ALERT: {attack_type} 🚨🚨[/bold red on yellow]")
        self.console.print(f"[red]   Severity: {alert.severity.upper()}[/red]")
        self.console.print(f"[yellow]   {description}[/yellow]")
        self.console.print(f"[yellow]   Count: {current} | Threshold: {threshold} | Sources: {len(self.window_all_ips)}[/yellow]\n")
        
        # Log
        self.logger.log_attack_detected("DISTRIBUTED", attack_type, threshold, current, {
            "source_count": len(self.window_all_ips),
            "description": description
        })
    
    # MITIGATION
    def _block_ip(self, ip: str, attack_type: str) -> None:
        """Block an attacking IP address."""
        success = self.mitigator.block_ip(ip)
        if success:
            self.blocked_ips_cache.add(ip)
            self.stats["ips_blocked"] += 1
        self.logger.log_ip_blocked(ip, attack_type, success)
    
    # WINDOW MANAGEMENT
    def reset_window(self) -> None:
        """Reset counters for new detection window."""
        with self.lock:
            # Log summary before reset
            if self.total_packets > 0:
                self.logger.log_traffic_summary({
                    "unique_ips": len(self.window_all_ips),
                    "total_packets": self.total_packets,
                    "total_syn": self.total_syn,
                    "total_udp": self.total_udp,
                    "total_icmp": self.total_icmp
                })
            
            # Write stats to JSON for dashboard
            self._write_stats_json()
            
            # Update known IPs
            self.known_ips.update(self.window_new_ips)
            
            # Reset all window-specific data
            self.ip_packet_counts.clear()
            self.ip_syn_counts.clear()
            self.ip_udp_counts.clear()
            self.ip_icmp_counts.clear()
            self.total_packets = 0
            self.total_syn = 0
            self.total_udp = 0
            self.total_icmp = 0
            self.window_new_ips.clear()
            self.window_all_ips.clear()
            self.dos_alerts_this_window.clear()
            self.ddos_alerts_this_window.clear()
            self.window_start = datetime.now()
    
    def _write_stats_json(self) -> None:
        """Write current stats to JSON file for web dashboard."""
        try:
            stats_data = {
                'packet_counts': dict(sorted(
                    self.ip_packet_counts.items(),
                    key=lambda x: x[1], reverse=True
                )[:10]),
                'blocked_ips': list(self.mitigator.get_blocked_ips()),
                'total_packets': self.stats["total_packets_all_time"],
                'dos_attacks': self.stats["dos_attacks_detected"],
                'ddos_attacks': self.stats["ddos_attacks_detected"],
                'unique_ips': len(self.window_all_ips),
                'timestamp': datetime.now().isoformat(),
                'detector_running': True
            }
            with open('stats.json', 'w') as f:
                json.dump(stats_data, f, indent=2)
        except Exception as e:
            self.logger.log_error(f"Failed to write stats.json: {e}")
    
    # UTILITIES
    def _calculate_severity(self, current: int, threshold: int) -> str:
        """Calculate alert severity based on threshold exceedance."""
        ratio = current / max(threshold, 1)
        if ratio >= 10:
            return 'critical'
        elif ratio >= 5:
            return 'high'
        elif ratio >= 2:
            return 'medium'
        return 'low'
    
    def _get_top_sources(self, n: int) -> List[Tuple[str, int]]:
        """Get top N source IPs by packet count."""
        return sorted(self.ip_packet_counts.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current detector statistics."""
        with self.lock:
            uptime = datetime.now() - self.stats["start_time"]
            return {
                "uptime": str(uptime).split('.')[0],
                "total_packets": self.stats["total_packets_all_time"],
                "dos_attacks": self.stats["dos_attacks_detected"],
                "ddos_attacks": self.stats["ddos_attacks_detected"],
                "ips_blocked": self.stats["ips_blocked"],
                "current_window_packets": self.total_packets,
                "unique_ips": len(self.window_all_ips),
                "known_ips": len(self.known_ips)
            }
    
    def get_recent_alerts(self, limit: int = 10) -> List[Alert]:
        """Get most recent alerts."""
        return self.alerts[-limit:]
    
    # DASHBOARD
    def create_traffic_table(self) -> Table:
        """Create traffic monitoring table for CLI dashboard."""
        table = Table(
            title="🛡️ Real-Time Traffic Monitor",
            title_style="bold cyan",
            show_header=True,
            header_style="bold magenta",
            border_style="blue"
        )
        
        table.add_column("IP Address", style="cyan", width=18)
        table.add_column("Packets", justify="right", style="green", width=8)
        table.add_column("SYN", justify="right", style="yellow", width=6)
        table.add_column("UDP", justify="right", style="blue", width=6)
        table.add_column("ICMP", justify="right", style="magenta", width=6)
        table.add_column("Status", justify="center", width=15)
        
        with self.lock:
            if self.ip_packet_counts:
                sorted_ips = sorted(
                    self.ip_packet_counts.items(),
                    key=lambda x: x[1], reverse=True
                )[:15]
                
                for ip, count in sorted_ips:
                    syn = self.ip_syn_counts.get(ip, 0)
                    udp = self.ip_udp_counts.get(ip, 0)
                    icmp = self.ip_icmp_counts.get(ip, 0)
                    
                    # Determine status
                    if self.mitigator.is_blocked(ip):
                        status = "[red]🔒 BLOCKED[/red]"
                        style = "dim"
                    elif (count > PACKET_THRESHOLD or syn > SYN_THRESHOLD or 
                          udp > UDP_THRESHOLD or icmp > ICMP_THRESHOLD):
                        status = "[red]⚠️ ALERT[/red]"
                        style = "bold red"
                    elif (count > PACKET_THRESHOLD * 0.7 or syn > SYN_THRESHOLD * 0.7):
                        status = "[yellow]⚡ WARNING[/yellow]"
                        style = "yellow"
                    else:
                        status = "[green]✓ Normal[/green]"
                        style = ""
                    
                    table.add_row(ip, str(count), str(syn), str(udp), str(icmp), status, style=style)
            else:
                table.add_row("No traffic", "-", "-", "-", "-", "[dim]Idle[/dim]")
        
        return table
    
    def create_status_panel(self) -> Panel:
        """Create status panel for CLI dashboard."""
        stats = self.get_stats()
        
        text = Text()
        text.append("System Status\n", style="bold underline cyan")
        text.append(f"Interface: ", style="bold")
        text.append(f"{NETWORK_INTERFACE}\n", style="cyan")
        text.append(f"Uptime: ", style="bold")
        text.append(f"{stats['uptime']}\n", style="green")
        text.append(f"Total Packets: ", style="bold")
        text.append(f"{stats['total_packets']:,}\n", style="yellow")
        text.append(f"DoS Attacks: ", style="bold")
        text.append(f"{stats['dos_attacks']}\n", style="red")
        text.append(f"DDoS Attacks: ", style="bold")
        text.append(f"{stats['ddos_attacks']}\n", style="red")
        text.append(f"IPs Blocked: ", style="bold")
        text.append(f"{stats['ips_blocked']}\n", style="red")
        
        return Panel(text, title="📊 System Info", border_style="green")
    
    def create_thresholds_panel(self) -> Panel:
        """Create thresholds panel for CLI dashboard."""
        text = Text()
        text.append("DoS Thresholds (Per-IP)\n", style="bold underline magenta")
        text.append(f"Packets: {PACKET_THRESHOLD}  SYN: {SYN_THRESHOLD}  UDP: {UDP_THRESHOLD}  ICMP: {ICMP_THRESHOLD}\n", style="cyan")
        
        text.append("\nDDoS Thresholds (Aggregate)\n", style="bold underline red")
        text.append(f"Packets: {AGGREGATE_PACKET_THRESHOLD}  SYN: {AGGREGATE_SYN_THRESHOLD}  UDP: {AGGREGATE_UDP_THRESHOLD}\n", style="red")
        text.append(f"IP Spike: {NEW_IP_SPIKE_THRESHOLD} new IPs/window\n", style="red")
        
        text.append(f"\nTime Window: {TIME_WINDOW}s", style="cyan")
        
        return Panel(text, title="⚙️ Configuration", border_style="yellow")


# MAIN EXECUTION
def main():
    """Main entry point for the detector."""
    console = Console()
    
    # Display banner
    console.print("\n[bold cyan]" + "=" * 70 + "[/bold cyan]")
    console.print("[bold cyan]UNIFIED DoS/DDoS DETECTION SYSTEM[/bold cyan]", justify="center")
    console.print("[bold cyan]Advanced Multi-Vector Attack Detection[/bold cyan]", justify="center")
    console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
    
    # Initialize detector
    detector = UnifiedDetector()
    
    # Display configuration
    console.print(detector.create_status_panel())
    console.print(detector.create_thresholds_panel())
    
    console.print("\n[bold green]🛡️ Mitigation: ENABLED[/bold green] (iptables)")
    console.print("[bold green]📝 Logging: ENABLED[/bold green] (logs/ directory)")
    console.print("[bold red]🌐 DDoS Detection: ENABLED[/bold red]")
    console.print("[bold yellow]⚠️ Warning: Malicious IPs will be automatically blocked![/bold yellow]")
    console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")
    
    # Start window reset timer
    def reset_timer():
        while not detector.shutdown_flag.is_set():
            time.sleep(TIME_WINDOW)
            if not detector.shutdown_flag.is_set():
                detector.reset_window()
    
    timer_thread = threading.Thread(target=reset_timer, daemon=True)
    timer_thread.start()
    
    # Start dashboard thread
    def display_dashboard():
        try:
            with Live(detector.create_traffic_table(), refresh_per_second=2, console=console) as live:
                while not detector.shutdown_flag.is_set():
                    time.sleep(0.5)
                    live.update(detector.create_traffic_table())
        except KeyboardInterrupt:
            pass
    
    dashboard_thread = threading.Thread(target=display_dashboard, daemon=True)
    dashboard_thread.start()
    
    # Main sniffing loop
    try:
        console.print(f"[green]Monitoring traffic on {NETWORK_INTERFACE}...[/green]\n")
        detector.logger.log_system_event(f"Started monitoring on {NETWORK_INTERFACE}")
        
        sniff(iface=NETWORK_INTERFACE, prn=detector.process_packet, store=0)
        
    except KeyboardInterrupt:
        detector.shutdown_flag.set()
        console.print("\n\n[bold yellow]Shutting down...[/bold yellow]\n")
        detector.logger.log_system_event("Shutdown initiated by user")
        
        # Display final stats
        stats = detector.get_stats()
        console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]")
        console.print("[bold cyan]Final Statistics[/bold cyan]", justify="center")
        console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
        
        stats_table = Table(show_header=False, border_style="cyan")
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Uptime", stats["uptime"])
        stats_table.add_row("Total Packets", f"{stats['total_packets']:,}")
        stats_table.add_row("DoS Attacks Detected", str(stats["dos_attacks"]))
        stats_table.add_row("DDoS Attacks Detected", str(stats["ddos_attacks"]))
        stats_table.add_row("IPs Blocked", str(stats["ips_blocked"]))
        stats_table.add_row("Unique IPs Tracked", str(stats["known_ips"]))
        
        console.print(stats_table)
        
        if detector.mitigator.get_blocked_count() > 0:
            console.print(f"\n[red]Blocked IPs:[/red]")
            for ip in detector.mitigator.get_blocked_ips():
                console.print(f"  [red]🔒 {ip}[/red]")
        
        detector.logger.log_shutdown(stats)
        console.print("\n[bold green]✅ Shutdown complete![/bold green]\n")
        
    except PermissionError:
        console.print("\n[bold red]❌ ERROR: Permission denied![/bold red]")
        console.print("[yellow]Run with sudo: sudo python3 src/detector.py[/yellow]\n")
        
    except Exception as e:
        console.print(f"\n[bold red]❌ ERROR: {e}[/bold red]")
        detector.logger.log_error(f"Runtime error: {e}", e)


if __name__ == "__main__":
    main()
