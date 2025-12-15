"""
Advanced DDoS/DoS Detection System - ENHANCED Unified Detector
==============================================================

This is the ENHANCED detection engine with 10 advanced detection capabilities:

1. TCP Flag Analysis - ACK, FIN, RST, SYN-ACK, XMAS, NULL, invalid flags
2. Packet Size Analysis - Small packet floods, amplification attacks
3. ICMP Type Analysis - Ping floods, smurf attacks, ICMP type differentiation
4. Destination Port Analysis - Port scanning, service-targeted attacks
5. TTL Anomaly Detection - Spoofed traffic detection via TTL variance
6. Fragment Attack Detection - Teardrop, fragmentation floods
7. Connection State Tracking - Half-open connection detection
8. Burst Detection - Micro-burst attacks within time windows
9. Protocol Distribution Anomaly - Unusual traffic pattern detection
10. Application Layer Inspection - HTTP/DNS attack detection

All configuration is loaded from config/config.py for clean separation.

Usage:
    sudo python3 src/detector.py

Author: PyDOS Project - Enhanced Version
"""

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Set, List, Tuple, Optional, Any
import time
import json
import sys
import statistics
from pathlib import Path

# Third-party imports
from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, sniff
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.columns import Columns

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
        # Enhanced TCP Flag thresholds
        ACK_THRESHOLD,
        FIN_THRESHOLD,
        RST_THRESHOLD,
        SYN_ACK_THRESHOLD,
        XMAS_THRESHOLD,
        NULL_THRESHOLD,
        INVALID_FLAGS_THRESHOLD,
        # Aggregate thresholds (DDoS)
        AGGREGATE_PACKET_THRESHOLD,
        AGGREGATE_SYN_THRESHOLD,
        AGGREGATE_UDP_THRESHOLD,
        AGGREGATE_ICMP_THRESHOLD,
        AGGREGATE_ACK_THRESHOLD,
        AGGREGATE_FIN_THRESHOLD,
        AGGREGATE_RST_THRESHOLD,
        # Packet size thresholds
        SMALL_PACKET_SIZE,
        LARGE_PACKET_SIZE,
        SMALL_PACKET_THRESHOLD,
        LARGE_PACKET_THRESHOLD,
        AGGREGATE_SMALL_PACKET_THRESHOLD,
        AGGREGATE_LARGE_PACKET_THRESHOLD,
        BANDWIDTH_THRESHOLD_MBPS,
        # ICMP type thresholds
        ICMP_ECHO_REQUEST_THRESHOLD,
        ICMP_ECHO_REPLY_THRESHOLD,
        ICMP_UNREACHABLE_THRESHOLD,
        AGGREGATE_ICMP_ECHO_THRESHOLD,
        # Port analysis
        PORT_SCAN_THRESHOLD,
        SERVICE_PORT_THRESHOLD,
        AGGREGATE_PORT_CONCENTRATION,
        MONITORED_PORTS,
        # TTL analysis
        TTL_VARIANCE_THRESHOLD,
        LOW_TTL_THRESHOLD,
        TTL_ANOMALY_PERCENTAGE,
        # Fragment detection
        FRAGMENT_THRESHOLD,
        AGGREGATE_FRAGMENT_THRESHOLD,
        TINY_FRAGMENT_SIZE,
        FRAGMENT_OVERLAP_ALERT,
        # Connection tracking
        HALF_OPEN_RATIO_THRESHOLD,
        SYN_WITHOUT_ACK_THRESHOLD,
        CONNECTION_TRACKING_ENABLED,
        # Burst detection
        BURST_WINDOW_MS,
        BURST_PACKET_THRESHOLD,
        BURST_COUNT_THRESHOLD,
        # Protocol anomaly
        PROTOCOL_BASELINE,
        PROTOCOL_DEVIATION_THRESHOLD,
        # Application layer
        HTTP_REQUEST_THRESHOLD,
        HTTP_PORTS,
        DNS_QUERY_THRESHOLD,
        DNS_AMPLIFICATION_SIZE,
        DNS_PORT,
        # IP Spike detection
        NEW_IP_SPIKE_THRESHOLD,
        # Low-and-slow detection
        LOW_SLOW_MIN_SOURCES,
        LOW_SLOW_PER_IP_MAX,
        LOW_SLOW_AGGREGATE_MIN,
        # Feature flags
        ENABLE_AUTO_BLOCKING,
        ENABLE_TCP_FLAG_ANALYSIS,
        ENABLE_PACKET_SIZE_ANALYSIS,
        ENABLE_ICMP_TYPE_ANALYSIS,
        ENABLE_PORT_ANALYSIS,
        ENABLE_TTL_ANALYSIS,
        ENABLE_FRAGMENT_DETECTION,
        ENABLE_CONNECTION_TRACKING,
        ENABLE_BURST_DETECTION,
        ENABLE_PROTOCOL_ANOMALY,
        ENABLE_APP_LAYER_INSPECTION,
    )
    CONFIG_LOADED = True
except ImportError as e:
    print(f"[WARNING] Could not load config: {e}")
    print("[WARNING] Using default values")
    CONFIG_LOADED = False
    # Fallback defaults (basic)
    NETWORK_INTERFACE = "eth0"
    ALLOW_LOOPBACK_DETECTION = True
    TIME_WINDOW = 5.0
    PACKET_THRESHOLD = 100
    SYN_THRESHOLD = 50
    UDP_THRESHOLD = 50
    ICMP_THRESHOLD = 50
    ACK_THRESHOLD = 50
    FIN_THRESHOLD = 30
    RST_THRESHOLD = 30
    SYN_ACK_THRESHOLD = 40
    XMAS_THRESHOLD = 5
    NULL_THRESHOLD = 5
    INVALID_FLAGS_THRESHOLD = 3
    AGGREGATE_PACKET_THRESHOLD = 1000
    AGGREGATE_SYN_THRESHOLD = 500
    AGGREGATE_UDP_THRESHOLD = 500
    AGGREGATE_ICMP_THRESHOLD = 300
    AGGREGATE_ACK_THRESHOLD = 500
    AGGREGATE_FIN_THRESHOLD = 300
    AGGREGATE_RST_THRESHOLD = 300
    SMALL_PACKET_SIZE = 64
    LARGE_PACKET_SIZE = 1000
    SMALL_PACKET_THRESHOLD = 80
    LARGE_PACKET_THRESHOLD = 50
    AGGREGATE_SMALL_PACKET_THRESHOLD = 800
    AGGREGATE_LARGE_PACKET_THRESHOLD = 400
    BANDWIDTH_THRESHOLD_MBPS = 10
    ICMP_ECHO_REQUEST_THRESHOLD = 30
    ICMP_ECHO_REPLY_THRESHOLD = 50
    ICMP_UNREACHABLE_THRESHOLD = 20
    AGGREGATE_ICMP_ECHO_THRESHOLD = 300
    PORT_SCAN_THRESHOLD = 15
    SERVICE_PORT_THRESHOLD = 100
    AGGREGATE_PORT_CONCENTRATION = 0.8
    MONITORED_PORTS = [80, 443, 22, 21, 25, 53, 3306, 5432, 6379, 11211, 123]
    TTL_VARIANCE_THRESHOLD = 30
    LOW_TTL_THRESHOLD = 5
    TTL_ANOMALY_PERCENTAGE = 0.3
    FRAGMENT_THRESHOLD = 20
    AGGREGATE_FRAGMENT_THRESHOLD = 200
    TINY_FRAGMENT_SIZE = 60
    FRAGMENT_OVERLAP_ALERT = True
    HALF_OPEN_RATIO_THRESHOLD = 0.8
    SYN_WITHOUT_ACK_THRESHOLD = 40
    CONNECTION_TRACKING_ENABLED = True
    BURST_WINDOW_MS = 100
    BURST_PACKET_THRESHOLD = 20
    BURST_COUNT_THRESHOLD = 3
    PROTOCOL_BASELINE = {'tcp': 0.70, 'udp': 0.20, 'icmp': 0.05, 'other': 0.05}
    PROTOCOL_DEVIATION_THRESHOLD = 0.3
    HTTP_REQUEST_THRESHOLD = 50
    HTTP_PORTS = [80, 8080, 8000, 8443, 443]
    DNS_QUERY_THRESHOLD = 30
    DNS_AMPLIFICATION_SIZE = 512
    DNS_PORT = 53
    NEW_IP_SPIKE_THRESHOLD = 50
    LOW_SLOW_MIN_SOURCES = 20
    LOW_SLOW_PER_IP_MAX = 50
    LOW_SLOW_AGGREGATE_MIN = 500
    ENABLE_AUTO_BLOCKING = True
    ENABLE_TCP_FLAG_ANALYSIS = True
    ENABLE_PACKET_SIZE_ANALYSIS = True
    ENABLE_ICMP_TYPE_ANALYSIS = True
    ENABLE_PORT_ANALYSIS = True
    ENABLE_TTL_ANALYSIS = True
    ENABLE_FRAGMENT_DETECTION = True
    ENABLE_CONNECTION_TRACKING = True
    ENABLE_BURST_DETECTION = True
    ENABLE_PROTOCOL_ANOMALY = True
    ENABLE_APP_LAYER_INSPECTION = True

# Import local modules
from mitigator import Mitigator
from logger import get_logger
from utils import is_private_or_localhost


# DATA CLASSES
@dataclass
class PacketInfo:
    """Detailed packet information extracted during analysis."""
    src_ip: str
    dst_ip: str
    protocol: str  # 'tcp', 'udp', 'icmp', 'other'
    size: int
    ttl: int
    
    # TCP specific
    tcp_flags: Optional[str] = None
    tcp_flags_int: int = 0
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    is_syn: bool = False
    is_ack: bool = False
    is_fin: bool = False
    is_rst: bool = False
    is_syn_ack: bool = False
    is_xmas: bool = False
    is_null: bool = False
    is_invalid_flags: bool = False
    
    # ICMP specific
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    
    # Fragment info
    is_fragment: bool = False
    fragment_offset: int = 0
    more_fragments: bool = False
    
    # Application layer
    is_http: bool = False
    is_dns: bool = False
    dns_query_count: int = 0
    
    # Timing
    timestamp: float = field(default_factory=time.time)


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


# ENHANCED UNIFIED DETECTOR CLASS

class UnifiedDetector:
    """
    Advanced unified detection engine for both DoS and DDoS attacks.
    
    This ENHANCED version includes 10 additional detection capabilities
    for comprehensive packet-level and behavioral analysis.
    """
    
    def __init__(self):
        """Initialize the detector with all counters and components."""
        # Thread safety
        self.lock = threading.RLock()
        
        # BASIC COUNTERS (Original)
        self.ip_packet_counts: Dict[str, int] = defaultdict(int)
        self.ip_syn_counts: Dict[str, int] = defaultdict(int)
        self.ip_udp_counts: Dict[str, int] = defaultdict(int)
        self.ip_icmp_counts: Dict[str, int] = defaultdict(int)
        
        # Aggregate counters
        self.total_packets = 0
        self.total_syn = 0
        self.total_udp = 0
        self.total_icmp = 0
        
        # FEATURE 1: TCP FLAG COUNTERS
        self.ip_ack_counts: Dict[str, int] = defaultdict(int)
        self.ip_fin_counts: Dict[str, int] = defaultdict(int)
        self.ip_rst_counts: Dict[str, int] = defaultdict(int)
        self.ip_syn_ack_counts: Dict[str, int] = defaultdict(int)
        self.ip_xmas_counts: Dict[str, int] = defaultdict(int)
        self.ip_null_counts: Dict[str, int] = defaultdict(int)
        self.ip_invalid_flags_counts: Dict[str, int] = defaultdict(int)
        
        self.total_ack = 0
        self.total_fin = 0
        self.total_rst = 0
        self.total_syn_ack = 0
        self.total_xmas = 0
        self.total_null = 0
        self.total_invalid_flags = 0
        
        # FEATURE 2: PACKET SIZE TRACKING
        self.ip_small_packet_counts: Dict[str, int] = defaultdict(int)
        self.ip_large_packet_counts: Dict[str, int] = defaultdict(int)
        self.ip_bytes: Dict[str, int] = defaultdict(int)
        
        self.total_small_packets = 0
        self.total_large_packets = 0
        self.total_bytes = 0
        
        # FEATURE 3: ICMP TYPE TRACKING
        self.ip_icmp_echo_req_counts: Dict[str, int] = defaultdict(int)
        self.ip_icmp_echo_reply_counts: Dict[str, int] = defaultdict(int)
        self.ip_icmp_unreachable_counts: Dict[str, int] = defaultdict(int)
        
        self.total_icmp_echo_req = 0
        self.total_icmp_echo_reply = 0
        
        # FEATURE 4: PORT TRACKING
        self.ip_ports_hit: Dict[str, Set[int]] = defaultdict(set)
        self.ip_port_counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self.port_packet_counts: Dict[int, int] = defaultdict(int)
        
        # FEATURE 5: TTL TRACKING
        self.ip_ttl_values: Dict[str, List[int]] = defaultdict(list)
        self.low_ttl_count = 0
        self.ttl_anomaly_count = 0
        
        # FEATURE 6: FRAGMENT TRACKING
        self.ip_fragment_counts: Dict[str, int] = defaultdict(int)
        self.total_fragments = 0
        self.tiny_fragment_count = 0
        
        # FEATURE 7: CONNECTION STATE TRACKING
        self.ip_syn_sent: Dict[str, int] = defaultdict(int)
        self.ip_ack_received: Dict[str, int] = defaultdict(int)
        self.pending_connections: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)
        
        # FEATURE 8: BURST DETECTION
        self.ip_packet_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.ip_burst_counts: Dict[str, int] = defaultdict(int)
        
        # FEATURE 9: PROTOCOL DISTRIBUTION
        self.protocol_counts = {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}
        
        # FEATURE 10: APPLICATION LAYER
        self.ip_http_counts: Dict[str, int] = defaultdict(int)
        self.ip_dns_counts: Dict[str, int] = defaultdict(int)
        self.total_http = 0
        self.total_dns = 0
        
        # IP TRACKING
        self.known_ips: Set[str] = set()
        self.window_new_ips: Set[str] = set()
        self.window_all_ips: Set[str] = set()
        
        # Attack tracking (prevent duplicate alerts per window)
        self.dos_alerts_this_window: Set[str] = set()
        self.ddos_alerts_this_window: Set[str] = set()
        
        # STATISTICS
        self.stats = {
            "total_packets_all_time": 0,
            "dos_attacks_detected": 0,
            "ddos_attacks_detected": 0,
            "ips_blocked": 0,
            "malformed_packets": 0,
            "port_scans_detected": 0,
            "spoofed_packets_detected": 0,
            "fragment_attacks_detected": 0,
            "burst_attacks_detected": 0,
            "app_layer_attacks_detected": 0,
            "start_time": datetime.now()
        }
        
        # COMPONENTS
        self.mitigator = Mitigator()
        self.logger = get_logger()
        self.console = Console()
        
        # Blocked IPs cache
        self.blocked_ips_cache: Set[str] = set()
        
        # All alerts history
        self.alerts: List[Alert] = []
        
        # Window management
        self.window_start = datetime.now()
        self.shutdown_flag = threading.Event()
        
        # Log initialization
        self._log_initialization()
    
    def _log_initialization(self):
        """Log system initialization with all enabled features."""
        self.logger.log_system_event("Enhanced Unified Detector initialized")
        self.logger.log_system_event(f"DoS Thresholds - Packets: {PACKET_THRESHOLD}, SYN: {SYN_THRESHOLD}, UDP: {UDP_THRESHOLD}, ICMP: {ICMP_THRESHOLD}")
        self.logger.log_system_event(f"DDoS Thresholds - Packets: {AGGREGATE_PACKET_THRESHOLD}, SYN: {AGGREGATE_SYN_THRESHOLD}")
        
        enabled_features = []
        if ENABLE_TCP_FLAG_ANALYSIS: enabled_features.append("TCP Flag Analysis")
        if ENABLE_PACKET_SIZE_ANALYSIS: enabled_features.append("Packet Size Analysis")
        if ENABLE_ICMP_TYPE_ANALYSIS: enabled_features.append("ICMP Type Analysis")
        if ENABLE_PORT_ANALYSIS: enabled_features.append("Port Analysis")
        if ENABLE_TTL_ANALYSIS: enabled_features.append("TTL Analysis")
        if ENABLE_FRAGMENT_DETECTION: enabled_features.append("Fragment Detection")
        if ENABLE_CONNECTION_TRACKING: enabled_features.append("Connection Tracking")
        if ENABLE_BURST_DETECTION: enabled_features.append("Burst Detection")
        if ENABLE_PROTOCOL_ANOMALY: enabled_features.append("Protocol Anomaly")
        if ENABLE_APP_LAYER_INSPECTION: enabled_features.append("App Layer Inspection")
        
        self.logger.log_system_event(f"Enhanced Features Enabled: {', '.join(enabled_features)}")

    # PACKET ANALYSIS
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract detailed information from a packet."""
        if not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        
        info = PacketInfo(
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            protocol='other',
            size=len(packet),
            ttl=ip_layer.ttl,
            is_fragment=ip_layer.frag > 0 or bool(ip_layer.flags.MF),
            fragment_offset=ip_layer.frag,
            more_fragments=bool(ip_layer.flags.MF)
        )
        
        # TCP Analysis
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info.protocol = 'tcp'
            info.src_port = tcp.sport
            info.dst_port = tcp.dport
            info.tcp_flags = str(tcp.flags)
            info.tcp_flags_int = int(tcp.flags)
            
            # Parse TCP flags
            flags = str(tcp.flags)
            info.is_syn = flags == 'S'
            info.is_ack = 'A' in flags and 'S' not in flags and 'F' not in flags and 'R' not in flags
            info.is_fin = 'F' in flags
            info.is_rst = 'R' in flags
            info.is_syn_ack = 'S' in flags and 'A' in flags
            
            # XMAS scan: FIN + PSH + URG
            info.is_xmas = 'F' in flags and 'P' in flags and 'U' in flags
            
            # NULL scan: no flags
            info.is_null = tcp.flags == 0
            
            # Invalid flag combinations
            info.is_invalid_flags = ('S' in flags and 'F' in flags) or \
                                   ('S' in flags and 'R' in flags) or \
                                   (info.is_null and info.size > 40)
            
            # HTTP detection
            if info.dst_port in HTTP_PORTS or info.src_port in HTTP_PORTS:
                info.is_http = True
                
        # UDP Analysis
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info.protocol = 'udp'
            info.src_port = udp.sport
            info.dst_port = udp.dport
            
            # DNS detection
            if udp.dport == DNS_PORT or udp.sport == DNS_PORT:
                info.is_dns = True
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    info.dns_query_count = dns.qdcount if hasattr(dns, 'qdcount') else 0
                    
        # ICMP Analysis
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info.protocol = 'icmp'
            info.icmp_type = icmp.type
            info.icmp_code = icmp.code
        
        return info

    # MAIN PACKET PROCESSING    
    def process_packet(self, packet) -> None:
        """
        Process a single captured packet.
        
        This is the main entry point called by the sniffer for each packet.
        Performs comprehensive analysis using all 10 detection features.
        """
        # Extract packet information
        pkt_info = self._extract_packet_info(packet)
        if pkt_info is None:
            return
        
        src_ip = pkt_info.src_ip
        
        # Validate IP
        if not src_ip or src_ip == "0.0.0.0":
            return
        
        # Skip private/loopback unless testing
        if not ALLOW_LOOPBACK_DETECTION and is_private_or_localhost(src_ip):
            return
        
        # Skip already blocked IPs
        if src_ip in self.blocked_ips_cache:
            return
        
        with self.lock:
            # Update all counters
            self._update_all_counters(pkt_info)
            
            # Run all detection checks
            self._run_all_detections(pkt_info)
    
    def _update_all_counters(self, pkt_info: PacketInfo) -> None:
        """Update all packet counters based on packet information."""
        src_ip = pkt_info.src_ip
        
        # Basic counters
        self.ip_packet_counts[src_ip] += 1
        self.total_packets += 1
        self.stats["total_packets_all_time"] += 1
        
        # Protocol counters
        self.protocol_counts[pkt_info.protocol] += 1
        
        if pkt_info.protocol == 'tcp':
            self._update_tcp_counters(src_ip, pkt_info)
        elif pkt_info.protocol == 'udp':
            self.ip_udp_counts[src_ip] += 1
            self.total_udp += 1
        elif pkt_info.protocol == 'icmp':
            self._update_icmp_counters(src_ip, pkt_info)
        
        # Feature 2: Packet size tracking
        if ENABLE_PACKET_SIZE_ANALYSIS:
            self._update_size_counters(src_ip, pkt_info)
        
        # Feature 4: Port tracking
        if ENABLE_PORT_ANALYSIS and pkt_info.dst_port:
            self._update_port_counters(src_ip, pkt_info)
        
        # Feature 5: TTL tracking
        if ENABLE_TTL_ANALYSIS:
            self._update_ttl_tracking(src_ip, pkt_info)
        
        # Feature 6: Fragment tracking
        if ENABLE_FRAGMENT_DETECTION and pkt_info.is_fragment:
            self._update_fragment_counters(src_ip, pkt_info)
        
        # Feature 8: Burst detection
        if ENABLE_BURST_DETECTION:
            self._update_burst_tracking(src_ip, pkt_info)
        
        # Feature 10: Application layer
        if ENABLE_APP_LAYER_INSPECTION:
            self._update_app_layer_counters(src_ip, pkt_info)
        
        # IP tracking
        self.window_all_ips.add(src_ip)
        if src_ip not in self.known_ips:
            self.window_new_ips.add(src_ip)
    
    def _update_tcp_counters(self, src_ip: str, pkt_info: PacketInfo) -> None:
        """Update TCP-specific counters (Feature 1)."""
        if pkt_info.is_syn:
            self.ip_syn_counts[src_ip] += 1
            self.total_syn += 1
            if ENABLE_CONNECTION_TRACKING:
                self.ip_syn_sent[src_ip] += 1
        
        if pkt_info.is_ack:
            self.ip_ack_counts[src_ip] += 1
            self.total_ack += 1
            if ENABLE_CONNECTION_TRACKING:
                self.ip_ack_received[src_ip] += 1
        
        if pkt_info.is_fin:
            self.ip_fin_counts[src_ip] += 1
            self.total_fin += 1
        
        if pkt_info.is_rst:
            self.ip_rst_counts[src_ip] += 1
            self.total_rst += 1
        
        if pkt_info.is_syn_ack:
            self.ip_syn_ack_counts[src_ip] += 1
            self.total_syn_ack += 1
        
        if pkt_info.is_xmas:
            self.ip_xmas_counts[src_ip] += 1
            self.total_xmas += 1
            self.stats["malformed_packets"] += 1
        
        if pkt_info.is_null:
            self.ip_null_counts[src_ip] += 1
            self.total_null += 1
            self.stats["malformed_packets"] += 1
        
        if pkt_info.is_invalid_flags:
            self.ip_invalid_flags_counts[src_ip] += 1
            self.total_invalid_flags += 1
            self.stats["malformed_packets"] += 1
    
    def _update_icmp_counters(self, src_ip: str, pkt_info: PacketInfo) -> None:
        """Update ICMP-specific counters (Feature 3)."""
        self.ip_icmp_counts[src_ip] += 1
        self.total_icmp += 1
        
        if ENABLE_ICMP_TYPE_ANALYSIS and pkt_info.icmp_type is not None:
            if pkt_info.icmp_type == 8:  # Echo Request
                self.ip_icmp_echo_req_counts[src_ip] += 1
                self.total_icmp_echo_req += 1
            elif pkt_info.icmp_type == 0:  # Echo Reply
                self.ip_icmp_echo_reply_counts[src_ip] += 1
                self.total_icmp_echo_reply += 1
            elif pkt_info.icmp_type == 3:  # Destination Unreachable
                self.ip_icmp_unreachable_counts[src_ip] += 1
    
    def _update_size_counters(self, src_ip: str, pkt_info: PacketInfo) -> None:
        """Update packet size counters (Feature 2)."""
        self.ip_bytes[src_ip] += pkt_info.size
        self.total_bytes += pkt_info.size
        
        if pkt_info.size <= SMALL_PACKET_SIZE:
            self.ip_small_packet_counts[src_ip] += 1
            self.total_small_packets += 1
        elif pkt_info.size >= LARGE_PACKET_SIZE:
            self.ip_large_packet_counts[src_ip] += 1
            self.total_large_packets += 1
    
    def _update_port_counters(self, src_ip: str, pkt_info: PacketInfo) -> None:
        """Update port tracking counters (Feature 4)."""
        dst_port = pkt_info.dst_port
        self.ip_ports_hit[src_ip].add(dst_port)
        self.ip_port_counts[src_ip][dst_port] += 1
        self.port_packet_counts[dst_port] += 1
    
    def _update_ttl_tracking(self, src_ip: str, pkt_info: PacketInfo) -> None:
        """Update TTL tracking (Feature 5)."""
        self.ip_ttl_values[src_ip].append(pkt_info.ttl)
        
        if pkt_info.ttl < LOW_TTL_THRESHOLD:
            self.low_ttl_count += 1
    
    def _update_fragment_counters(self, src_ip: str, pkt_info: PacketInfo) -> None:
        """Update fragment tracking (Feature 6)."""
        self.ip_fragment_counts[src_ip] += 1
        self.total_fragments += 1
        
        if pkt_info.size < TINY_FRAGMENT_SIZE:
            self.tiny_fragment_count += 1
    
    def _update_burst_tracking(self, src_ip: str, pkt_info: PacketInfo) -> None:
        """Update burst detection tracking (Feature 8)."""
        current_time = pkt_info.timestamp
        self.ip_packet_timestamps[src_ip].append(current_time)
        
        # Check for burst
        timestamps = self.ip_packet_timestamps[src_ip]
        burst_window_sec = BURST_WINDOW_MS / 1000.0
        
        recent_packets = sum(1 for ts in timestamps if current_time - ts < burst_window_sec)
        
        if recent_packets >= BURST_PACKET_THRESHOLD:
            self.ip_burst_counts[src_ip] += 1
    
    def _update_app_layer_counters(self, src_ip: str, pkt_info: PacketInfo) -> None:
        """Update application layer counters (Feature 10)."""
        if pkt_info.is_http:
            self.ip_http_counts[src_ip] += 1
            self.total_http += 1
        
        if pkt_info.is_dns:
            self.ip_dns_counts[src_ip] += 1
            self.total_dns += 1

    # DETECTION METHODS
    
    def _run_all_detections(self, pkt_info: PacketInfo) -> None:
        """Run all detection checks."""
        src_ip = pkt_info.src_ip
        dst_ip = pkt_info.dst_ip
        
        # Original DoS detection
        self._check_dos_attack(src_ip, dst_ip, pkt_info)
        
        # Original DDoS detection
        self._check_ddos_attacks()
        
        # Feature 1: TCP Flag attacks
        if ENABLE_TCP_FLAG_ANALYSIS:
            self._check_tcp_flag_attacks(src_ip)
        
        # Feature 2: Packet size attacks
        if ENABLE_PACKET_SIZE_ANALYSIS:
            self._check_size_attacks(src_ip)
        
        # Feature 3: ICMP type attacks
        if ENABLE_ICMP_TYPE_ANALYSIS:
            self._check_icmp_attacks(src_ip)
        
        # Feature 4: Port scan detection
        if ENABLE_PORT_ANALYSIS:
            self._check_port_attacks(src_ip)
        
        # Feature 5: TTL anomaly detection
        if ENABLE_TTL_ANALYSIS:
            self._check_ttl_anomalies(src_ip)
        
        # Feature 6: Fragment attacks
        if ENABLE_FRAGMENT_DETECTION:
            self._check_fragment_attacks(src_ip)
        
        # Feature 7: Half-open connection detection
        if ENABLE_CONNECTION_TRACKING:
            self._check_half_open_connections(src_ip)
        
        # Feature 8: Burst detection
        if ENABLE_BURST_DETECTION:
            self._check_burst_attacks(src_ip)
        
        # Feature 9: Protocol anomaly
        if ENABLE_PROTOCOL_ANOMALY:
            self._check_protocol_anomaly()
        
        # Feature 10: Application layer attacks
        if ENABLE_APP_LAYER_INSPECTION:
            self._check_app_layer_attacks(src_ip)
    
    # DoS DETECTION (Per-IP) - Original + Enhanced
    
    def _check_dos_attack(self, src_ip: str, dst_ip: str, pkt_info: PacketInfo) -> None:
        """Check if a single IP exceeds per-IP thresholds."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        packet_count = self.ip_packet_counts[src_ip]
        syn_count = self.ip_syn_counts[src_ip]
        udp_count = self.ip_udp_counts[src_ip]
        icmp_count = self.ip_icmp_counts[src_ip]
        
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
        
        self._trigger_dos_alert(src_ip, dst_ip, attack_types, packet_count)
    
    def _check_tcp_flag_attacks(self, src_ip: str) -> None:
        """Check for TCP flag-based attacks (Feature 1)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        attack_types = []
        
        if self.ip_ack_counts[src_ip] > ACK_THRESHOLD:
            attack_types.append("ACK_FLOOD")
        if self.ip_fin_counts[src_ip] > FIN_THRESHOLD:
            attack_types.append("FIN_FLOOD")
        if self.ip_rst_counts[src_ip] > RST_THRESHOLD:
            attack_types.append("RST_FLOOD")
        if self.ip_syn_ack_counts[src_ip] > SYN_ACK_THRESHOLD:
            attack_types.append("SYN_ACK_FLOOD")
        
        # Immediate alerts for malicious packets
        if self.ip_xmas_counts[src_ip] >= XMAS_THRESHOLD:
            attack_types.append("XMAS_SCAN")
        if self.ip_null_counts[src_ip] >= NULL_THRESHOLD:
            attack_types.append("NULL_SCAN")
        if self.ip_invalid_flags_counts[src_ip] >= INVALID_FLAGS_THRESHOLD:
            attack_types.append("MALFORMED_TCP")
        
        if attack_types:
            self._trigger_dos_alert(src_ip, "", attack_types, 
                                   self.ip_packet_counts[src_ip],
                                   additional_info={"tcp_flags_triggered": attack_types})
    
    def _check_size_attacks(self, src_ip: str) -> None:
        """Check for packet size-based attacks (Feature 2)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        attack_types = []
        
        if self.ip_small_packet_counts[src_ip] > SMALL_PACKET_THRESHOLD:
            attack_types.append("SMALL_PACKET_FLOOD")
        if self.ip_large_packet_counts[src_ip] > LARGE_PACKET_THRESHOLD:
            attack_types.append("AMPLIFICATION_ATTACK")
        
        if attack_types:
            bandwidth_mbps = (self.ip_bytes[src_ip] * 8) / (TIME_WINDOW * 1_000_000)
            self._trigger_dos_alert(src_ip, "", attack_types,
                                   self.ip_packet_counts[src_ip],
                                   additional_info={
                                       "small_packets": self.ip_small_packet_counts[src_ip],
                                       "large_packets": self.ip_large_packet_counts[src_ip],
                                       "bandwidth_mbps": round(bandwidth_mbps, 2)
                                   })
    
    def _check_icmp_attacks(self, src_ip: str) -> None:
        """Check for ICMP type-based attacks (Feature 3)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        attack_types = []
        
        if self.ip_icmp_echo_req_counts[src_ip] > ICMP_ECHO_REQUEST_THRESHOLD:
            attack_types.append("PING_FLOOD")
        if self.ip_icmp_echo_reply_counts[src_ip] > ICMP_ECHO_REPLY_THRESHOLD:
            attack_types.append("SMURF_ATTACK_INDICATOR")
        if self.ip_icmp_unreachable_counts[src_ip] > ICMP_UNREACHABLE_THRESHOLD:
            attack_types.append("ICMP_UNREACHABLE_FLOOD")
        
        if attack_types:
            self._trigger_dos_alert(src_ip, "", attack_types,
                                   self.ip_icmp_counts[src_ip],
                                   additional_info={
                                       "echo_requests": self.ip_icmp_echo_req_counts[src_ip],
                                       "echo_replies": self.ip_icmp_echo_reply_counts[src_ip]
                                   })
    
    def _check_port_attacks(self, src_ip: str) -> None:
        """Check for port-based attacks (Feature 4)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        attack_types = []
        ports_hit = len(self.ip_ports_hit[src_ip])
        
        # Port scan detection
        if ports_hit > PORT_SCAN_THRESHOLD:
            attack_types.append("PORT_SCAN")
            self.stats["port_scans_detected"] += 1
        
        # Service-targeted attack
        for port, count in self.ip_port_counts[src_ip].items():
            if count > SERVICE_PORT_THRESHOLD:
                service_name = self._get_service_name(port)
                attack_types.append(f"SERVICE_FLOOD_{service_name}")
        
        if attack_types:
            self._trigger_dos_alert(src_ip, "", attack_types,
                                   self.ip_packet_counts[src_ip],
                                   additional_info={
                                       "ports_scanned": ports_hit,
                                       "top_ports": dict(sorted(
                                           self.ip_port_counts[src_ip].items(),
                                           key=lambda x: x[1], reverse=True
                                       )[:5])
                                   })
    
    def _check_ttl_anomalies(self, src_ip: str) -> None:
        """Check for TTL-based spoofing indicators (Feature 5)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        ttl_values = self.ip_ttl_values[src_ip]
        if len(ttl_values) < 5:
            return
        
        # Check TTL variance
        try:
            ttl_variance = max(ttl_values) - min(ttl_values)
            
            if ttl_variance > TTL_VARIANCE_THRESHOLD:
                self.stats["spoofed_packets_detected"] += 1
                self._trigger_dos_alert(src_ip, "", ["SPOOFED_TRAFFIC_TTL_VARIANCE"],
                                       self.ip_packet_counts[src_ip],
                                       additional_info={
                                           "ttl_min": min(ttl_values),
                                           "ttl_max": max(ttl_values),
                                           "ttl_variance": ttl_variance
                                       })
        except (ValueError, statistics.StatisticsError):
            pass
    
    def _check_fragment_attacks(self, src_ip: str) -> None:
        """Check for fragmentation attacks (Feature 6)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        if self.ip_fragment_counts[src_ip] > FRAGMENT_THRESHOLD:
            self.stats["fragment_attacks_detected"] += 1
            self._trigger_dos_alert(src_ip, "", ["FRAGMENT_FLOOD"],
                                   self.ip_fragment_counts[src_ip],
                                   additional_info={
                                       "fragments": self.ip_fragment_counts[src_ip],
                                       "tiny_fragments": self.tiny_fragment_count
                                   })
    
    def _check_half_open_connections(self, src_ip: str) -> None:
        """Check for half-open connection attacks (Feature 7)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        syns = self.ip_syn_sent[src_ip]
        acks = self.ip_ack_received[src_ip]
        
        if syns > SYN_WITHOUT_ACK_THRESHOLD:
            if acks == 0 or (syns / max(acks, 1)) > (1 / (1 - HALF_OPEN_RATIO_THRESHOLD)):
                self._trigger_dos_alert(src_ip, "", ["HALF_OPEN_SYN_FLOOD"],
                                       syns,
                                       additional_info={
                                           "syn_sent": syns,
                                           "ack_received": acks,
                                           "completion_ratio": round(acks / max(syns, 1), 2)
                                       })
    
    def _check_burst_attacks(self, src_ip: str) -> None:
        """Check for burst attacks (Feature 8)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        if self.ip_burst_counts[src_ip] >= BURST_COUNT_THRESHOLD:
            self.stats["burst_attacks_detected"] += 1
            self._trigger_dos_alert(src_ip, "", ["BURST_ATTACK"],
                                   self.ip_packet_counts[src_ip],
                                   additional_info={
                                       "burst_count": self.ip_burst_counts[src_ip],
                                       "burst_window_ms": BURST_WINDOW_MS
                                   })
    
    def _check_app_layer_attacks(self, src_ip: str) -> None:
        """Check for application layer attacks (Feature 10)."""
        if src_ip in self.dos_alerts_this_window:
            return
        
        attack_types = []
        
        if self.ip_http_counts[src_ip] > HTTP_REQUEST_THRESHOLD:
            attack_types.append("HTTP_FLOOD")
        
        if self.ip_dns_counts[src_ip] > DNS_QUERY_THRESHOLD:
            attack_types.append("DNS_FLOOD")
        
        if attack_types:
            self.stats["app_layer_attacks_detected"] += 1
            self._trigger_dos_alert(src_ip, "", attack_types,
                                   self.ip_packet_counts[src_ip],
                                   additional_info={
                                       "http_requests": self.ip_http_counts[src_ip],
                                       "dns_queries": self.ip_dns_counts[src_ip]
                                   })
    
    def _trigger_dos_alert(self, src_ip: str, dst_ip: str, attack_types: List[str],
                          packet_count: int, additional_info: Dict = None) -> None:
        """Trigger a DoS alert."""
        self.dos_alerts_this_window.add(src_ip)
        self.stats["dos_attacks_detected"] += 1
        
        attack_type = " + ".join(attack_types)
        
        alert = Alert(
            timestamp=datetime.now(),
            attack_type=f"DoS: {attack_type}",
            source_ip=src_ip,
            severity=self._calculate_severity(packet_count, PACKET_THRESHOLD),
            description=f"DoS attack from {src_ip}",
            packet_count=packet_count,
            threshold=PACKET_THRESHOLD,
            additional_info=additional_info or {}
        )
        self.alerts.append(alert)
        
        # Display alert
        self._display_dos_alert(src_ip, attack_type, packet_count, additional_info)
        self.logger.log_attack_detected(src_ip, attack_type, PACKET_THRESHOLD, packet_count, additional_info)
        
        # Block the IP
        if ENABLE_AUTO_BLOCKING:
            self._block_ip(src_ip, attack_type)
    
    def _display_dos_alert(self, ip: str, attack_type: str, packets: int, 
                          additional_info: Dict = None) -> None:
        """Display DoS alert in console."""
        self.console.print(f"\n[bold red]🚨 DoS ALERT: {attack_type} from {ip}[/bold red]")
        self.console.print(f"[yellow]   Packets: {packets} | Type: {attack_type}[/yellow]")
        if additional_info:
            for key, value in list(additional_info.items())[:3]:
                self.console.print(f"[dim]   {key}: {value}[/dim]")
        self.console.print()

    # DDoS DETECTION (Aggregate) - Original + Enhanced
    
    def _check_ddos_attacks(self) -> None:
        """Check for distributed attacks using aggregate thresholds."""
        self._check_aggregate_syn_flood()
        self._check_aggregate_udp_flood()
        self._check_aggregate_icmp_flood()
        self._check_aggregate_packet_flood()
        self._check_ip_spike()
        self._check_low_and_slow()
        
        # Enhanced DDoS checks
        if ENABLE_TCP_FLAG_ANALYSIS:
            self._check_aggregate_tcp_flag_floods()
        if ENABLE_PACKET_SIZE_ANALYSIS:
            self._check_aggregate_size_attacks()
        if ENABLE_ICMP_TYPE_ANALYSIS:
            self._check_aggregate_icmp_type_attacks()
    
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
    
    def _check_aggregate_tcp_flag_floods(self) -> None:
        """Check for distributed TCP flag floods."""
        if 'ddos_ack' not in self.ddos_alerts_this_window and self.total_ack > AGGREGATE_ACK_THRESHOLD:
            self.ddos_alerts_this_window.add('ddos_ack')
            self._trigger_ddos_alert(
                "DISTRIBUTED_ACK_FLOOD",
                self.total_ack,
                AGGREGATE_ACK_THRESHOLD,
                f"Distributed ACK flood from {len(self.window_all_ips)} sources"
            )
        
        if 'ddos_fin' not in self.ddos_alerts_this_window and self.total_fin > AGGREGATE_FIN_THRESHOLD:
            self.ddos_alerts_this_window.add('ddos_fin')
            self._trigger_ddos_alert(
                "DISTRIBUTED_FIN_FLOOD",
                self.total_fin,
                AGGREGATE_FIN_THRESHOLD,
                f"Distributed FIN flood from {len(self.window_all_ips)} sources"
            )
        
        if 'ddos_rst' not in self.ddos_alerts_this_window and self.total_rst > AGGREGATE_RST_THRESHOLD:
            self.ddos_alerts_this_window.add('ddos_rst')
            self._trigger_ddos_alert(
                "DISTRIBUTED_RST_FLOOD",
                self.total_rst,
                AGGREGATE_RST_THRESHOLD,
                f"Distributed RST flood from {len(self.window_all_ips)} sources"
            )
    
    def _check_aggregate_size_attacks(self) -> None:
        """Check for distributed size-based attacks."""
        if 'ddos_small_pkt' not in self.ddos_alerts_this_window and self.total_small_packets > AGGREGATE_SMALL_PACKET_THRESHOLD:
            self.ddos_alerts_this_window.add('ddos_small_pkt')
            self._trigger_ddos_alert(
                "DISTRIBUTED_SMALL_PACKET_FLOOD",
                self.total_small_packets,
                AGGREGATE_SMALL_PACKET_THRESHOLD,
                f"Distributed small packet flood from {len(self.window_all_ips)} sources"
            )
        
        if 'ddos_large_pkt' not in self.ddos_alerts_this_window and self.total_large_packets > AGGREGATE_LARGE_PACKET_THRESHOLD:
            self.ddos_alerts_this_window.add('ddos_large_pkt')
            bandwidth_mbps = (self.total_bytes * 8) / (TIME_WINDOW * 1_000_000)
            self._trigger_ddos_alert(
                "DISTRIBUTED_AMPLIFICATION_ATTACK",
                self.total_large_packets,
                AGGREGATE_LARGE_PACKET_THRESHOLD,
                f"Distributed amplification attack - {bandwidth_mbps:.1f} Mbps from {len(self.window_all_ips)} sources"
            )
    
    def _check_aggregate_icmp_type_attacks(self) -> None:
        """Check for distributed ICMP type attacks."""
        if 'ddos_ping' not in self.ddos_alerts_this_window and self.total_icmp_echo_req > AGGREGATE_ICMP_ECHO_THRESHOLD:
            self.ddos_alerts_this_window.add('ddos_ping')
            self._trigger_ddos_alert(
                "DISTRIBUTED_PING_FLOOD",
                self.total_icmp_echo_req,
                AGGREGATE_ICMP_ECHO_THRESHOLD,
                f"Distributed ping flood from {len(self.window_all_ips)} sources"
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
        """Check for low-and-slow attacks."""
        if 'low_slow' in self.ddos_alerts_this_window:
            return
        
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
    
    def _check_protocol_anomaly(self) -> None:
        """Check for protocol distribution anomalies (Feature 9)."""
        if 'protocol_anomaly' in self.ddos_alerts_this_window:
            return
        
        if self.total_packets < 100:  # Need enough samples
            return
        
        # Calculate current ratios
        current_ratios = {
            proto: count / self.total_packets
            for proto, count in self.protocol_counts.items()
        }
        
        # Check for deviations
        for proto, baseline in PROTOCOL_BASELINE.items():
            current = current_ratios.get(proto, 0)
            deviation = abs(current - baseline)
            
            if deviation > PROTOCOL_DEVIATION_THRESHOLD:
                self.ddos_alerts_this_window.add('protocol_anomaly')
                self._trigger_ddos_alert(
                    f"PROTOCOL_ANOMALY_{proto.upper()}",
                    int(current * 100),
                    int(baseline * 100),
                    f"Protocol anomaly: {proto.upper()} at {current*100:.1f}% (baseline: {baseline*100:.1f}%)"
                )
                break
    
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
    
    # UTILITY METHODS
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for a port."""
        services = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
            25: "SMTP", 53: "DNS", 3306: "MySQL", 5432: "PostgreSQL",
            6379: "Redis", 11211: "Memcached", 123: "NTP"
        }
        return services.get(port, str(port))
    
    def _block_ip(self, ip: str, attack_type: str) -> None:
        """Block an attacking IP address."""
        success = self.mitigator.block_ip(ip)
        if success:
            self.blocked_ips_cache.add(ip)
            self.stats["ips_blocked"] += 1
        self.logger.log_ip_blocked(ip, attack_type, success)
    
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
                    "total_icmp": self.total_icmp,
                    "total_bytes": self.total_bytes,
                    "malformed_packets": self.stats["malformed_packets"]
                })
            
            # Write stats to JSON for dashboard
            self._write_stats_json()
            
            # Update known IPs
            self.known_ips.update(self.window_new_ips)
            
            # Reset all counters
            self._reset_all_counters()
    
    def _reset_all_counters(self) -> None:
        """Reset all window-specific counters."""
        # Basic counters
        self.ip_packet_counts.clear()
        self.ip_syn_counts.clear()
        self.ip_udp_counts.clear()
        self.ip_icmp_counts.clear()
        self.total_packets = 0
        self.total_syn = 0
        self.total_udp = 0
        self.total_icmp = 0
        
        # TCP flag counters
        self.ip_ack_counts.clear()
        self.ip_fin_counts.clear()
        self.ip_rst_counts.clear()
        self.ip_syn_ack_counts.clear()
        self.ip_xmas_counts.clear()
        self.ip_null_counts.clear()
        self.ip_invalid_flags_counts.clear()
        self.total_ack = 0
        self.total_fin = 0
        self.total_rst = 0
        self.total_syn_ack = 0
        self.total_xmas = 0
        self.total_null = 0
        self.total_invalid_flags = 0
        
        # Size counters
        self.ip_small_packet_counts.clear()
        self.ip_large_packet_counts.clear()
        self.ip_bytes.clear()
        self.total_small_packets = 0
        self.total_large_packets = 0
        self.total_bytes = 0
        
        # ICMP counters
        self.ip_icmp_echo_req_counts.clear()
        self.ip_icmp_echo_reply_counts.clear()
        self.ip_icmp_unreachable_counts.clear()
        self.total_icmp_echo_req = 0
        self.total_icmp_echo_reply = 0
        
        # Port counters
        self.ip_ports_hit.clear()
        self.ip_port_counts.clear()
        self.port_packet_counts.clear()
        
        # TTL tracking
        self.ip_ttl_values.clear()
        self.low_ttl_count = 0
        self.ttl_anomaly_count = 0
        
        # Fragment counters
        self.ip_fragment_counts.clear()
        self.total_fragments = 0
        self.tiny_fragment_count = 0
        
        # Connection tracking
        self.ip_syn_sent.clear()
        self.ip_ack_received.clear()
        self.pending_connections.clear()
        
        # Burst tracking
        self.ip_packet_timestamps.clear()
        self.ip_burst_counts.clear()
        
        # Protocol counts
        self.protocol_counts = {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}
        
        # App layer counters
        self.ip_http_counts.clear()
        self.ip_dns_counts.clear()
        self.total_http = 0
        self.total_dns = 0
        
        # IP tracking
        self.window_new_ips.clear()
        self.window_all_ips.clear()
        self.dos_alerts_this_window.clear()
        self.ddos_alerts_this_window.clear()
        self.window_start = datetime.now()
    
    def _write_stats_json(self) -> None:
        """Write current stats to JSON file for web dashboard."""
        try:
            bandwidth_mbps = (self.total_bytes * 8) / (TIME_WINDOW * 1_000_000) if TIME_WINDOW > 0 else 0
            
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
                'detector_running': True,
                # Enhanced stats
                'malformed_packets': self.stats["malformed_packets"],
                'port_scans': self.stats["port_scans_detected"],
                'spoofed_detected': self.stats["spoofed_packets_detected"],
                'fragment_attacks': self.stats["fragment_attacks_detected"],
                'burst_attacks': self.stats["burst_attacks_detected"],
                'app_layer_attacks': self.stats["app_layer_attacks_detected"],
                'bandwidth_mbps': round(bandwidth_mbps, 2),
                'protocol_distribution': self.protocol_counts
            }
            with open('stats.json', 'w') as f:
                json.dump(stats_data, f, indent=2)
        except Exception as e:
            self.logger.log_error(f"Failed to write stats.json: {e}")
    
    # STATISTICS & DASHBOARD
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current detector statistics."""
        with self.lock:
            uptime = datetime.now() - self.stats["start_time"]
            bandwidth_mbps = (self.total_bytes * 8) / (TIME_WINDOW * 1_000_000) if TIME_WINDOW > 0 else 0
            
            return {
                "uptime": str(uptime).split('.')[0],
                "total_packets": self.stats["total_packets_all_time"],
                "dos_attacks": self.stats["dos_attacks_detected"],
                "ddos_attacks": self.stats["ddos_attacks_detected"],
                "ips_blocked": self.stats["ips_blocked"],
                "current_window_packets": self.total_packets,
                "unique_ips": len(self.window_all_ips),
                "known_ips": len(self.known_ips),
                "malformed_packets": self.stats["malformed_packets"],
                "port_scans": self.stats["port_scans_detected"],
                "bandwidth_mbps": round(bandwidth_mbps, 2)
            }
    
    def get_recent_alerts(self, limit: int = 10) -> List[Alert]:
        """Get most recent alerts."""
        return self.alerts[-limit:]
    
    def create_traffic_table(self) -> Table:
        """Create traffic monitoring table for CLI dashboard."""
        table = Table(
            title=" Enhanced Real-Time Traffic Monitor",
            title_style="bold cyan",
            show_header=True,
            header_style="bold magenta",
            border_style="blue"
        )
        
        table.add_column("IP Address", style="cyan", width=16)
        table.add_column("Pkts", justify="right", style="green", width=6)
        table.add_column("SYN", justify="right", style="yellow", width=5)
        table.add_column("ACK", justify="right", style="blue", width=5)
        table.add_column("UDP", justify="right", style="magenta", width=5)
        table.add_column("Ports", justify="right", style="cyan", width=5)
        table.add_column("Flags", justify="center", width=8)
        table.add_column("Status", justify="center", width=12)
        
        with self.lock:
            if self.ip_packet_counts:
                sorted_ips = sorted(
                    self.ip_packet_counts.items(),
                    key=lambda x: x[1], reverse=True
                )[:12]
                
                for ip, count in sorted_ips:
                    syn = self.ip_syn_counts.get(ip, 0)
                    ack = self.ip_ack_counts.get(ip, 0)
                    udp = self.ip_udp_counts.get(ip, 0)
                    ports = len(self.ip_ports_hit.get(ip, set()))
                    
                    # Flag indicators
                    flags = []
                    if self.ip_xmas_counts.get(ip, 0) > 0: flags.append("X")
                    if self.ip_null_counts.get(ip, 0) > 0: flags.append("N")
                    if self.ip_invalid_flags_counts.get(ip, 0) > 0: flags.append("!")
                    if self.ip_burst_counts.get(ip, 0) > 0: flags.append("B")
                    flags_str = "".join(flags) if flags else "-"
                    
                    # Determine status
                    if self.mitigator.is_blocked(ip):
                        status = "[red] BLOCKED[/red]"
                        style = "dim"
                    elif ip in self.dos_alerts_this_window:
                        status = "[red] ALERT[/red]"
                        style = "bold red"
                    elif (count > PACKET_THRESHOLD * 0.7 or syn > SYN_THRESHOLD * 0.7 or
                          ports > PORT_SCAN_THRESHOLD * 0.7):
                        status = "[yellow]⚡ WARN[/yellow]"
                        style = "yellow"
                    else:
                        status = "[green]✓ OK[/green]"
                        style = ""
                    
                    table.add_row(
                        ip, str(count), str(syn), str(ack), str(udp),
                        str(ports), flags_str, status, style=style
                    )
            else:
                table.add_row("No traffic", "-", "-", "-", "-", "-", "-", "[dim]Idle[/dim]")
        
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
        text.append(f"Bandwidth: ", style="bold")
        text.append(f"{stats['bandwidth_mbps']} Mbps\n", style="cyan")
        text.append(f"DoS Attacks: ", style="bold")
        text.append(f"{stats['dos_attacks']}\n", style="red")
        text.append(f"DDoS Attacks: ", style="bold")
        text.append(f"{stats['ddos_attacks']}\n", style="red")
        text.append(f"IPs Blocked: ", style="bold")
        text.append(f"{stats['ips_blocked']}\n", style="red")
        text.append(f"Malformed: ", style="bold")
        text.append(f"{stats['malformed_packets']}\n", style="magenta")
        
        return Panel(text, title=" System Info", border_style="green")
    
    def create_thresholds_panel(self) -> Panel:
        """Create thresholds panel for CLI dashboard."""
        text = Text()
        text.append("DoS Thresholds (Per-IP)\n", style="bold underline magenta")
        text.append(f"Pkt:{PACKET_THRESHOLD} SYN:{SYN_THRESHOLD} UDP:{UDP_THRESHOLD} ICMP:{ICMP_THRESHOLD}\n", style="cyan")
        text.append(f"ACK:{ACK_THRESHOLD} FIN:{FIN_THRESHOLD} RST:{RST_THRESHOLD}\n", style="cyan")
        
        text.append("\nDDoS Thresholds (Aggregate)\n", style="bold underline red")
        text.append(f"Pkt:{AGGREGATE_PACKET_THRESHOLD} SYN:{AGGREGATE_SYN_THRESHOLD} UDP:{AGGREGATE_UDP_THRESHOLD}\n", style="red")
        
        text.append(f"\nTime Window: {TIME_WINDOW}s", style="cyan")
        
        # Feature flags
        text.append("\n\nEnabled Features: ", style="bold")
        features = []
        if ENABLE_TCP_FLAG_ANALYSIS: features.append("TCP")
        if ENABLE_PACKET_SIZE_ANALYSIS: features.append("Size")
        if ENABLE_PORT_ANALYSIS: features.append("Port")
        if ENABLE_TTL_ANALYSIS: features.append("TTL")
        if ENABLE_BURST_DETECTION: features.append("Burst")
        text.append(", ".join(features), style="green")
        
        return Panel(text, title="⚙️ Configuration", border_style="yellow")


# MAIN EXECUTION
def main():
    """Main entry point for the enhanced detector."""
    console = Console()
    
    # Display banner
    console.print("\n[bold cyan]" + "=" * 70 + "[/bold cyan]")
    console.print("[bold cyan]ENHANCED DoS/DDoS DETECTION SYSTEM[/bold cyan]", justify="center")
    console.print("[bold cyan]Advanced Multi-Vector Attack Detection[/bold cyan]", justify="center")
    console.print("[bold cyan]10 Detection Features Enabled[/bold cyan]", justify="center")
    console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
    
    # Initialize detector
    detector = UnifiedDetector()
    
    # Display configuration
    console.print(detector.create_status_panel())
    console.print(detector.create_thresholds_panel())
    
    # Display enabled features
    console.print("\n[bold green] Enhanced Detection Features:[/bold green]")
    features = [
        ("TCP Flag Analysis", ENABLE_TCP_FLAG_ANALYSIS, "ACK/FIN/RST/XMAS/NULL floods"),
        ("Packet Size Analysis", ENABLE_PACKET_SIZE_ANALYSIS, "Amplification & small packet floods"),
        ("ICMP Type Analysis", ENABLE_ICMP_TYPE_ANALYSIS, "Ping floods, smurf attacks"),
        ("Port Analysis", ENABLE_PORT_ANALYSIS, "Port scans, service attacks"),
        ("TTL Analysis", ENABLE_TTL_ANALYSIS, "Spoofed traffic detection"),
        ("Fragment Detection", ENABLE_FRAGMENT_DETECTION, "Teardrop, frag floods"),
        ("Connection Tracking", ENABLE_CONNECTION_TRACKING, "Half-open SYN floods"),
        ("Burst Detection", ENABLE_BURST_DETECTION, "Micro-burst attacks"),
        ("Protocol Anomaly", ENABLE_PROTOCOL_ANOMALY, "Traffic pattern anomalies"),
        ("App Layer Inspection", ENABLE_APP_LAYER_INSPECTION, "HTTP/DNS attacks"),
    ]
    
    for name, enabled, desc in features:
        status = "[green]✓[/green]" if enabled else "[red]✗[/red]"
        console.print(f"  {status} {name}: [dim]{desc}[/dim]")
    
    console.print(f"\n[bold green] Mitigation: ENABLED[/bold green] (iptables)")
    console.print("[bold green] Logging: ENABLED[/bold green] (logs/ directory)")
    console.print("[bold yellow] Warning: Malicious IPs will be automatically blocked![/bold yellow]")
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
        stats_table.add_row("Malformed Packets", str(stats["malformed_packets"]))
        stats_table.add_row("Port Scans Detected", str(stats["port_scans"]))
        
        console.print(stats_table)
        
        if detector.mitigator.get_blocked_count() > 0:
            console.print(f"\n[red]Blocked IPs:[/red]")
            for ip in detector.mitigator.get_blocked_ips():
                console.print(f"  [red] {ip}[/red]")
        
        detector.logger.log_shutdown(stats)
        console.print("\n[bold green] Shutdown complete![/bold green]\n")
        
    except PermissionError:
        console.print("\n[bold red] ERROR: Permission denied![/bold red]")
        console.print("[yellow]Run with sudo: sudo python3 src/detector.py[/yellow]\n")
        
    except Exception as e:
        console.print(f"\n[bold red] ERROR: {e}[/bold red]")
        detector.logger.log_error(f"Runtime error: {e}", e)


if __name__ == "__main__":
    main()
