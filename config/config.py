# PyDOS Configuration File - ENHANCED VERSION
# Central configuration for the DDoS/DoS Detection System
# All detection thresholds and system settings are defined here.
# 
# ENHANCED FEATURES (10 New Detection Capabilities):
# 1. TCP Flag Analysis (ACK, FIN, RST, SYN-ACK, XMAS, NULL floods)
# 2. Packet Size Analysis (amplification, small packet floods)
# 3. ICMP Type Analysis (ping flood, smurf detection)
# 4. Destination Port Analysis (port scan, service-targeted attacks)
# 5. TTL Anomaly Detection (spoofed traffic detection)
# 6. Fragment Attack Detection (teardrop, frag floods)
# 7. Connection State Tracking (half-open connection detection)
# 8. Burst Detection (micro-burst attacks)
# 9. Protocol Distribution Anomaly (unusual traffic mix)
# 10. Application Layer Inspection (HTTP/DNS attacks)

from src.utils import get_default_network_interface

# NETWORK CONFIGURATION
_AUTO_DETECTED_INTERFACE = get_default_network_interface()
NETWORK_INTERFACE = _AUTO_DETECTED_INTERFACE if _AUTO_DETECTED_INTERFACE else "eth0"

# Time window for detection (seconds)
TIME_WINDOW = 5.0  # Counters reset every 5 seconds

# DoS DETECTION THRESHOLDS (Per-IP - Single Source Attacks)
# These thresholds detect attacks from a SINGLE source IP
# If any IP exceeds these limits within TIME_WINDOW, it's flagged as DoS attack

PACKET_THRESHOLD = 100  # Max packets per IP per window
SYN_THRESHOLD = 50      # Max SYN packets per IP per window
UDP_THRESHOLD = 50      # Max UDP packets per IP per window
ICMP_THRESHOLD = 50     # Max ICMP packets per IP per window

# ENHANCED TCP FLAG THRESHOLDS (Per-IP)
# Feature 1: TCP Flag Analysis - Detect various TCP flood attack types

ACK_THRESHOLD = 50       # Max ACK packets per IP per window
FIN_THRESHOLD = 30       # Max FIN packets per IP per window  
RST_THRESHOLD = 30       # Max RST packets per IP per window
SYN_ACK_THRESHOLD = 40   # Max SYN-ACK packets per IP per window
XMAS_THRESHOLD = 5       # Max XMAS scan packets (immediate alert - always malicious)
NULL_THRESHOLD = 5       # Max NULL scan packets (immediate alert - always malicious)
INVALID_FLAGS_THRESHOLD = 3  # Max invalid flag combinations (SYN+FIN, etc.)

# DDoS DETECTION THRESHOLDS (Aggregate - Distributed Attacks)
# These thresholds detect attacks from MULTIPLE source IPs combined

AGGREGATE_PACKET_THRESHOLD = 1000  # Total packets from ALL IPs per window
AGGREGATE_SYN_THRESHOLD = 500      # Total SYN packets from ALL IPs per window
AGGREGATE_UDP_THRESHOLD = 500      # Total UDP packets from ALL IPs per window
AGGREGATE_ICMP_THRESHOLD = 300     # Total ICMP packets from ALL IPs per window

# Aggregate TCP flag thresholds
AGGREGATE_ACK_THRESHOLD = 500      # Total ACK flood threshold
AGGREGATE_FIN_THRESHOLD = 300      # Total FIN flood threshold
AGGREGATE_RST_THRESHOLD = 300      # Total RST flood threshold

# PACKET SIZE ANALYSIS (Feature 2)
# Detect amplification attacks (large packets) and small packet floods

SMALL_PACKET_SIZE = 64          # Packets <= this size are "small" (bytes)
LARGE_PACKET_SIZE = 1000        # Packets >= this size are "large" (bytes)
SMALL_PACKET_THRESHOLD = 80     # Max small packets per IP per window (per-IP)
LARGE_PACKET_THRESHOLD = 50     # Max large packets per IP per window (amplification)
AGGREGATE_SMALL_PACKET_THRESHOLD = 800   # Aggregate small packet flood
AGGREGATE_LARGE_PACKET_THRESHOLD = 400   # Aggregate amplification attack
BANDWIDTH_THRESHOLD_MBPS = 10   # Bandwidth threshold in Mbps per window

# ICMP TYPE ANALYSIS (Feature 3)
# Differentiate ICMP attack types

ICMP_ECHO_REQUEST_THRESHOLD = 30    # Max ping requests per IP (type 8)
ICMP_ECHO_REPLY_THRESHOLD = 50      # Max ping replies per IP (type 0) - smurf indicator
ICMP_UNREACHABLE_THRESHOLD = 20     # Max destination unreachable per IP (type 3)
AGGREGATE_ICMP_ECHO_THRESHOLD = 300 # Aggregate ping flood

# DESTINATION PORT ANALYSIS (Feature 4)
# Detect port scanning and service-targeted attacks

PORT_SCAN_THRESHOLD = 15           # Max unique ports hit by single IP = port scan
SERVICE_PORT_THRESHOLD = 100       # Max packets to single service port per IP
AGGREGATE_PORT_CONCENTRATION = 0.8 # If >80% traffic to one port = service attack

# Common service ports to monitor
MONITORED_PORTS = [80, 443, 22, 21, 25, 53, 3306, 5432, 6379, 11211, 123]

# TTL ANOMALY DETECTION (Feature 5)
# Detect spoofed packets via TTL analysis

TTL_VARIANCE_THRESHOLD = 30        # Max TTL variance for single IP (spoofing indicator)
LOW_TTL_THRESHOLD = 5              # TTL values below this are suspicious
TTL_ANOMALY_PERCENTAGE = 0.3       # If >30% packets have anomalous TTL = spoofing

# FRAGMENT ATTACK DETECTION (Feature 6)
# Detect IP fragmentation attacks

FRAGMENT_THRESHOLD = 20            # Max fragmented packets per IP per window
AGGREGATE_FRAGMENT_THRESHOLD = 200 # Aggregate fragment flood
TINY_FRAGMENT_SIZE = 60            # Fragments smaller than this are suspicious
FRAGMENT_OVERLAP_ALERT = True      # Alert on overlapping fragments (teardrop)

# CONNECTION STATE TRACKING (Feature 7)
# Track TCP handshake completion for half-open detection

HALF_OPEN_RATIO_THRESHOLD = 0.8    # If >80% SYNs don't complete = SYN flood
SYN_WITHOUT_ACK_THRESHOLD = 40     # Max SYNs without corresponding ACK per IP
CONNECTION_TRACKING_ENABLED = True # Enable stateful connection tracking

# BURST DETECTION (Feature 8)
# Detect micro-bursts within time windows

BURST_WINDOW_MS = 100              # Micro-window for burst detection (milliseconds)
BURST_PACKET_THRESHOLD = 20        # Max packets in micro-window per IP
BURST_COUNT_THRESHOLD = 3          # Max bursts per IP per main window

# PROTOCOL DISTRIBUTION ANOMALY (Feature 9)
# Alert when protocol ratios deviate significantly from baseline

PROTOCOL_BASELINE = {
    'tcp': 0.70,   # Expected ~70% TCP
    'udp': 0.20,   # Expected ~20% UDP
    'icmp': 0.05,  # Expected ~5% ICMP
    'other': 0.05  # Expected ~5% other
}
PROTOCOL_DEVIATION_THRESHOLD = 0.3  # Alert if deviation > 30% from baseline

# APPLICATION LAYER INSPECTION (Feature 10)
# Basic HTTP/DNS attack detection

# HTTP Detection
HTTP_REQUEST_THRESHOLD = 50        # Max HTTP requests per IP per window
HTTP_SLOW_HEADERS_TIMEOUT = 10     # Seconds - Slowloris detection
HTTP_SLOW_BODY_TIMEOUT = 30        # Seconds - Slow POST detection
HTTP_PORTS = [80, 8080, 8000, 8443, 443]

# DNS Detection  
DNS_QUERY_THRESHOLD = 30           # Max DNS queries per IP per window
DNS_AMPLIFICATION_SIZE = 512       # Response > this size = potential amplification
DNS_PORT = 53

# IP SPIKE DETECTION (Botnet Indicator)
NEW_IP_SPIKE_THRESHOLD = 50        # New unique IPs per window to trigger alert

# LOW-AND-SLOW ATTACK DETECTION
LOW_SLOW_MIN_SOURCES = 20          # Minimum sources to consider low-and-slow
LOW_SLOW_PER_IP_MAX = 50           # Max packets per IP (should be < PACKET_THRESHOLD)
LOW_SLOW_AGGREGATE_MIN = 500       # Min aggregate to trigger alert

# ATTACK SIMULATION SETTINGS
DEFAULT_ATTACK_TARGET = "127.0.0.1"
DEFAULT_ATTACK_PORT = 80
DEFAULT_PACKET_COUNT = 200
DEFAULT_DDOS_SOURCES = 100
DEFAULT_PACKET_DELAY = 0.001

# WEB DASHBOARD CONFIGURATION
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5001

# LOGGING CONFIGURATION
LOG_DIRECTORY = "logs"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 5

# SYSTEM CONFIGURATION
ENABLE_AUTO_BLOCKING = True
ENABLE_WEB_DASHBOARD = True
ENABLE_CLI_DASHBOARD = True

# FEATURE FLAGS - Enable/Disable Enhanced Detection Features
ENABLE_TCP_FLAG_ANALYSIS = True          # Feature 1
ENABLE_PACKET_SIZE_ANALYSIS = True       # Feature 2
ENABLE_ICMP_TYPE_ANALYSIS = True         # Feature 3
ENABLE_PORT_ANALYSIS = True              # Feature 4
ENABLE_TTL_ANALYSIS = True               # Feature 5
ENABLE_FRAGMENT_DETECTION = True         # Feature 6
ENABLE_CONNECTION_TRACKING = True        # Feature 7
ENABLE_BURST_DETECTION = True            # Feature 8
ENABLE_PROTOCOL_ANOMALY = True           # Feature 9
ENABLE_APP_LAYER_INSPECTION = True       # Feature 10

# TESTING/DEVELOPMENT CONFIGURATION
ALLOW_LOOPBACK_DETECTION = True
TESTING_MODE = True

# PLATFORM NOTES
# - iptables blocking only works on Linux
# - On Windows, the system runs in simulation mode (no actual blocking)
# - For full functionality, use Linux (native or VM)
