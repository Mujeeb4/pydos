# =============================================================================
# PyDOS Configuration File
# =============================================================================
# Central configuration for the DDoS/DoS Detection System
# All detection thresholds and system settings are defined here.

from src.utils import get_default_network_interface

# NETWORK CONFIGURATION
# Automatically detect the default network interface
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

# DDoS DETECTION THRESHOLDS (Aggregate - Distributed Attacks)
# These thresholds detect attacks from MULTIPLE source IPs combined
# Even if each IP is under per-IP limit, high aggregate = DDoS attack

AGGREGATE_PACKET_THRESHOLD = 1000  # Total packets from ALL IPs per window
AGGREGATE_SYN_THRESHOLD = 500      # Total SYN packets from ALL IPs per window
AGGREGATE_UDP_THRESHOLD = 500      # Total UDP packets from ALL IPs per window
AGGREGATE_ICMP_THRESHOLD = 300     # Total ICMP packets from ALL IPs per window

# IP SPIKE DETECTION (Botnet Indicator)
# Detects sudden flood of new source IPs (typical botnet behavior)

NEW_IP_SPIKE_THRESHOLD = 50    # New unique IPs per window to trigger alert

# LOW-AND-SLOW ATTACK DETECTION
# Detects sophisticated attacks where each IP stays under threshold
# but combined traffic is overwhelming

LOW_SLOW_MIN_SOURCES = 20      # Minimum sources to consider low-and-slow
LOW_SLOW_PER_IP_MAX = 50       # Max packets per IP (should be < PACKET_THRESHOLD)
LOW_SLOW_AGGREGATE_MIN = 500   # Min aggregate to trigger alert

# ATTACK SIMULATION SETTINGS
# Default settings for attack simulators (simulate_attack.py, simulate_ddos.py)

DEFAULT_ATTACK_TARGET = "127.0.0.1"  # Default target IP
DEFAULT_ATTACK_PORT = 80             # Default target port
DEFAULT_PACKET_COUNT = 200           # Default packets per attack type
DEFAULT_DDOS_SOURCES = 100           # Default spoofed IPs for DDoS simulation
DEFAULT_PACKET_DELAY = 0.001         # Delay between packets (seconds)

# WEB DASHBOARD CONFIGURATION
DASHBOARD_HOST = "0.0.0.0"  # Listen on all interfaces (use 127.0.0.1 for local only)
DASHBOARD_PORT = 5001       # Web dashboard port

# LOGGING CONFIGURATION
LOG_DIRECTORY = "logs"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB max per log file
LOG_BACKUP_COUNT = 5              # Keep 5 backup files

# SYSTEM CONFIGURATION
ENABLE_AUTO_BLOCKING = True   # Automatically block detected attackers via iptables
ENABLE_WEB_DASHBOARD = True   # Enable web dashboard
ENABLE_CLI_DASHBOARD = True   # Enable terminal dashboard

# TESTING/DEVELOPMENT CONFIGURATION
# Set ALLOW_LOOPBACK_DETECTION = True during development/testing
# to detect attacks from 127.0.0.1
# In production, set to False to avoid false positives from local services

ALLOW_LOOPBACK_DETECTION = True  # Allow detection from 127.0.0.1 (testing)
TESTING_MODE = True              # Enable testing mode features

# PLATFORM NOTES
# - iptables blocking only works on Linux
# - On Windows, the system runs in simulation mode (no actual blocking)
# - For full functionality, use Linux (native or VM)
