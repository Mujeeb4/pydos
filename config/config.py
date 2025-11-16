# Configuration File for DDoS Detection System

from src.utils import get_default_network_interface

# Network Configuration
# Automatically detect the default network interface
_AUTO_DETECTED_INTERFACE = get_default_network_interface()
NETWORK_INTERFACE = _AUTO_DETECTED_INTERFACE if _AUTO_DETECTED_INTERFACE else "eth0"  # Fallback to eth0 if detection fails

# Detection Thresholds
PACKET_THRESHOLD = 100  # Packets per time window to trigger packet flood alert
SYN_THRESHOLD = 50      # SYN packets per time window to trigger SYN flood alert

# Time Window (seconds)
TIME_WINDOW = 5.0  # Reset counters every 5 seconds

# Web Dashboard Configuration
DASHBOARD_HOST = "0.0.0.0"  # Listen on all interfaces
DASHBOARD_PORT = 5001       # Web dashboard port

# Logging Configuration
LOG_DIRECTORY = "logs"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 5              # Keep 5 backup files

# System Configuration
ENABLE_AUTO_BLOCKING = True  # Automatically block detected attackers
ENABLE_WEB_DASHBOARD = True  # Enable web dashboard
ENABLE_CLI_DASHBOARD = True  # Enable terminal dashboard

# Testing Configuration
# IMPORTANT: Set ALLOW_LOOPBACK_DETECTION = True during development/testing
# to detect attacks from 127.0.0.1. In production, keep it False to avoid
# false positives from local services.
ALLOW_LOOPBACK_DETECTION = True  # Allow detection of loopback (127.0.0.1) attacks for testing
TESTING_MODE = True  # Enable testing mode features

# Attack Simulation Defaults
# Change this to your actual network IP for realistic testing
# Example: "192.168.1.100" or use the IP of your network interface
DEFAULT_ATTACK_TARGET = "127.0.0.1"  # Default target for attack simulation

# Platform Detection
# Note: iptables blocking only works on Linux
# On Windows, the system will run in simulation mode
