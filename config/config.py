# Configuration File for DDoS Detection System

# Network Configuration
NETWORK_INTERFACE = "enp0s3"  # Change this to your Linux interface (e.g., eth0, wlp1s0)

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

# Platform Detection
# Note: iptables blocking only works on Linux
# On Windows, the system will run in simulation mode
