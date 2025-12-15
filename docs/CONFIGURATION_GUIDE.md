# Configuration Guide

## Overview

The configuration system provides centralized management of all DDoS detection system settings through the `config/config.py` file. This allows easy customization without modifying core code.

## Configuration File Location

```
pydos/
└── config/
    └── config.py
```

## Configuration Categories

### 1. Network Configuration

#### Network Interface

```python
NETWORK_INTERFACE = "wlp1s0"  # Your network interface name
```

**Auto-detection**:
```python
from src.utils import get_default_network_interface
NETWORK_INTERFACE = get_default_network_interface()
```

**Common Interface Names**:
- **Wired**: `eth0`, `enp0s3`, `enp3s0`
- **Wireless**: `wlan0`, `wlp1s0`, `wlp2s0`
- **Loopback**: `lo` (127.0.0.1)
- **Virtual**: `veth0`, `docker0`

**How to Find Your Interface**:
```bash
# Linux
ip addr show
ip link show

# Display active interface
ip route | grep default

# Windows (not applicable - Linux only)
ipconfig
```

**Example Output**:
```
1: lo: <LOOPBACK,UP,LOWER_UP>
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
3: wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP>
```

### 2. Detection Thresholds

#### Packet Flood Threshold

```python
PACKET_THRESHOLD = 100  # Packets per TIME_WINDOW
```

**Purpose**: Detect volumetric DDoS attacks

**Tuning Guide**:
- **Conservative** (fewer false positives): 200-500
- **Balanced** (default): 100-200
- **Aggressive** (more sensitive): 50-100
- **Very Aggressive**: 25-50

**Factors to Consider**:
- Network baseline traffic
- Server type (web, database, etc.)
- Expected legitimate traffic peaks
- Time of day variations

**Example Scenarios**:
```python
# High-traffic web server
PACKET_THRESHOLD = 500

# Low-traffic internal server
PACKET_THRESHOLD = 50

# Testing/development
PACKET_THRESHOLD = 20
```

#### SYN Flood Threshold

```python
SYN_THRESHOLD = 50  # SYN packets per TIME_WINDOW
```

**Purpose**: Detect TCP SYN flood attacks

**Tuning Guide**:
- **Conservative**: 100-200
- **Balanced**: 50-100
- **Aggressive**: 25-50

**Relationship to Packet Threshold**:
```python
# Typically 40-60% of PACKET_THRESHOLD
SYN_THRESHOLD = int(PACKET_THRESHOLD * 0.5)
```

**Why Separate Threshold?**
- SYN floods are specific attack type
- Can detect even with low overall packet count
- Targets connection exhaustion vs. bandwidth

### 3. Time Windows

```python
TIME_WINDOW = 5.0  # seconds
```

**Purpose**: Rolling time window for counting packets

**Options**:
- **Short** (1-3 seconds): More responsive, more false positives
- **Medium** (5 seconds): Balanced (default)
- **Long** (10-30 seconds): Less sensitive, fewer false positives

**Impact on Detection**:
```python
# Same traffic, different windows:

# TIME_WINDOW = 1.0
# 100 packets in 1 sec = Attack ✓

# TIME_WINDOW = 10.0
# 100 packets in 10 sec = Normal ✗
```

**Calculation Example**:
```
PACKET_THRESHOLD = 100
TIME_WINDOW = 5.0

Detection Rate = 100 packets / 5 seconds = 20 packets/sec
```

### 4. Dashboard Configuration

#### Web Dashboard

```python
DASHBOARD_HOST = "0.0.0.0"  # Listen on all interfaces
DASHBOARD_PORT = 5001        # HTTP server port
ENABLE_WEB_DASHBOARD = True  # Enable/disable web interface
```

**Host Options**:
- `"0.0.0.0"`: All interfaces (public access)
- `"127.0.0.1"`: Localhost only (secure)
- `"192.168.1.100"`: Specific IP

**Port Options**:
- `5001`: Default
- `8080`: Alternative HTTP port
- `5000`: Flask default

**Security Considerations**:
```python
# Production: Restrict to localhost
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5001

# Development: Allow network access
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5001
```

#### CLI Dashboard

```python
ENABLE_CLI_DASHBOARD = True  # Enable terminal dashboard
```

### 5. Logging Configuration

```python
LOG_DIRECTORY = "logs"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB per file
LOG_BACKUP_COUNT = 5              # Keep 5 backup files
```

**Log Directory Options**:
```python
# Relative path (default)
LOG_DIRECTORY = "logs"

# Absolute path
LOG_DIRECTORY = "/var/log/ddos-detector"

# Custom location
LOG_DIRECTORY = "/home/user/ddos-logs"
```

**File Size Management**:
```python
# Small files (frequent rotation)
LOG_MAX_BYTES = 1 * 1024 * 1024  # 1 MB

# Large files (less rotation)
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB

# Calculate total space:
# Total = LOG_MAX_BYTES * (LOG_BACKUP_COUNT + 1)
# Example: 5 MB * 6 = 30 MB max
```

**Backup Count**:
```python
# Minimal backups
LOG_BACKUP_COUNT = 2  # 15 MB total (5MB * 3)

# Standard backups
LOG_BACKUP_COUNT = 5  # 30 MB total

# Extended backups
LOG_BACKUP_COUNT = 10  # 55 MB total
```

### 6. System Configuration

#### Auto-blocking

```python
ENABLE_AUTO_BLOCKING = True  # Automatically block detected attackers
```

**Options**:
- `True`: Auto-block on detection (production)
- `False`: Detection only, no blocking (monitoring mode)

**Use Cases**:
```python
# Production: Full protection
ENABLE_AUTO_BLOCKING = True

# Testing: Monitor without blocking
ENABLE_AUTO_BLOCKING = False

# Hybrid: Log only mode for validation
ENABLE_AUTO_BLOCKING = False  # Test thresholds first
```

### 7. Testing Configuration

#### Loopback Detection

```python
ALLOW_LOOPBACK_DETECTION = True  # Detect 127.0.0.1 attacks
```

**Purpose**: Enable/disable detection of localhost traffic

**Settings**:
```python
# Development/Testing
ALLOW_LOOPBACK_DETECTION = True

# Production
ALLOW_LOOPBACK_DETECTION = False
```

**Why Disable in Production?**
- Prevents blocking local services
- Avoids false positives from internal apps
- Localhost traffic usually legitimate

#### Testing Mode

```python
TESTING_MODE = True  # Enable testing features
```

**Effects**:
- Allows loopback detection
- Reduces some safety checks
- More verbose logging
- Simulation features enabled

**Production vs. Testing**:
```python
# Production
TESTING_MODE = False
ALLOW_LOOPBACK_DETECTION = False
ENABLE_AUTO_BLOCKING = True

# Testing
TESTING_MODE = True
ALLOW_LOOPBACK_DETECTION = True
ENABLE_AUTO_BLOCKING = True  # or False
```

#### Attack Simulation

```python
DEFAULT_ATTACK_TARGET = "127.0.0.1"  # Target for attack simulator
```

**Usage**:
```python
# Localhost testing
DEFAULT_ATTACK_TARGET = "127.0.0.1"

# Real network testing
DEFAULT_ATTACK_TARGET = "192.168.1.100"

# Remote testing
DEFAULT_ATTACK_TARGET = "10.0.0.50"
```

## Configuration Profiles

### Development Profile

```python
# config/config.py - Development
NETWORK_INTERFACE = "lo"  # Loopback
PACKET_THRESHOLD = 20     # Sensitive
SYN_THRESHOLD = 10        # Sensitive
TIME_WINDOW = 5.0
ALLOW_LOOPBACK_DETECTION = True
TESTING_MODE = True
ENABLE_AUTO_BLOCKING = True
DASHBOARD_HOST = "127.0.0.1"
LOG_MAX_BYTES = 1 * 1024 * 1024  # 1 MB
```

### Testing Profile

```python
# config/config.py - Testing
NETWORK_INTERFACE = get_default_network_interface()
PACKET_THRESHOLD = 50
SYN_THRESHOLD = 25
TIME_WINDOW = 5.0
ALLOW_LOOPBACK_DETECTION = True
TESTING_MODE = True
ENABLE_AUTO_BLOCKING = True
DASHBOARD_HOST = "0.0.0.0"
LOG_MAX_BYTES = 5 * 1024 * 1024
```

### Production Profile

```python
# config/config.py - Production
NETWORK_INTERFACE = "eth0"  # Actual interface
PACKET_THRESHOLD = 200
SYN_THRESHOLD = 100
TIME_WINDOW = 5.0
ALLOW_LOOPBACK_DETECTION = False
TESTING_MODE = False
ENABLE_AUTO_BLOCKING = True
DASHBOARD_HOST = "127.0.0.1"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 10
```

## Environment-based Configuration

### Using Environment Variables

```python
import os

# Override from environment
NETWORK_INTERFACE = os.getenv('DDOS_NETWORK_INTERFACE', 'eth0')
PACKET_THRESHOLD = int(os.getenv('DDOS_PACKET_THRESHOLD', '100'))
DASHBOARD_PORT = int(os.getenv('DDOS_DASHBOARD_PORT', '5001'))
```

**Usage**:
```bash
# Set environment variables
export DDOS_NETWORK_INTERFACE="wlp1s0"
export DDOS_PACKET_THRESHOLD="150"
export DDOS_DASHBOARD_PORT="8080"

# Run with custom config
sudo -E python3 src/ddos_detector.py
```

### Configuration File Selection

```python
import os

ENV = os.getenv('ENVIRONMENT', 'development')

if ENV == 'production':
    from config.config_production import *
elif ENV == 'testing':
    from config.config_testing import *
else:
    from config.config_development import *
```

**Usage**:
```bash
# Run in production mode
export ENVIRONMENT=production
sudo python3 src/ddos_detector.py
```

## Advanced Configuration

### Dynamic Thresholds

```python
import datetime

def get_packet_threshold():
    """Adjust threshold based on time of day"""
    hour = datetime.datetime.now().hour
    
    if 9 <= hour <= 17:  # Business hours
        return 200
    else:  # Off-hours
        return 100

PACKET_THRESHOLD = get_packet_threshold()
```

### Network-based Configuration

```python
def get_config_for_network():
    """Different configs for different networks"""
    import socket
    hostname = socket.gethostname()
    
    if hostname.startswith('prod-'):
        return ProductionConfig()
    elif hostname.startswith('test-'):
        return TestingConfig()
    else:
        return DevelopmentConfig()
```

### Adaptive Thresholds

```python
class AdaptiveConfig:
    def __init__(self):
        self.baseline_traffic = self.measure_baseline()
        self.packet_threshold = self.baseline_traffic * 3
    
    def measure_baseline(self):
        """Measure normal traffic for 5 minutes"""
        # Implementation
        return 50  # packets/5sec average
```

## Configuration Validation

### Validation Function

```python
def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Check network interface
    if not NETWORK_INTERFACE:
        errors.append("NETWORK_INTERFACE not set")
    
    # Check thresholds
    if PACKET_THRESHOLD <= 0:
        errors.append("PACKET_THRESHOLD must be positive")
    
    if SYN_THRESHOLD <= 0:
        errors.append("SYN_THRESHOLD must be positive")
    
    # Check time window
    if TIME_WINDOW <= 0:
        errors.append("TIME_WINDOW must be positive")
    
    # Check port range
    if not (1 <= DASHBOARD_PORT <= 65535):
        errors.append("DASHBOARD_PORT must be 1-65535")
    
    if errors:
        raise ValueError("Configuration errors: " + ", ".join(errors))
    
    return True

# Run validation on import
validate_config()
```

### Type Checking

```python
from typing import Union

# Type hints for configuration
NETWORK_INTERFACE: str
PACKET_THRESHOLD: int
SYN_THRESHOLD: int
TIME_WINDOW: float
DASHBOARD_HOST: str
DASHBOARD_PORT: int
ENABLE_AUTO_BLOCKING: bool
```

## Troubleshooting

### Problem: Config Not Loading

**Symptoms**: Default values used instead of config.py

**Solutions**:
1. Check import path in code
2. Verify config file exists
3. Check for syntax errors: `python3 -m py_compile config/config.py`

### Problem: Interface Not Found

**Symptoms**: "Network interface not found" error

**Solutions**:
```bash
# List all interfaces
ip addr show

# Update config with correct interface name
nano config/config.py
```

### Problem: Thresholds Not Effective

**Symptoms**: Too many/too few false positives

**Solutions**:
1. Measure baseline traffic first
2. Adjust thresholds incrementally
3. Monitor logs for patterns
4. Use adaptive configuration

### Problem: Permission Denied on Logs

**Symptoms**: Cannot write to log directory

**Solutions**:
```bash
# Create log directory
mkdir -p logs

# Fix permissions
chmod 755 logs

# Or use different directory
# Edit config.py: LOG_DIRECTORY = "/tmp/ddos-logs"
```

## Best Practices

### 1. Documentation

```python
# config/config.py

# Network Configuration
# -------------------
# NETWORK_INTERFACE: The network interface to monitor
# Find yours with: ip addr show
NETWORK_INTERFACE = "wlp1s0"
```

### 2. Version Control

```bash
# .gitignore
config/config_local.py  # Local overrides
*.pyc
```

### 3. Backup Configuration

```bash
# Backup before changes
cp config/config.py config/config.py.backup

# Restore if needed
cp config/config.py.backup config/config.py
```

### 4. Testing Changes

```python
# Test new configuration
def test_config():
    """Test configuration before deploying"""
    assert PACKET_THRESHOLD > 0
    assert SYN_THRESHOLD > 0
    assert TIME_WINDOW > 0
    assert validate_config()
    print("✓ Configuration valid")

test_config()
```

## References

- [Network Interface Configuration](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
- [Python Configuration Best Practices](https://docs.python-guide.org/writing/structure/)
- [Environment Variables](https://12factor.net/config)
