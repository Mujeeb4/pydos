<p align="center">
  <img src="pydos_logo.png" alt="PyDoS Logo" width="400">
</p>

# Enhanced Real-Time DDoS Detection System v2.0

A Python-based real-time DDoS detection and mitigation system with **10 advanced detection capabilities** and **21 attack simulation types**. Monitors network traffic in real-time, detects sophisticated DDoS attacks using multi-layered analysis, automatically mitigates threats, and provides comprehensive monitoring dashboards.

## 🎯 Key Highlights

- **10 Advanced Detection Features**: TCP flags, packet sizes, ICMP types, port analysis, TTL spoofing, fragments, connection tracking, burst detection, protocol anomalies, application layer inspection
- **21 Attack Simulation Types**: Complete testing suite for all detection capabilities
- **Multi-Vector Detection**: Simultaneous SYN+UDP+ICMP+ACK+HTTP flood detection
- **Behavioral Analysis**: Detects low-and-slow attacks, IP spikes, spoofing patterns
- **Enhanced CLI Dashboard**: Shows TCP flags, port scans, burst indicators
- **Comprehensive Logging**: 21 attack types logged with detailed metadata
- **Production Ready**: Optimized for high-throughput networks (10,000+ pps)

## ⚡ Enhanced Features

- **Real-time Traffic Monitoring**: Deep packet inspection with Scapy
- **Advanced Attack Detection**: 21 different attack patterns identified
- **Automatic Mitigation**: Intelligent IP blocking with iptables
- **Comprehensive Logging**: Structured JSON logs with attack metadata
- **Beautiful CLI Dashboard**: Enhanced real-time terminal UI
- **Web Dashboard**: Modern interface with live attack visualization
- **RESTful API**: Programmatic access to detection data
- **Modular Architecture**: 10 pluggable detection features
- **Attack Simulation Suite**: Test all 21 attack types
- **Performance Optimized**: Minimal CPU impact (<10% at 10Kpps)

## Current Development Status

**Version 2.0 - FULLY ENHANCED (100% Complete)**

- ✅ **Phase 1**: Environment Setup & Foundations (100%)
- ✅ **Phase 2**: Traffic Capture Module (100%)
- ✅ **Phase 3**: Enhanced Detection Engine v2.0 (100%) - **10 Advanced Features**
- ✅ **Phase 4**: Mitigation Module (100%)
- ✅ **Phase 5**: Enhanced Testing & Simulation (100%) - **21 Attack Types**
- ✅ **Phase 6**: Advanced Logging & Monitoring (100%)
- ✅ **Phase 7**: Project Finalization (100%)
- 🔄 **Phase 8**: ML Model Integration (Optional - Future)

## 🚀 Quick Start

### 1. Automated Setup
```bash
chmod +x setup_phase1.sh
./setup_phase1.sh
```

### 2. Launch Complete System
```bash
# Run the interactive menu (recommended)
sudo python3 main.py

# Select option 3: "Launch Complete Environment"
# This starts detector + dashboard + lets you choose from 21 attack types
```

### 3. Manual Launch (Advanced)
```bash
# Terminal 1: Enhanced detector with all 10 features
sudo python3 src/detector.py

# Terminal 2: Web dashboard
python3 src/dashboard.py

# Terminal 3: Test with any of 21 attack types
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type xmas
```

## System Requirements

- Linux OS (Ubuntu 22.04 LTS recommended)
- Python 3.8+
- Root/sudo privileges (for packet capture and firewall management)
- Network interface with traffic to monitor

## Dependencies

All dependencies are listed in `requirements.txt`:
- scapy - Packet sniffing and manipulation
- pandas - Data processing
- rich - Terminal UI
- scikit-learn - ML model (optional, Phase 8)
- joblib - Model persistence
- flask - Web dashboard (optional, Phase 6)

## System Requirements

- **Operating System**: Ubuntu 22.04 LTS (or any Linux distro)
- **Python**: 3.8 or higher
- **Root/Sudo Access**: Required for iptables and packet sniffing
- **Network Interface**: Active network interface for monitoring
- **RAM**: 2GB minimum, 4GB recommended
- **Disk Space**: 500MB for logs and system files

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/pydos.git
cd pydos
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python3 ddos_detector.py --help
```

## Quick Start

### Basic Detection (CLI Dashboard)

```bash
# Must run with sudo for packet capture
# Run from project root directory
sudo venv/bin/python3 src/ddos_detector.py
```

### With Web Dashboard

```bash
# Terminal 1: Run detection engine
sudo venv/bin/python3 src/ddos_detector.py

# Terminal 2: Start web dashboard
python3 src/dashboard.py
```

Then open http://localhost:5001 in your browser.

### Simulate an Attack (Testing)

```bash
# In another terminal (requires sudo)
sudo venv/bin/python3 scripts/simulate_attack.py --target 192.168.1.100 --type syn --count 200
```

## Usage Examples

### Monitor Specific Interface

```bash
# Edit config file
nano config/config.py
# Update NETWORK_INTERFACE = "eth0"

# Then run
sudo venv/bin/python3 src/ddos_detector.py
```

### Custom Thresholds

Edit `config/config.py`:
```python
PACKET_THRESHOLD = 150  # Packets per 5 seconds
SYN_THRESHOLD = 75      # SYN packets per 5 seconds
```

### View Logs

```bash
# Real-time log monitoring
tail -f logs/ddos_events.log

# Attack logs
tail -f logs/ddos_attacks.log

# System logs
tail -f logs/ddos_system.log

# JSON structured logs
cat logs/ddos_events.json | jq
```

### Unblock All IPs

```bash
sudo bash scripts/unblock_all.sh
```

## 🏗️ Enhanced Architecture v2.0

```
┌─────────────────────────────────────────────────────┐
│                  Network Traffic                     │
└────────────────────┬────────────────────────────────┘
                     │
          ┌──────────▼──────────┐
          │     sniffer.py      │  ◄── Scapy Deep Packet Inspection
          │  (Traffic Capture)  │
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │   detector.py       │  ◄── ENHANCED Detection Engine v2.0
          │ 10 Detection Features│      ┌─────────────────────────────────┐
          └──────┬───────┬──────┘      │ 1. TCP Flag Analysis          │
                 │       │             │ 2. Packet Size Analysis      │
       ┌─────────┘       └─────────┐   │ 3. ICMP Type Analysis        │
       │                           │   │ 4. Port Analysis             │
┌──────▼────────┐         ┌────────▼──────┐ │ 5. TTL Anomaly Detection  │
│ mitigator.py  │         │  logger.py    │ │ 6. Fragment Detection      │
│ (IP Blocking) │         │  (Enhanced    │ │ 7. Connection Tracking     │
└───────────────┘         │   Logging)    │ │ 8. Burst Detection         │
       │                  └────────┬──────┘ │ 9. Protocol Anomaly        │
       │                           │        │ 10. App Layer Inspection   │
       │                  ┌────────▼──────────┐ └───────────────────────────┘
       │                  │  dashboard.py     │
       │                  │  (Enhanced Web UI)│
       │                  └───────────────────┘
       │
┌──────▼──────────┐         ┌──────────────────┐
│    iptables     │         │   simulate_*.py  │ ◄── 21 Attack Types
│  (OS Firewall)  │         │  (Test Suite)    │
└─────────────────┘         └──────────────────┘
```

### Enhanced Detection Pipeline

```
Packet Arrives → Deep Analysis → 10 Detection Checks → Alert Generation → Mitigation
       ↓              ↓              ↓                    ↓              ↓
   Scapy Capture  TCP Flags     Threshold Check      Log Event      IP Block
   IP/TCP/UDP     Size/Type      Anomaly Detect     JSON/CLI       iptables DROP
   Fragment Info  Port Scan      Pattern Match       Dashboard       Auto-Unblock
   TTL Values     Burst Detect   Protocol Ratio     Web UI          60min timeout
   App Payload    Connection     Behavioral         REST API
                 State Track    Analysis
```

## 📁 Enhanced Project Structure v2.0

```
Pydos/
├── src/                    # Enhanced Source Code
│   ├── detector.py         # ENHANCED Detection Engine (10 features)
│   ├── sniffer.py          # Traffic capture module
│   ├── mitigator.py        # IP blocking (iptables)
│   ├── logger.py           # Comprehensive logging
│   ├── dashboard.py        # Web dashboard (Flask)
│   └── utils.py            # Utility functions
├── config/                 # Enhanced Configuration
│   └── config.py           # 100+ configuration options (10 features)
├── scripts/                # Enhanced Testing Suite
│   ├── simulate_ddos.py    # 21 Attack Types (Distributed)
│   ├── simulate_attack.py  # 16 Attack Types (Single-Source)
│   └── unblock_all.sh      # Unblock all IPs
├── docs/                   # Comprehensive Documentation
│   ├── DETECTION_ENGINE.md # 10 Detection Features Guide
│   ├── ATTACK_SIMULATION.md# 21 Attack Types Reference
│   ├── SECURITY.md         # Security considerations
│   ├── DEPLOYMENT_GUIDE.md # Production deployment
│   └── [Previous docs...]  # All original documentation
├── tests/                  # Test Suite
│   └── README.md           # Testing guide
├── logs/                   # Enhanced Log Files
│   ├── ddos_events.log     # All events (enhanced format)
│   ├── ddos_attacks.log    # 21 Attack types logged
│   ├── ddos_system.log     # System operations
│   └── ddos_events.json    # Structured JSON logs
├── requirements.txt        # Dependencies (unchanged)
├── main.py                 # Interactive Menu (22 options)
└── README.md              # This enhanced README
```

### New Files & Features:
- **detector.py**: 10 advanced detection features (replaces ddos_detector.py)
- **simulate_ddos.py**: 21 distributed attack types
- **simulate_attack.py**: 16 single-source attack types (enhanced)
- **main.py**: Interactive menu with all attack options
- **ATTACK_SIMULATION.md**: Complete attack simulation guide
- **100+ config options**: Fine-tuned thresholds for all features

## 🎯 Enhanced Detection Logic v2.0

### 10 Advanced Detection Features

The system now uses **multi-layered threshold analysis** with 10 specialized detection engines:

#### 1. TCP Flag Analysis
- **ACK Flood**: `ACK_THRESHOLD = 50` packets/5s per IP
- **FIN Flood**: `FIN_THRESHOLD = 30` packets/5s per IP
- **RST Flood**: `RST_THRESHOLD = 30` packets/5s per IP
- **XMAS Scan**: `XMAS_THRESHOLD = 5` (immediate alert - always malicious)
- **NULL Scan**: `NULL_THRESHOLD = 5` (immediate alert - always malicious)
- **Invalid Flags**: `INVALID_FLAGS_THRESHOLD = 3` (impossible combinations)

#### 2. Packet Size Analysis
- **Small Packet Flood**: `SMALL_PACKET_THRESHOLD = 80` (<64 bytes)
- **Amplification Attack**: `LARGE_PACKET_THRESHOLD = 50` (>1000 bytes)
- **Bandwidth Monitoring**: `BANDWIDTH_THRESHOLD_MBPS = 10`

#### 3. ICMP Type Analysis
- **Ping Flood**: `ICMP_ECHO_REQUEST_THRESHOLD = 30`
- **Smurf Attack**: Detects ICMP echo replies (type 0)
- **ICMP Unreachable**: `ICMP_UNREACHABLE_THRESHOLD = 20`

#### 4. Port Analysis
- **Port Scan Detection**: `PORT_SCAN_THRESHOLD = 15` unique ports
- **Service Flood**: `SERVICE_PORT_THRESHOLD = 100` to single port
- **Monitored Ports**: HTTP, HTTPS, SSH, DNS, MySQL, Redis, etc.

#### 5. TTL Anomaly Detection
- **TTL Variance**: `TTL_VARIANCE_THRESHOLD = 30`
- **Low TTL**: `LOW_TTL_THRESHOLD = 5` (suspicious)
- **Spoofed Traffic**: Detects highly varied TTL patterns

#### 6. Fragment Attack Detection
- **Fragment Flood**: `FRAGMENT_THRESHOLD = 20` fragments/5s per IP
- **Tiny Fragments**: `TINY_FRAGMENT_SIZE = 60` bytes
- **Aggregate Fragments**: `AGGREGATE_FRAGMENT_THRESHOLD = 200`

#### 7. Connection State Tracking
- **Half-Open Ratio**: `HALF_OPEN_RATIO_THRESHOLD = 0.8`
- **SYN Without ACK**: `SYN_WITHOUT_ACK_THRESHOLD = 40`
- **Completion Monitoring**: Tracks TCP handshake completion

#### 8. Burst Detection
- **Micro-Burst Window**: `BURST_WINDOW_MS = 100` milliseconds
- **Burst Threshold**: `BURST_PACKET_THRESHOLD = 20` packets
- **Max Bursts**: `BURST_COUNT_THRESHOLD = 3` per window

#### 9. Protocol Distribution Anomaly
- **Baseline Ratios**: TCP:70%, UDP:20%, ICMP:5%, Other:5%
- **Deviation Threshold**: `PROTOCOL_DEVIATION_THRESHOLD = 0.3`
- **Traffic Pattern Analysis**: Detects unusual protocol mixes

#### 10. Application Layer Inspection
- **HTTP Flood**: `HTTP_REQUEST_THRESHOLD = 50` requests/5s
- **DNS Flood**: `DNS_QUERY_THRESHOLD = 30` queries/5s
- **Amplification Detection**: Large DNS responses flagged

### Enhanced Threshold Categories

#### Per-IP DoS Thresholds (Individual Attackers)
```python
PACKET_THRESHOLD = 100      # General packet flood
SYN_THRESHOLD = 50          # SYN flood
UDP_THRESHOLD = 50          # UDP flood
ICMP_THRESHOLD = 50         # ICMP flood
# + 10 additional thresholds above
```

#### Aggregate DDoS Thresholds (Distributed Attacks)
```python
AGGREGATE_PACKET_THRESHOLD = 1000   # Total from all IPs
AGGREGATE_SYN_THRESHOLD = 500       # Total SYN packets
AGGREGATE_UDP_THRESHOLD = 500       # Total UDP packets
AGGREGATE_ICMP_THRESHOLD = 300      # Total ICMP packets
# + Enhanced aggregate thresholds
```

### Time Windows & Performance

- **Primary Window**: 5 seconds (rolling detection)
- **Micro-Burst Window**: 100ms (burst detection)
- **Reset Interval**: Every 5 seconds
- **Dashboard Update**: Every 1-2 seconds
- **Max Throughput**: 10,000+ packets/second
- **CPU Usage**: <10% at full load

### Intelligent Alert Severity

- **LOW**: Minor threshold exceedance
- **MEDIUM**: Moderate attack patterns
- **HIGH**: Significant traffic anomalies
- **CRITICAL**: Malformed packets, spoofing indicators, impossible flag combinations

### Enhanced Automatic Mitigation

When attacks are detected:
1. **Immediate Logging**: Attack details to structured logs
2. **IP Blocking**: iptables DROP rules with auto-expiry (60 min)
3. **Alert Classification**: Severity-based response
4. **Dashboard Updates**: Real-time visualization
5. **JSON Export**: For external monitoring systems

## 📊 Enhanced Dashboard Features v2.0

### Enhanced CLI Dashboard (Rich)

- **Advanced Traffic Table**: Shows 8 columns of detailed metrics
  - IP Address, Packets, SYN, ACK, UDP, Ports Scanned, Flag Indicators, Status
- **Enhanced Status Indicators**:
  - 🟢 **Green**: Normal traffic
  - 🟡 **Yellow**: Warning (near threshold)
  - 🔴 **Red**: Attack detected
  - 💀 **Black**: Malformed/critical packets (XMAS, NULL, Invalid flags)
- **Flag Indicators**: X=XMAS, N=NULL, !=Invalid flags, B=Burst detected
- **Port Scan Display**: Shows unique ports hit per IP
- **Advanced Summary Panels**: 4 panels showing system status, thresholds, statistics
- **Real-time Updates**: Enhanced refresh every 1-2 seconds

### Enhanced Web Dashboard (Flask)

- **Modern Dark UI**: Professional gradient design
- **Live Attack Visualization**: Real-time charts with enhanced metrics
- **21 Attack Type Tracking**: Individual counters for all attack types
- **Advanced Statistics**: Malformed packets, port scans, spoofing detections
- **Enhanced Attack Log**: Shows all 21 attack types with detailed metadata
- **API Endpoints**: RESTful access with 10 new data endpoints
- **Performance Metrics**: Bandwidth monitoring, CPU usage, detection latency

### New Dashboard Features

#### CLI Enhancements:
- **TCP Flag Columns**: SYN, ACK counters in traffic table
- **Port Analysis**: Shows unique ports scanned per IP
- **Malformation Indicators**: Special symbols for XMAS/NULL attacks
- **Burst Detection**: 'B' indicator for micro-burst patterns
- **Configuration Panel**: Shows all 10 enabled detection features

#### Web Dashboard Additions:
- **Attack Type Breakdown**: Pie chart of detected attack types
- **Bandwidth Monitoring**: Real-time Mbps tracking
- **Feature Status**: Shows which of 10 detection features are active
- **Advanced Filtering**: Filter logs by attack type, severity, time
- **Export Capabilities**: JSON/CSV export of detection data

## API Reference

### Health Check
```bash
GET /health
```

### Get Statistics
```bash
GET /api/stats
Response: {
  "total_packets": 1234,
  "unique_ips": 45,
  "blocked_ips": 2,
  "timestamp": "2024-01-15 10:30:45"
}
```

### Get Recent Logs
```bash
GET /api/logs?limit=50
Response: {
  "logs": [
    {
      "timestamp": "2024-01-15 10:30:45",
      "level": "WARNING",
      "message": "Attack detected from 192.168.1.100"
    }
  ]
}
```

## 🧪 Enhanced Testing Suite v2.0

### Interactive Testing Menu (Recommended)

```bash
# Launch complete testing environment
sudo python3 main.py

# Select option 3: "Launch Complete Environment"
# Choose from 22 attack types including "Run All Attacks"
```

### Comprehensive Attack Testing

#### Single-Source DoS Testing (16 Types)
```bash
# Enhanced single-IP attack simulator
sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --type all

# Test specific enhanced attacks
sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --type xmas
sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --type portscan
sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --type burst
```

#### Distributed DDoS Testing (21 Types)
```bash
# Enhanced distributed attack simulator
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type multi

# Test advanced detection features
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type ttlspoof
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type fragment
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type amplify

# Run ALL 21 attack types sequentially
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type all
```

### Complete Testing Workflow

```bash
# Terminal 1: Enhanced detector with all 10 features
sudo python3 src/detector.py

# Terminal 2: Web dashboard
python3 src/dashboard.py

# Terminal 3: Attack simulation menu
sudo python3 main.py
# Select option 4, then choose from 22 attack types

# Terminal 4: Monitor logs in real-time
tail -f logs/ddos_attacks.log

# Terminal 5: Monitor JSON structured logs
watch -n 1 'cat logs/ddos_events.json | jq ".event_type" | sort | uniq -c'
```

### Expected Detection Results

| Attack Command | Expected Alert | Feature Tested | Severity |
|----------------|----------------|----------------|----------|
| `--type xmas` | `MALFORMED_TCP` | TCP Flag Analysis | CRITICAL |
| `--type smallpkt` | `SMALL_PACKET_FLOOD` | Packet Size Analysis | HIGH |
| `--type portscan` | `PORT_SCAN` | Port Analysis | MEDIUM |
| `--type ttlspoof` | `SPOOFED_TRAFFIC_TTL_VARIANCE` | TTL Analysis | HIGH |
| `--type burst` | `BURST_ATTACK` | Burst Detection | HIGH |
| `--type http` | `HTTP_FLOOD` | App Layer Inspection | MEDIUM |

### Legacy hping3 Testing (Still Supported)

```bash
# SYN flood test
sudo hping3 -S -p 80 --flood <target-ip>

# UDP flood test
sudo hping3 --udp -p 53 --flood <target-ip>
```

## 🛡️ Security Considerations

**Important Security Notes**:

1. **Root Access**: System requires root/sudo for:
   - Packet capture (Scapy)
   - iptables firewall modifications

2. **False Positives**: Adjust thresholds based on your network:
   - High-traffic networks may need higher thresholds
   - Test thoroughly before production use

3. **Legitimate Traffic**: Be careful not to block:
   - NAT gateways
   - Load balancers
   - Legitimate high-volume clients

4. **Firewall Persistence**: iptables rules are NOT persistent by default
   - Use `iptables-save` for persistence
   - Consider impact on existing firewall rules

## Troubleshooting

### Permission Denied Error

```bash
# Solution: Run with sudo
sudo venv/bin/python3 src/ddos_detector.py
```

### Module Not Found Error

```bash
# Solution: Activate venv and reinstall
source venv/bin/activate
pip install -r requirements.txt
```

### No Packets Captured

```bash
# Solution: Check network interface
ip addr show          # List interfaces

# Update config file
nano config/config.py  # Set correct NETWORK_INTERFACE
```

### Web Dashboard Not Accessible

```bash
# Solution: Check if Flask is running
ps aux | grep dashboard.py

# Restart dashboard
python3 src/dashboard.py --port 5001
```

### Running on Windows?

See [docs/WINDOWS_TESTING_GUIDE.md](docs/WINDOWS_TESTING_GUIDE.md) for Windows-specific instructions and VirtualBox setup guide.

## 📚 Enhanced Documentation v2.0

### Core Documentation
- **[Detection Engine v2.0](docs/DETECTION_ENGINE.md)**: Complete guide to 10 advanced detection features
- **[Attack Simulation Guide](docs/ATTACK_SIMULATION.md)**: Reference for all 21 attack types
- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)**: Production deployment instructions
- **[Security Considerations](docs/SECURITY.md)**: Security analysis and best practices

### Original Phase Documentation
- [Phase 1: Environment Setup](docs/PHASE1_CHECKLIST.md)
- [Phase 2: Traffic Capture](docs/PHASE2_COMPLETE.md)
- [Phase 3: Detection Engine](docs/PHASE3_COMPLETE.md)
- [Phase 4: Mitigation Module](docs/PHASE4_COMPLETE.md)
- [Phase 6: Logging & Monitoring](docs/PHASE6_COMPLETE.md)

## Future Enhancements (Phase 8)

- [ ] Machine Learning model integration
- [ ] Support for more attack types (HTTP floods, DNS amplification)
- [ ] Database integration for historical analysis
- [ ] Alert notifications (email, SMS, Slack)
- [ ] Distributed deployment support
- [ ] Advanced anomaly detection algorithms

## Contributing

This is an academic project for BSIT degree. For contributions:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is developed as part of an academic curriculum.

## Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **Rich**: Beautiful terminal formatting
- **Flask**: Lightweight web framework
- **Chart.js**: Beautiful charts and graphs

## Contact

For questions or issues, please open an issue on GitHub.

---

**Disclaimer**: This tool is for educational and authorized testing purposes only. Unauthorized network monitoring or DDoS attacks are illegal. Always obtain proper authorization before testing on any network.

## Development Phases

1. **Phase 1**: Environment Setup & Foundations (Current)
2. **Phase 2**: Traffic Capture Module
3. **Phase 3**: Detection Engine
4. **Phase 4**: Mitigation Module
5. **Phase 5**: Testing & Simulation
6. **Phase 6**: Logging & Monitoring
7. **Phase 7**: Project Finalization
8. **Phase 8**: ML Model Integration (Optional)

## 🚀 Enhanced Usage v2.0

### Interactive Main Menu (Recommended)

```bash
# Launch the interactive menu with all options
sudo python3 main.py

# Available options:
# [1] Start DDoS Detector (CLI Dashboard)
# [2] Start Web Dashboard
# [3] Launch Complete Environment (Detector + Dashboard + Attack Testing)
# [4] Simulate DDoS Attack (22 attack types)
# [5] View System Configuration (10 features shown)
# [6] View Logs
# [7] Clean Firewall Rules
# [8] Check System Status
# [9] Run Tests
# [0] Exit
```

### Complete Testing Environment (Option 3)

```bash
sudo python3 main.py
# Select option 3
# Choose DoS (16 types) or DDoS (22 types)
# Select any attack type or "Run All Attacks"
# Everything launches automatically in separate terminals
```

### Manual Launch Options

```bash
# Enhanced detector with all 10 features
sudo python3 src/detector.py

# Web dashboard with enhanced attack visualization
python3 src/dashboard.py

# Test individual attack types
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type xmas
sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --type portscan

# View enhanced logs
tail -f logs/ddos_attacks.log
cat logs/ddos_events.json | jq
```

## Network Interface

Your active network interface: **wlp1s0**
- IP: 192.168.10.8/24
- Type: Wireless

## Safety & Ethics

**Important**: This tool is for educational purposes and authorized security testing only.
- Only test on networks you own or have explicit permission to test
- Never use attack simulation tools on production systems
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Support

For issues or questions, refer to:
- `implementation.md` - Complete step-by-step guide
- `PHASE1_CHECKLIST.md` - Phase 1 specific help
