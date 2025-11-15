# Real-Time DDoS Detection System

A Python-based real-time DDoS detection and mitigation system using traffic analysis, firewall integration, and comprehensive monitoring.

## Project Overview

This system monitors network traffic in real-time, detects potential DDoS attacks using threshold-based rules, automatically mitigates threats by blocking malicious IPs using iptables, and provides beautiful monitoring dashboards with comprehensive logging.

## ✨ Features

- **Real-time Traffic Monitoring**: Captures and analyzes network packets using Scapy
- **Attack Detection**: Identifies DDoS patterns (SYN floods, packet floods)
- **Automatic Mitigation**: Blocks malicious IPs using Linux firewall (iptables)
- **Comprehensive Logging**: File-based logging with rotation and JSON structured logs
- **Beautiful CLI Dashboard**: Real-time terminal UI with Rich library
- **Web Dashboard**: Modern web interface with live charts and statistics
- **RESTful API**: Access system data programmatically
- **Extensible Architecture**: Modular design for easy enhancement

## 🚀 Current Development Status

**Phases Completed: 4/5 (80%)** ✅

- ✅ **Phase 1**: Environment Setup & Foundations (100%)
- ✅ **Phase 2**: Traffic Capture Module (100%)
- ✅ **Phase 3**: Detection Engine (100%)
- ✅ **Phase 4**: Mitigation Module (100%)
- ⏭️ **Phase 5**: Testing & Simulation (Pending)
- ✅ **Phase 6**: Logging & Monitoring (100%)
- ⏭️ **Phase 7**: Project Finalization (Pending)
- ⏭️ **Phase 8**: ML Model Integration (Optional)

## Quick Start (Phase 1)

1. **Run the automated setup:**
   ```bash
   chmod +x setup_phase1.sh
   ./setup_phase1.sh
   ```

2. **Verify installation:**
   ```bash
   python3 --version
   pip3 --version
   hping3 --version
   ```

3. **Check your network interface:**
   ```bash
   ip a
   ```
   Note the interface name (e.g., `wlp1s0`, `enp0s3`, `eth0`) - you'll need this for Phase 2.

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

## 📋 System Requirements

- **Operating System**: Ubuntu 22.04 LTS (or any Linux distro)
- **Python**: 3.8 or higher
- **Root/Sudo Access**: Required for iptables and packet sniffing
- **Network Interface**: Active network interface for monitoring
- **RAM**: 2GB minimum, 4GB recommended
- **Disk Space**: 500MB for logs and system files

## 🔧 Installation

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

## 🎯 Quick Start

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

## 📊 Usage Examples

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

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Network Traffic                     │
└────────────────────┬────────────────────────────────┘
                     │
          ┌──────────▼──────────┐
          │   sniffer.py        │  ◄── Scapy Packet Capture
          │  (Traffic Capture)  │
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │ ddos_detector.py    │  ◄── Detection Engine
          │  (Main Controller)  │
          └──────┬───────┬──────┘
                 │       │
       ┌─────────┘       └─────────┐
       │                           │
┌──────▼────────┐         ┌────────▼──────┐
│ mitigator.py  │         │  logger.py    │
│ (IP Blocking) │         │  (Logging)    │
└───────────────┘         └────────┬──────┘
       │                           │
       │                  ┌────────▼──────────┐
       │                  │  dashboard.py     │
       │                  │  (Web Interface)  │
       │                  └───────────────────┘
       │
┌──────▼──────────┐
│    iptables     │  ◄── Linux Firewall
│  (OS Firewall)  │
└─────────────────┘
```

## 📁 Project Structure

```
Pydos/
├── src/                    # Source code
│   ├── ddos_detector.py    # Main detection engine
│   ├── sniffer.py          # Traffic capture module
│   ├── mitigator.py        # IP blocking (iptables)
│   ├── logger.py           # Comprehensive logging
│   ├── dashboard.py        # Web dashboard (Flask)
│   └── utils.py            # Utility functions
├── config/                 # Configuration
│   └── config.py           # System configuration
├── scripts/                # Utility scripts
│   ├── simulate_attack.py  # Attack simulator
│   └── unblock_all.sh      # Unblock all IPs
├── docs/                   # Documentation
│   ├── Project_Report.md   # Academic report
│   ├── Testing_Guide.md    # Testing procedures
│   ├── WINDOWS_TESTING_GUIDE.md  # Windows guide
│   ├── PROJECT_STRUCTURE.md      # This structure
│   └── PHASE*.md           # Phase documentation
├── tests/                  # Test files
│   └── README.md           # Test guide
├── logs/                   # Log files (auto-generated)
│   ├── ddos_events.log     # All events
│   ├── ddos_attacks.log    # Attack logs
│   ├── ddos_system.log     # System logs
│   └── ddos_events.json    # JSON logs
├── requirements.txt        # Dependencies
└── README.md              # This file
```

See [docs/PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md) for detailed structure explanation.

## 🔍 Detection Logic

### Threshold-Based Detection

The system uses two primary thresholds:

1. **Packet Threshold**: `100 packets/5 seconds` per source IP
   - Detects general packet flooding attacks

2. **SYN Threshold**: `50 SYN packets/5 seconds` per source IP
   - Detects SYN flood attacks specifically

### Time Windows

- **Tracking Window**: 5 seconds (rolling)
- **Reset Interval**: Every 5 seconds
- **Dashboard Update**: Every 1 second

### Automatic Mitigation

When an attack is detected:
1. Source IP is logged to `ddos_attacks.log`
2. IP is blocked using iptables DROP rule
3. Event is recorded in JSON format
4. Dashboard is updated with blocked IP

## 🎨 Dashboard Features

### CLI Dashboard (Rich)

- **Live Traffic Table**: Real-time packet counts per IP
- **Color-Coded Status**: 
  - 🟢 Green: Normal traffic
  - 🟡 Yellow: Warning (approaching threshold)
  - 🔴 Red: Attack detected
- **Summary Panel**: Total packets, unique IPs, blocked IPs
- **Auto-refresh**: Updates every second

### Web Dashboard (Flask)

- **Modern UI**: Gradient design with dark theme
- **Real-time Charts**: Live traffic visualization with Chart.js
- **Statistics Cards**: Active IPs, blocked IPs, total packets
- **Recent Attacks Table**: Last 10 detected attacks
- **API Endpoints**: RESTful access to system data
- **Auto-refresh**: Updates every 2 seconds

## 🔌 API Reference

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

## 🧪 Testing

### Manual Testing

```bash
# Start the detector
sudo venv/bin/python3 ddos_detector.py

# In another terminal, simulate SYN flood
sudo venv/bin/python3 scripts/simulate_attack.py --target <your-ip> --type syn --count 200

# Monitor logs
tail -f logs/ddos_attacks.log
```

### Using hping3

```bash
# SYN flood test
sudo hping3 -S -p 80 --flood <target-ip>

# UDP flood test
sudo hping3 --udp -p 53 --flood <target-ip>
```

## 🛡️ Security Considerations

⚠️ **Important Security Notes**:

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

## 🐛 Troubleshooting

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

## 📚 Documentation

Detailed documentation for each phase:

- [Phase 1: Environment Setup](docs/PHASE1_CHECKLIST.md)
- [Phase 2: Traffic Capture](docs/PHASE2_COMPLETE.md)
- [Phase 3: Detection Engine](docs/PHASE3_COMPLETE.md)
- [Phase 4: Mitigation Module](docs/PHASE4_COMPLETE.md)
- [Phase 6: Logging & Monitoring](docs/PHASE6_COMPLETE.md)

## 🚧 Future Enhancements (Phase 8)

- [ ] Machine Learning model integration
- [ ] Support for more attack types (HTTP floods, DNS amplification)
- [ ] Database integration for historical analysis
- [ ] Alert notifications (email, SMS, Slack)
- [ ] Distributed deployment support
- [ ] Advanced anomaly detection algorithms

## 👥 Contributing

This is an academic project for BSIT degree. For contributions:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is developed as part of an academic curriculum.

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **Rich**: Beautiful terminal formatting
- **Flask**: Lightweight web framework
- **Chart.js**: Beautiful charts and graphs

## 📞 Contact

For questions or issues, please open an issue on GitHub.

---

**⚠️ Disclaimer**: This tool is for educational and authorized testing purposes only. Unauthorized network monitoring or DDoS attacks are illegal. Always obtain proper authorization before testing on any network.

## Development Phases

1. **Phase 1**: Environment Setup & Foundations (Current)
2. **Phase 2**: Traffic Capture Module
3. **Phase 3**: Detection Engine
4. **Phase 4**: Mitigation Module
5. **Phase 5**: Testing & Simulation
6. **Phase 6**: Logging & Monitoring
7. **Phase 7**: Project Finalization
8. **Phase 8**: ML Model Integration (Optional)

## Usage (Coming in Phase 2+)

```bash
# Run the DDoS detector (requires sudo)
sudo python3 main.py

# Run attack simulation (for testing)
sudo python3 scripts/simulate_attack.py

# View logs
cat ddos_events.log
```

## Network Interface

Your active network interface: **wlp1s0**
- IP: 192.168.10.8/24
- Type: Wireless

## Safety & Ethics

⚠️ **Important**: This tool is for educational purposes and authorized security testing only.
- Only test on networks you own or have explicit permission to test
- Never use attack simulation tools on production systems
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## License

Educational Project - Please use responsibly

## Support

For issues or questions, refer to:
- `implementation.md` - Complete step-by-step guide
- `PHASE1_CHECKLIST.md` - Phase 1 specific help
