# Deployment Guide

## Overview

This guide covers deploying the DDoS Detection System in various environments, from development to production.

## System Requirements

### Hardware Requirements

**Minimum**:
- CPU: 1 core, 1.5 GHz
- RAM: 2 GB
- Disk: 2 GB free space
- Network: 100 Mbps

**Recommended**:
- CPU: 2+ cores, 2.5 GHz
- RAM: 4 GB
- Disk: 10 GB free space (for logs)
- Network: 1 Gbps

**Production**:
- CPU: 4+ cores, 3.0 GHz
- RAM: 8 GB
- Disk: 50 GB free space
- Network: 10 Gbps

### Software Requirements

**Operating System**:
- ✅ Ubuntu 22.04 LTS (recommended)
- ✅ Ubuntu 20.04 LTS
- ✅ Debian 11/12
- ✅ CentOS 8/9
- ✅ Red Hat Enterprise Linux 8/9
- ❌ Windows (limited - no iptables)
- ❌ macOS (limited - no iptables)

**Python**:
- Python 3.8 or higher
- pip 20.0 or higher
- venv module

**System Packages**:
- iptables (firewall)
- libpcap (packet capture)
- git (version control)

## Installation

### 1. System Preparation

#### Update System

```bash
# Ubuntu/Debian
sudo apt update
sudo apt upgrade -y

# CentOS/RHEL
sudo yum update -y
```

#### Install Dependencies

```bash
# Ubuntu/Debian
sudo apt install -y python3 python3-pip python3-venv \
    iptables libpcap-dev git build-essential

# CentOS/RHEL
sudo yum install -y python3 python3-pip python3-virtualenv \
    iptables libpcap-devel git gcc
```

### 2. Clone Repository

```bash
# Clone from GitHub
git clone https://github.com/yourusername/pydos.git
cd pydos

# Or download and extract
wget https://github.com/yourusername/pydos/archive/main.zip
unzip main.zip
cd pydos-main
```

### 3. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# Verify activation
which python3
# Should show: /path/to/pydos/venv/bin/python3
```

### 4. Install Python Dependencies

```bash
# Install requirements
pip install -r requirements.txt

# Verify installation
pip list

# Should see:
# - scapy
# - pandas
# - rich
# - flask
# - scikit-learn
# - joblib
```

### 5. Configure System

#### Network Interface

```bash
# Find your network interface
ip addr show

# Edit configuration
nano config/config.py

# Update NETWORK_INTERFACE
NETWORK_INTERFACE = "eth0"  # Your interface name
```

#### Set Thresholds

```python
# config/config.py

# Adjust based on your network
PACKET_THRESHOLD = 100  # Packets per 5 seconds
SYN_THRESHOLD = 50      # SYN packets per 5 seconds
```

### 6. Test Installation

```bash
# Test detection engine (requires sudo)
sudo venv/bin/python3 src/ddos_detector.py

# In another terminal, test attack simulation
sudo venv/bin/python3 scripts/simulate_attack.py \
    --target 127.0.0.1 \
    --type syn \
    --count 100

# Check logs
tail -f logs/ddos_events.log
```

## Deployment Modes

### Development Deployment

**Purpose**: Testing and development

**Configuration**:
```python
# config/config.py
TESTING_MODE = True
ALLOW_LOOPBACK_DETECTION = True
PACKET_THRESHOLD = 20
ENABLE_AUTO_BLOCKING = True
DASHBOARD_HOST = "127.0.0.1"
```

**Running**:
```bash
# Activate virtual environment
source venv/bin/activate

# Run detector
sudo venv/bin/python3 src/ddos_detector.py

# Run web dashboard (separate terminal)
python3 src/dashboard.py
```

### Standalone Deployment

**Purpose**: Single server monitoring

**Configuration**:
```python
# config/config.py
TESTING_MODE = False
ALLOW_LOOPBACK_DETECTION = False
PACKET_THRESHOLD = 150
ENABLE_AUTO_BLOCKING = True
DASHBOARD_HOST = "0.0.0.0"
LOG_DIRECTORY = "/var/log/ddos-detector"
```

**Setup**:
```bash
# Create log directory
sudo mkdir -p /var/log/ddos-detector
sudo chown $USER:$USER /var/log/ddos-detector

# Create systemd service
sudo nano /etc/systemd/system/ddos-detector.service
```

**Service File** (`/etc/systemd/system/ddos-detector.service`):
```ini
[Unit]
Description=DDoS Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/pydos
Environment="PATH=/opt/pydos/venv/bin"
ExecStart=/opt/pydos/venv/bin/python3 /opt/pydos/src/ddos_detector.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and Start**:
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable ddos-detector.service

# Start service
sudo systemctl start ddos-detector.service

# Check status
sudo systemctl status ddos-detector.service

# View logs
sudo journalctl -u ddos-detector.service -f
```

### Production Deployment

**Purpose**: Production environment

**Configuration**:
```python
# config/config.py
TESTING_MODE = False
ALLOW_LOOPBACK_DETECTION = False
PACKET_THRESHOLD = 200
SYN_THRESHOLD = 100
ENABLE_AUTO_BLOCKING = True
DASHBOARD_HOST = "127.0.0.1"  # Restrict dashboard
LOG_DIRECTORY = "/var/log/ddos-detector"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 10
```

**Hardening**:
```bash
# Create dedicated user
sudo useradd -r -s /bin/false ddos-detector

# Set ownership
sudo chown -R ddos-detector:ddos-detector /opt/pydos

# Set permissions
sudo chmod 750 /opt/pydos
sudo chmod 640 /opt/pydos/config/config.py
```

**Advanced Systemd Service**:
```ini
[Unit]
Description=DDoS Detection System
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=/opt/pydos
Environment="PATH=/opt/pydos/venv/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=/opt/pydos/venv/bin/python3 /opt/pydos/src/ddos_detector.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/ddos-detector

[Install]
WantedBy=multi-user.target
```

## Monitoring and Maintenance

### Log Rotation

#### Using logrotate

```bash
# Create logrotate config
sudo nano /etc/logrotate.d/ddos-detector
```

**Logrotate Configuration**:
```
/var/log/ddos-detector/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ddos-detector ddos-detector
    postrotate
        systemctl reload ddos-detector.service > /dev/null 2>&1 || true
    endscript
}
```

#### Test Rotation

```bash
# Test logrotate
sudo logrotate -f /etc/logrotate.d/ddos-detector

# Verify
ls -lh /var/log/ddos-detector/
```

### Health Monitoring

#### Monitoring Script

```bash
#!/bin/bash
# /usr/local/bin/monitor-ddos.sh

# Check if service is running
if ! systemctl is-active --quiet ddos-detector.service; then
    echo "ERROR: DDoS Detector is not running"
    systemctl restart ddos-detector.service
    # Send alert
    mail -s "DDoS Detector Restarted" admin@example.com <<< "Service was down"
fi

# Check log file size
LOG_SIZE=$(du -sm /var/log/ddos-detector | cut -f1)
if [ $LOG_SIZE -gt 1000 ]; then
    echo "WARNING: Log directory > 1GB"
    # Trigger cleanup or alert
fi

# Check blocked IP count
BLOCKED_COUNT=$(grep -c "BLOCKED" /var/log/ddos-detector/ddos_attacks.log)
if [ $BLOCKED_COUNT -gt 100 ]; then
    echo "WARNING: More than 100 IPs blocked"
fi
```

#### Cron Job

```bash
# Add to crontab
crontab -e

# Check every 5 minutes
*/5 * * * * /usr/local/bin/monitor-ddos.sh >> /var/log/ddos-monitor.log 2>&1
```

### Performance Monitoring

```bash
# Monitor CPU and memory
top -p $(pgrep -f ddos_detector)

# Detailed process info
ps aux | grep ddos_detector

# Network statistics
netstat -i
ifstat -i wlp1s0
```

## Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# /usr/local/bin/backup-ddos.sh

BACKUP_DIR="/backup/ddos-detector"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp -r /opt/pydos/config "$BACKUP_DIR/config_$DATE"

# Backup logs (compressed)
tar -czf "$BACKUP_DIR/logs_$DATE.tar.gz" /var/log/ddos-detector/

# Backup iptables rules
iptables-save > "$BACKUP_DIR/iptables_$DATE.rules"

# Keep only last 7 days of backups
find "$BACKUP_DIR" -mtime +7 -delete

echo "Backup completed: $DATE"
```

### Recovery Procedure

```bash
# Restore configuration
cp -r /backup/ddos-detector/config_20240115_120000/* /opt/pydos/config/

# Restore iptables rules
iptables-restore < /backup/ddos-detector/iptables_20240115_120000.rules

# Restart service
systemctl restart ddos-detector.service
```

## Scaling and High Availability

### Multi-Server Setup

**Architecture**:
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Sensor 1   │────▶│   Central   │◀────│  Sensor 2   │
│  (Monitor)  │     │   Server    │     │  (Monitor)  │
└─────────────┘     │(Aggregation)│     └─────────────┘
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Dashboard  │
                    └─────────────┘
```

**Sensor Configuration**:
```python
# Sensor nodes - monitoring only
ENABLE_AUTO_BLOCKING = False
SEND_TO_CENTRAL = True
CENTRAL_SERVER = "http://central.example.com:5001"
```

**Central Server Configuration**:
```python
# Central server - aggregation and blocking
ENABLE_AUTO_BLOCKING = True
ACCEPT_FROM_SENSORS = True
SENSOR_API_KEY = "your-secure-api-key"
```

### Load Balancing

```nginx
# nginx configuration
upstream ddos_dashboard {
    server 192.168.1.10:5001;
    server 192.168.1.11:5001;
    server 192.168.1.12:5001;
}

server {
    listen 80;
    server_name ddos.example.com;
    
    location / {
        proxy_pass http://ddos_dashboard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Hardening

### Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 5001/tcp  # Dashboard (from specific IPs)
sudo ufw enable

# Restrict dashboard access
sudo ufw allow from 192.168.1.0/24 to any port 5001
```

### SSL/TLS for Dashboard

```python
# Use Flask with SSL
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5001,
        ssl_context=('cert.pem', 'key.pem')
    )
```

### File Permissions

```bash
# Secure configuration files
chmod 600 config/config.py

# Secure log directory
chmod 750 /var/log/ddos-detector

# Secure executable
chmod 550 src/ddos_detector.py
```

## Troubleshooting

### Service Won't Start

```bash
# Check systemd logs
sudo journalctl -u ddos-detector.service -n 50

# Check Python errors
sudo venv/bin/python3 src/ddos_detector.py

# Verify permissions
ls -la /opt/pydos
```

### High Resource Usage

```bash
# Check process stats
top -p $(pgrep -f ddos_detector)

# Reduce logging
# Edit config: LOG_LEVEL = "WARNING"

# Increase time window
# Edit config: TIME_WINDOW = 10.0
```

### iptables Issues

```bash
# Check iptables rules
sudo iptables -L -n -v

# Clear all rules (CAREFUL!)
sudo iptables -F INPUT

# Verify iptables is installed
which iptables
```

## Upgrading

### Minor Updates

```bash
# Pull latest code
cd /opt/pydos
git pull origin main

# Upgrade dependencies
source venv/bin/activate
pip install -U -r requirements.txt

# Restart service
sudo systemctl restart ddos-detector.service
```

### Major Upgrades

```bash
# Backup current installation
/usr/local/bin/backup-ddos.sh

# Stop service
sudo systemctl stop ddos-detector.service

# Pull new version
git fetch --tags
git checkout v2.0.0

# Update dependencies
source venv/bin/activate
pip install -U -r requirements.txt

# Migrate configuration if needed
python3 scripts/migrate_config.py

# Test
sudo venv/bin/python3 src/ddos_detector.py --test

# Start service
sudo systemctl start ddos-detector.service
```

## Best Practices

1. **Always test in development first**
2. **Keep backups of configuration**
3. **Monitor system resources**
4. **Regularly update dependencies**
5. **Review logs periodically**
6. **Document custom configurations**
7. **Set up alerting for critical events**
8. **Use version control for config changes**

## References

- [systemd Documentation](https://www.freedesktop.org/software/systemd/man/)
- [iptables Guide](https://www.netfilter.org/documentation/)
- [Python Deployment Best Practices](https://docs.python-guide.org/shipping/packaging/)
- [Linux Security Hardening](https://www.cisecurity.org/cis-benchmarks/)
