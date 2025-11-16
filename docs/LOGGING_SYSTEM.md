# Logging System Documentation

## Overview

The Logging System (`logger.py`) provides comprehensive event tracking, audit trails, and debugging capabilities for the DDoS detection system. It implements multiple log files with different purposes and severity levels.

## Core Architecture

### Logger Class Structure

```python
class DDoSLogger:
    def __init__(self, log_dir: str = "logs"):
        self.event_logger    # Main events
        self.attack_logger   # Attack-specific logs
        self.system_logger   # System operations
        self.json_logger     # Structured JSON logs
```

## Log Files

### 1. Main Event Log (`ddos_events.log`)

**Purpose**: Tracks all system events

**Format**:
```
2024-01-15 10:30:45,123 - event_logger - INFO - System started
2024-01-15 10:30:46,234 - event_logger - WARNING - High traffic from 192.168.1.100
2024-01-15 10:30:47,345 - event_logger - CRITICAL - Attack detected from 192.168.1.100
```

**Content**:
- System startup/shutdown
- Configuration changes
- Traffic monitoring events
- Detection alerts
- General operations

**Usage**:
```python
logger.log_event("System started", level="INFO")
logger.log_event("High traffic detected", level="WARNING")
```

### 2. Attack Log (`ddos_attacks.log`)

**Purpose**: Dedicated attack event tracking

**Format**:
```
2024-01-15 10:30:47 [ATTACK] SYN flood detected from 192.168.1.100
  - SYN packets: 75 (threshold: 50)
  - Total packets: 150
  - Action: IP blocked via iptables
  - Block duration: 60 minutes
  - Attack type: SYN_FLOOD
```

**Content**:
- Attack detection timestamps
- Attack types (SYN flood, packet flood)
- Threshold violations
- Mitigation actions taken
- Attack metrics

**Usage**:
```python
logger.log_attack(
    ip_address="192.168.1.100",
    attack_type="SYN_FLOOD",
    packet_count=150,
    syn_count=75
)
```

### 3. System Log (`ddos_system.log`)

**Purpose**: System-level operations and errors

**Format**:
```
2024-01-15 10:30:45 [SYSTEM] iptables available: True
2024-01-15 10:30:45 [SYSTEM] Network interface: wlp1s0
2024-01-15 10:30:47 [SYSTEM] IP 192.168.1.100 blocked successfully
2024-01-15 10:30:48 [ERROR] Failed to block IP 192.168.1.101: Permission denied
```

**Content**:
- System initialization
- Configuration validation
- iptables operations
- Error conditions
- Resource status

**Usage**:
```python
logger.log_system("Network interface detected: wlp1s0")
logger.log_system("iptables command failed", level="ERROR")
```

### 4. JSON Log (`ddos_events.json`)

**Purpose**: Machine-readable structured logs

**Format**:
```json
{
  "timestamp": "2024-01-15T10:30:47.123456",
  "event_type": "attack_detected",
  "severity": "critical",
  "source_ip": "192.168.1.100",
  "attack_type": "SYN_FLOOD",
  "metrics": {
    "packet_count": 150,
    "syn_count": 75,
    "threshold_exceeded": true
  },
  "action": "ip_blocked",
  "duration": "60_minutes"
}
```

**Content**:
- All events in JSON format
- Searchable and parseable
- Integration-ready
- Analytics-friendly

**Usage**:
```python
logger.log_json({
    "event_type": "attack_detected",
    "source_ip": "192.168.1.100",
    "metrics": {"packet_count": 150}
})
```

## Log Levels

### Severity Hierarchy

```python
CRITICAL  # Attacks detected, system failures
ERROR     # iptables errors, permission issues
WARNING   # Threshold warnings, high traffic
INFO      # Normal operations, events
DEBUG     # Detailed debugging information
```

### Level Usage Guidelines

| Level | Use Case | Example |
|-------|----------|---------|
| CRITICAL | Active attacks | "DDoS attack detected from 192.168.1.100" |
| ERROR | System failures | "Failed to block IP: Permission denied" |
| WARNING | Threshold warnings | "High traffic: 80/100 packets" |
| INFO | Normal events | "Packet captured from 192.168.1.50" |
| DEBUG | Detailed traces | "Counter incremented: ip_counts[192.168.1.50]=5" |

### Setting Log Levels

```python
# Development: See everything
logger.set_level("DEBUG")

# Production: Warnings and above
logger.set_level("WARNING")

# Critical only
logger.set_level("CRITICAL")
```

## Log Rotation

### Automatic Rotation

```python
handler = RotatingFileHandler(
    filename="logs/ddos_events.log",
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=5               # Keep 5 backup files
)
```

**Configuration**:
- **Max Size**: 5 MB per file (default)
- **Backup Count**: 5 files retained
- **Total Space**: Up to 30 MB (5 MB × 6 files)

**Rotation Example**:
```
ddos_events.log       (current, 0-5 MB)
ddos_events.log.1     (previous, 5 MB)
ddos_events.log.2     (older, 5 MB)
ddos_events.log.3     (older, 5 MB)
ddos_events.log.4     (older, 5 MB)
ddos_events.log.5     (oldest, 5 MB)
```

### Manual Rotation

```bash
# Archive current logs
mkdir -p logs/archive
mv logs/*.log logs/archive/$(date +%Y%m%d)/

# Or use logrotate (Linux)
sudo logrotate /etc/logrotate.d/ddos-detector
```

## Log Format Customization

### Standard Format

```python
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
```

**Output**:
```
2024-01-15 10:30:45 - event_logger - INFO - System started
```

### Detailed Format (Debug)

```python
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - [%(filename)s:%(lineno)d] - %(levelname)s - %(message)s'
)
```

**Output**:
```
2024-01-15 10:30:45 - event_logger - [ddos_detector.py:123] - INFO - System started
```

### Custom Format

```python
formatter = logging.Formatter(
    '[%(levelname)s] %(asctime)s | %(message)s',
    datefmt='%H:%M:%S'
)
```

**Output**:
```
[INFO] 10:30:45 | System started
```

## Logging API

### Basic Logging

```python
from logger import get_logger

logger = get_logger()

# Simple logging
logger.log_event("Packet captured")

# With severity
logger.log_event("High traffic detected", level="WARNING")

# With additional context
logger.log_event(
    f"Traffic from {ip}: {count} packets",
    level="INFO"
)
```

### Attack Logging

```python
logger.log_attack(
    ip_address="192.168.1.100",
    attack_type="SYN_FLOOD",
    packet_count=150,
    syn_count=75,
    action_taken="IP blocked via iptables"
)
```

### System Logging

```python
logger.log_system("iptables available")
logger.log_system("Network interface: wlp1s0")
logger.log_system("Blocked IP: 192.168.1.100")
```

### Structured JSON Logging

```python
event = {
    "timestamp": datetime.now().isoformat(),
    "event_type": "packet_captured",
    "source_ip": "192.168.1.100",
    "protocol": "TCP",
    "flags": "SYN"
}

logger.log_json(event)
```

## Advanced Features

### 1. Context Managers

```python
with logger.log_context("Processing packet"):
    # Processing code
    pass
# Automatically logs start and end
```

### 2. Performance Timing

```python
@logger.log_timing
def process_packet(packet):
    # Function code
    pass

# Automatically logs execution time
```

### 3. Exception Logging

```python
try:
    mitigator.block_ip(ip_address)
except Exception as e:
    logger.log_exception(e, context="IP blocking failed")
```

### 4. Batch Logging

```python
# Queue logs for batch writing
logger.start_batch()

for packet in packets:
    logger.log_event(f"Processed {packet}")

logger.flush_batch()  # Write all at once
```

## Log Analysis

### Reading Logs

```bash
# View latest events
tail -f logs/ddos_events.log

# View attacks only
tail -f logs/ddos_attacks.log

# Search for specific IP
grep "192.168.1.100" logs/ddos_events.log

# Count attacks
grep "\[ATTACK\]" logs/ddos_attacks.log | wc -l
```

### JSON Log Analysis

```bash
# Pretty print JSON logs
cat logs/ddos_events.json | jq '.'

# Filter by event type
cat logs/ddos_events.json | jq 'select(.event_type == "attack_detected")'

# Count by attack type
cat logs/ddos_events.json | jq -r '.attack_type' | sort | uniq -c

# Extract IPs
cat logs/ddos_events.json | jq -r '.source_ip' | sort | uniq
```

### Python Analysis

```python
import json
from collections import Counter

# Load JSON logs
with open('logs/ddos_events.json') as f:
    events = [json.loads(line) for line in f]

# Count by event type
event_types = Counter(e['event_type'] for e in events)
print(event_types)

# Find top attackers
attackers = Counter(
    e['source_ip'] 
    for e in events 
    if e['event_type'] == 'attack_detected'
)
print(attackers.most_common(10))
```

## Configuration

### Log Directory

```python
# Default
logger = get_logger(log_dir="logs")

# Custom
logger = get_logger(log_dir="/var/log/ddos-detector")
```

### File Sizes

```python
# config/config.py
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 10              # 10 backups
```

### Enable/Disable Logs

```python
# Disable specific logs
logger.disable_attack_log = True
logger.disable_json_log = True

# Only console output
logger.disable_file_logging = True
```

## Performance Considerations

### I/O Impact

```python
# Synchronous (blocks)
logger.log_event("Message")  # Waits for disk write

# Asynchronous (future enhancement)
logger.log_event_async("Message")  # Returns immediately
```

### Buffering

```python
# Enable buffering for better performance
logger.set_buffer_size(1024)  # Buffer 1KB before flush

# Flush manually
logger.flush()
```

### Sampling

```python
# Log only 10% of packets
if random.random() < 0.1:
    logger.log_event(f"Packet from {ip}")
```

## Integration with Dashboard

### Real-time Log Viewing

```python
# Web dashboard endpoint
@app.route('/api/logs')
def get_logs():
    logs = logger.get_recent_logs(limit=100)
    return jsonify(logs)
```

### Log Statistics

```python
stats = {
    'total_events': logger.count_events(),
    'total_attacks': logger.count_attacks(),
    'error_count': logger.count_errors(),
    'last_update': logger.get_last_timestamp()
}
```

## Troubleshooting

### Problem: Logs Not Created

**Symptoms**: No log files in `logs/` directory

**Solutions**:
1. Check directory permissions: `ls -la logs/`
2. Create directory: `mkdir -p logs`
3. Check disk space: `df -h`

### Problem: Log Files Growing Too Large

**Symptoms**: Disk space warnings

**Solutions**:
1. Reduce `LOG_MAX_BYTES` in config
2. Decrease `LOG_BACKUP_COUNT`
3. Implement log cleanup script
4. Set up external log rotation

### Problem: Performance Degradation

**Symptoms**: System slow when logging heavily

**Solutions**:
1. Reduce log level (WARNING or ERROR only)
2. Enable log buffering
3. Use asynchronous logging
4. Sample high-frequency events

### Problem: Logs Missing Information

**Symptoms**: Incomplete log entries

**Solutions**:
1. Check log level settings
2. Verify formatter includes all fields
3. Ensure flush() called before exit
4. Check for exception handling

## Best Practices

### 1. Production Logging

```python
# Production settings
logger.set_level("WARNING")  # Only warnings and above
logger.enable_rotation = True
logger.max_file_size = 10 * 1024 * 1024  # 10 MB
```

### 2. Development Logging

```python
# Development settings
logger.set_level("DEBUG")  # All messages
logger.enable_console = True  # Also print to console
logger.enable_color = True    # Colored output
```

### 3. Security

```python
# Don't log sensitive data
logger.log_event(f"Attack from {ip}")  # OK
logger.log_event(f"Password: {password}")  # NEVER!

# Sanitize inputs
ip = sanitize_ip(raw_ip)
logger.log_event(f"Traffic from {ip}")
```

### 4. Structured Logging

```python
# Use structured format for analysis
logger.log_json({
    "timestamp": datetime.now().isoformat(),
    "event": "attack_detected",
    "ip": ip_address,
    "metrics": metrics
})
```

## Monitoring and Alerts

### Log Monitoring Tools

```bash
# tail + grep
tail -f logs/ddos_attacks.log | grep "CRITICAL"

# journalctl (if using systemd)
journalctl -u ddos-detector -f

# External tools
# - ELK Stack (Elasticsearch, Logstash, Kibana)
# - Splunk
# - Datadog
# - Grafana Loki
```

### Alerting Integration

```python
def send_alert(message):
    """Send alert via email/Slack/SMS"""
    if logger.get_attack_count() > 10:
        send_email("admin@example.com", message)
        send_slack_alert(message)
```

## Future Enhancements

### 1. Remote Logging

```python
# Send logs to remote server
import logging.handlers

handler = logging.handlers.SysLogHandler(
    address=('remote-server', 514)
)
logger.add_handler(handler)
```

### 2. Database Logging

```python
# Store logs in database
def log_to_database(event):
    db.execute(
        "INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)",
        (event['timestamp'], event['level'], event['message'])
    )
```

### 3. Real-time Analytics

```python
# Stream logs to analytics engine
from kafka import KafkaProducer

producer = KafkaProducer(bootstrap_servers='localhost:9092')
producer.send('ddos-logs', log_message)
```

## References

- [Python Logging Documentation](https://docs.python.org/3/library/logging.html)
- [Logging Best Practices](https://docs.python-guide.org/writing/logging/)
- [Log Rotation Guide](https://www.digitalocean.com/community/tutorials/how-to-manage-logfiles-with-logrotate-on-ubuntu-16-04)
- [ELK Stack](https://www.elastic.co/what-is/elk-stack)
