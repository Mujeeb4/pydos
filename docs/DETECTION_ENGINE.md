# Detection Engine Documentation

## Overview

The Detection Engine (`ddos_detector.py`) is the core component of the Real-Time DDoS Detection System. It orchestrates packet analysis, threat detection, and response coordination.

## Core Functionality

### 1. Packet Analysis

The detection engine receives packets from the sniffer module and performs real-time analysis:

```python
def packet_handler(packet):
    """Main packet processing function"""
    # Extract source IP
    # Update packet counters
    # Check for attack patterns
    # Trigger mitigation if needed
```

### 2. Detection Algorithms

#### A. Packet Flood Detection

**Purpose**: Detect volumetric DDoS attacks

**Algorithm**:
```
For each packet:
    1. Extract source IP address
    2. Increment packet counter for that IP
    3. If counter > PACKET_THRESHOLD within TIME_WINDOW:
        → Attack detected
        → Trigger mitigation
```

**Configuration**:
- `PACKET_THRESHOLD`: Default 100 packets/5 seconds
- `TIME_WINDOW`: Default 5.0 seconds

**Use Case**: Detects flood attacks from single sources

#### B. SYN Flood Detection

**Purpose**: Detect TCP SYN flood attacks specifically

**Algorithm**:
```
For each TCP packet:
    1. Check if SYN flag is set
    2. Increment SYN counter for source IP
    3. If SYN_counter > SYN_THRESHOLD within TIME_WINDOW:
        → SYN flood detected
        → Trigger mitigation
```

**Configuration**:
- `SYN_THRESHOLD`: Default 50 SYN packets/5 seconds
- Detects TCP flag 'S' (SYN bit)

**Use Case**: Specifically targets TCP connection exhaustion attacks

### 3. Time Window Management

#### Rolling Window Implementation

```python
# Global state
ip_packet_counts = defaultdict(int)
ip_syn_counts = defaultdict(int)
last_reset_time = time.time()

# Reset every TIME_WINDOW seconds
if current_time - last_reset_time >= TIME_WINDOW:
    ip_packet_counts.clear()
    ip_syn_counts.clear()
    last_reset_time = current_time
```

**Benefits**:
- Prevents counter overflow
- Focuses on recent traffic only
- Reduces memory footprint
- Provides fresh detection windows

#### Timer Thread

```python
def reset_counters_periodically():
    """Background thread that resets counters"""
    while True:
        time.sleep(TIME_WINDOW)
        with counter_lock:
            ip_packet_counts.clear()
            ip_syn_counts.clear()
```

### 4. Thread Safety

#### Critical Sections

All shared data structures are protected:

```python
counter_lock = threading.Lock()

def packet_handler(packet):
    with counter_lock:
        # Safe access to counters
        ip_packet_counts[src_ip] += 1
        ip_syn_counts[src_ip] += 1
```

**Protected Resources**:
- `ip_packet_counts` - Packet counters per IP
- `ip_syn_counts` - SYN packet counters per IP
- `blocked_ips` - Set of blocked IPs (in mitigator)

**Why Thread Safety Matters**:
- Scapy runs packet callbacks in separate threads
- Multiple packets processed concurrently
- Race conditions could corrupt counters
- Lock ensures atomic operations

## Detection Workflow

### Packet Processing Pipeline

```
1. Network Packet Arrives
   │
2. Scapy Captures Packet
   │
3. packet_handler() Called
   │
4. Acquire Lock
   │
5. Extract IP & Protocol Info
   │
6. Update Counters
   ├─> ip_packet_counts[src_ip] += 1
   └─> if TCP.SYN: ip_syn_counts[src_ip] += 1
   │
7. Check Thresholds
   ├─> Packet count > PACKET_THRESHOLD?
   └─> SYN count > SYN_THRESHOLD?
   │
8. Attack Detected?
   │
   YES─┐
   │   │
   │   ├─> Log Attack
   │   ├─> Call mitigator.block_ip()
   │   ├─> Update Dashboard
   │   └─> Continue monitoring
   │
   NO──┐
   │   │
   │   └─> Release Lock & Continue
   │
9. Repeat for next packet
```

## Detection Metrics

### Tracked Statistics

```python
statistics = {
    'total_packets': int,      # All packets processed
    'unique_ips': int,          # Distinct source IPs
    'blocked_ips': int,         # Currently blocked IPs
    'attacks_detected': int,    # Total attacks found
    'syn_floods': int,          # SYN flood attacks
    'packet_floods': int        # Generic packet floods
}
```

### Real-time Monitoring

The CLI dashboard displays:
- Current packet count per IP
- SYN packet count per IP
- Color-coded threat levels:
  - 🟢 Green: Normal (< 50% threshold)
  - 🟡 Yellow: Warning (50-99% threshold)
  - 🔴 Red: Attack (≥ threshold)

## Configuration Options

### Threshold Tuning

Adjust detection sensitivity in `config/config.py`:

```python
# Conservative (fewer false positives)
PACKET_THRESHOLD = 200
SYN_THRESHOLD = 100

# Aggressive (more sensitive)
PACKET_THRESHOLD = 50
SYN_THRESHOLD = 25

# Balanced (default)
PACKET_THRESHOLD = 100
SYN_THRESHOLD = 50
```

### Network Interface Selection

```python
# Auto-detect (recommended)
NETWORK_INTERFACE = get_default_network_interface()

# Manual specification
NETWORK_INTERFACE = "eth0"  # Wired
NETWORK_INTERFACE = "wlan0" # Wireless
NETWORK_INTERFACE = "wlp1s0" # Wireless (new naming)
```

### Testing Mode

```python
# Development/Testing
ALLOW_LOOPBACK_DETECTION = True  # Detect localhost attacks
TESTING_MODE = True

# Production
ALLOW_LOOPBACK_DETECTION = False # Ignore localhost
TESTING_MODE = False
```

## Attack Detection Examples

### Example 1: SYN Flood Attack

**Scenario**: Attacker sends 100 SYN packets in 3 seconds

```
Packet Stream:
192.168.1.100 → SYN packet #1   (t=0s)
192.168.1.100 → SYN packet #2   (t=0.03s)
...
192.168.1.100 → SYN packet #51  (t=1.5s)  ← THRESHOLD EXCEEDED
```

**Detection**:
```
[ALERT] SYN flood detected from 192.168.1.100
SYN count: 51 (threshold: 50)
Time window: 1.5 seconds
Action: Block IP via iptables
```

### Example 2: Packet Flood Attack

**Scenario**: Attacker floods with UDP packets

```
Packet Stream:
10.0.0.50 → UDP packet #1
10.0.0.50 → UDP packet #2
...
10.0.0.50 → UDP packet #101  ← THRESHOLD EXCEEDED
```

**Detection**:
```
[ALERT] Packet flood detected from 10.0.0.50
Packet count: 101 (threshold: 100)
Protocol: UDP
Action: Block IP via iptables
```

## Performance Optimization

### Memory Efficiency

```python
# Use defaultdict for automatic initialization
ip_packet_counts = defaultdict(int)

# Clear old data every TIME_WINDOW
# Prevents unbounded memory growth
```

**Memory Usage**:
- Baseline: ~50-100 MB
- Per tracked IP: ~1 KB
- 1000 IPs: ~51-101 MB

### CPU Optimization

```python
# Minimize processing in packet handler
def packet_handler(packet):
    # Fast path: Only extract what's needed
    if not packet.haslayer(IP):
        return  # Skip non-IP packets
    
    src_ip = packet[IP].src
    # ... minimal processing
```

**CPU Usage**:
- Idle: 1-5%
- Light traffic (100 pps): 10-20%
- Heavy traffic (1000 pps): 40-60%
- Depends on CPU speed

### Scalability Limits

| Metric | Value | Notes |
|--------|-------|-------|
| Max packet rate | ~10,000 pps | On commodity hardware |
| Max tracked IPs | ~10,000 | Before memory pressure |
| Max blocked IPs | Limited by iptables | ~10,000 rules |
| Detection latency | <10ms | Per packet processing |

## Error Handling

### Packet Processing Errors

```python
try:
    src_ip = packet[IP].src
except (AttributeError, IndexError):
    # Malformed packet
    logger.warning("Invalid packet format")
    return
```

### Counter Overflow Prevention

```python
# Automatic reset via time windows
# Prevents integer overflow
if counter > sys.maxsize:
    logger.error("Counter overflow detected")
    counter = 0
```

### Lock Timeout

```python
# Acquire lock with timeout
if counter_lock.acquire(timeout=1.0):
    try:
        # Critical section
        pass
    finally:
        counter_lock.release()
else:
    logger.warning("Lock acquisition timeout")
```

## Logging Integration

### Event Logging

```python
# Normal traffic
logger.info(f"Packet from {src_ip}")

# Threshold warning
logger.warning(f"High traffic from {src_ip}: {count} packets")

# Attack detection
logger.critical(f"ATTACK DETECTED from {src_ip}")
```

### Attack Logs

Logged to `logs/ddos_attacks.log`:
```
2024-01-15 10:30:45 [ATTACK] SYN flood from 192.168.1.100
  - SYN packets: 75
  - Threshold: 50
  - Action: IP blocked via iptables
  - Block duration: 60 minutes
```

## Dashboard Integration

### CLI Dashboard Updates

```python
# Real-time table generation
def generate_dashboard():
    table = Table(title="Live Traffic Monitor")
    
    for ip, count in ip_packet_counts.items():
        # Color code based on threshold
        if count >= PACKET_THRESHOLD:
            style = "red"
        elif count >= PACKET_THRESHOLD * 0.5:
            style = "yellow"
        else:
            style = "green"
        
        table.add_row(ip, str(count), style=style)
    
    return table
```

### Statistics Export

```python
# Export to stats.json for web dashboard
stats = {
    'total_packets': sum(ip_packet_counts.values()),
    'unique_ips': len(ip_packet_counts),
    'blocked_ips': len(mitigator.blocked_ips),
    'timestamp': datetime.now().isoformat()
}

with open('stats.json', 'w') as f:
    json.dump(stats, f)
```

## Testing the Detection Engine

### Unit Testing

```python
# Test threshold detection
def test_packet_threshold():
    detector = DDoSDetector()
    
    # Simulate 101 packets
    for _ in range(101):
        detector.process_packet("192.168.1.100")
    
    assert detector.is_attack_detected("192.168.1.100")
```

### Integration Testing

```bash
# Start detector
sudo python3 src/ddos_detector.py

# Simulate attack
sudo python3 scripts/simulate_attack.py \
    --target 127.0.0.1 \
    --type syn \
    --count 200

# Verify detection in logs
tail -f logs/ddos_attacks.log
```

## Troubleshooting

### No Packets Detected

**Symptoms**: Dashboard shows 0 packets

**Solutions**:
1. Check network interface: `ip addr show`
2. Verify interface in config: `config/config.py`
3. Run with sudo: `sudo python3 src/ddos_detector.py`
4. Check permissions: `getcap /usr/bin/python3`

### False Positives

**Symptoms**: Legitimate traffic blocked

**Solutions**:
1. Increase thresholds in `config.py`
2. Add IP to whitelist
3. Adjust time window duration
4. Review network baseline traffic

### High CPU Usage

**Symptoms**: System slow, CPU at 100%

**Solutions**:
1. Reduce packet capture rate
2. Increase TIME_WINDOW
3. Filter protocols: `sniff(filter="tcp")`
4. Use faster hardware

### Memory Leaks

**Symptoms**: Memory usage grows continuously

**Solutions**:
1. Verify counter resets are working
2. Check timer thread status
3. Clear old entries more frequently
4. Monitor with `htop` or `top`

## Best Practices

### 1. Threshold Configuration
- Start conservative, tune based on baseline
- Monitor false positive rate
- Document threshold changes

### 2. Resource Management
- Monitor CPU/memory usage
- Set up log rotation
- Clear expired data regularly

### 3. Testing
- Test in isolated environment first
- Use attack simulator for validation
- Monitor for false positives

### 4. Production Deployment
- Disable TESTING_MODE
- Set ALLOW_LOOPBACK_DETECTION = False
- Enable all logging
- Set up monitoring alerts

## Future Enhancements

### Phase 8: Machine Learning

```python
# Feature extraction for ML
features = extract_features(ip_address)
# - Packet rate
# - Protocol distribution
# - Packet size variance
# - Time-based patterns

# Prediction
is_attack = ml_model.predict(features)
```

### Advanced Detection

1. **Behavioral Analysis**: Learn normal traffic patterns
2. **Multi-vector Detection**: Detect combined attack types
3. **Geolocation Filtering**: Block by country/region
4. **Reputation Integration**: Use IP reputation databases

## References

- [DDoS Attack Patterns](https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/)
- [Scapy Packet Analysis](https://scapy.readthedocs.io/en/latest/usage.html)
- [TCP SYN Flood](https://en.wikipedia.org/wiki/SYN_flood)
- [Threading Best Practices](https://docs.python.org/3/library/threading.html)
