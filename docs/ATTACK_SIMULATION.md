# Enhanced Attack Simulation Documentation

## Overview

The Enhanced Attack Simulation System provides comprehensive testing capabilities for the 10 advanced DDoS detection features. This system includes **21 different attack types** that can be simulated to validate detection effectiveness.

**Version**: v2.0 (Enhanced)
**Attack Types**: 21 Different Simulations
**Scripts**: 2 Enhanced Simulation Scripts
**Testing Modes**: Single-Source (DoS) + Distributed (DDoS)

## Simulation Scripts Overview

### 1. `scripts/simulate_ddos.py` - Distributed Attacks (21 Types)
**Purpose**: Simulate DDoS attacks from multiple spoofed source IPs

**Supported Attack Types**:
- **Original Attacks** (6 types)
- **TCP Flag Attacks** (Feature 1) - 6 types
- **Packet Size Attacks** (Feature 2) - 2 types
- **ICMP Type Attacks** (Feature 3) - 1 type
- **Port Analysis Attacks** (Feature 4) - 1 type
- **TTL Analysis Attacks** (Feature 5) - 1 type
- **Fragment Attacks** (Feature 6) - 1 type
- **Burst Attacks** (Feature 8) - 1 type
- **App Layer Attacks** (Feature 10) - 2 types
- **Special Modes** - Sequential testing

### 2. `scripts/simulate_attack.py` - Single-Source Attacks (16 Types)
**Purpose**: Simulate DoS attacks from single IP for per-IP detection testing

## Complete Attack Type Reference

### Original Attack Types

#### 1. SYN Flood (`syn`)
**Description**: Classic TCP SYN flood - sends SYN packets without completing handshake
**Detection Feature**: Basic SYN counter + Connection State Tracking (Feature 7)
**Parameters**:
- `num_sources`: Number of spoofed IPs (default: 100)
- `packets_per_source`: SYN packets per IP (default: 10)
- `delay`: Delay between packets (default: 0.001s)

**Usage**:
```bash
# DDoS SYN flood
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type syn --sources 200

# Single-source SYN flood
sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --type syn --count 200
```

#### 2. UDP Flood (`udp`)
**Description**: UDP packet flood targeting specific port
**Detection Feature**: Basic UDP counter
**Parameters**:
- `target_port`: Target port (default: 53 - DNS)
- `payload_size`: UDP payload size (default: 512 bytes)
- `num_sources`: Spoofed sources (default: 100)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type udp --sources 150
```

#### 3. ICMP Flood (`icmp`)
**Description**: ICMP ping flood (echo requests)
**Detection Feature**: Basic ICMP counter + ICMP Type Analysis (Feature 3)
**Parameters**:
- `num_sources`: Spoofed sources (default: 100)
- `packets_per_source`: Ping packets per source (default: 10)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type icmp --sources 100
```

#### 4. Low-and-Slow (`lowslow`)
**Description**: Attack where each IP stays under threshold but combined traffic overwhelms
**Detection Feature**: Low-and-slow pattern detection
**Parameters**:
- `num_sources`: Total sources (default: 200)
- `packets_per_source`: Packets per source (default: 40 - under threshold)
- `delay`: Delay between packets (default: 0.01s)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type lowslow --sources 300
```

#### 5. IP Spike (`spike`)
**Description**: Sudden spike of many new source IPs in short time window
**Detection Feature**: IP spike detection
**Parameters**:
- `num_sources`: Unique IPs to create (default: 500)
- `duration_seconds`: Time window for spike (default: 2.0s)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type spike --sources 300
```

#### 6. Multi-Vector (`multi`)
**Description**: Coordinated attack with SYN, UDP, ICMP, ACK, and HTTP floods simultaneously
**Detection Feature**: Multi-vector DDoS detection
**Parameters**:
- `num_sources`: Sources per attack vector (default: 150)
- `duration_seconds`: Attack duration (default: 10.0s)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type multi --sources 100
```

### TCP Flag Attacks (Feature 1)

#### 7. ACK Flood (`ack`)
**Description**: Excessive TCP ACK packets
**Detection Feature**: TCP Flag Analysis (Feature 1)
**Parameters**:
- `num_sources`: Spoofed sources (default: 100)
- `packets_per_source`: ACK packets per source (default: 10)
- `delay`: Delay between packets (default: 0.001s)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type ack --sources 100
```

#### 8. FIN Flood (`fin`)
**Description**: Excessive TCP FIN packets
**Detection Feature**: TCP Flag Analysis (Feature 1)
**Parameters**:
- Similar to ACK flood

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type fin --sources 100
```

#### 9. RST Flood (`rst`)
**Description**: Excessive TCP RST packets
**Detection Feature**: TCP Flag Analysis (Feature 1)
**Parameters**:
- Similar to ACK flood

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type rst --sources 100
```

#### 10. XMAS Scan (`xmas`)
**Description**: Malformed TCP packets with FIN+PSH+URG flags set (always malicious)
**Detection Feature**: TCP Flag Analysis (Feature 1) - Immediate alert
**Parameters**:
- `num_sources`: Spoofed sources (default: 50)
- `packets_per_source`: XMAS packets per source (default: 5)
- `delay`: Delay between packets (default: 0.01s)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type xmas --sources 50
```

**Expected Result**:
```
🚨 DoS ALERT: MALFORMED_TCP from [IP]
   XMAS packets: 6 (threshold: 5)
   Severity: CRITICAL
   Action: Immediate IP block
```

#### 11. NULL Scan (`null`)
**Description**: Malformed TCP packets with NO flags set (always malicious)
**Detection Feature**: TCP Flag Analysis (Feature 1) - Immediate alert
**Parameters**:
- Similar to XMAS scan

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type null --sources 50
```

#### 12. Invalid Flags (`invalid`)
**Description**: Impossible TCP flag combinations (SYN+FIN, SYN+RST)
**Detection Feature**: TCP Flag Analysis (Feature 1) - Immediate alert
**Parameters**:
- Similar to XMAS scan

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type invalid --sources 50
```

### Packet Size Attacks (Feature 2)

#### 13. Small Packet Flood (`smallpkt`)
**Description**: Flood of minimal-size packets (<64 bytes) to overwhelm CPU processing
**Detection Feature**: Packet Size Analysis (Feature 2)
**Parameters**:
- `num_sources`: Spoofed sources (default: 100)
- `packets_per_source`: Small packets per source (default: 20)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type smallpkt --sources 100
```

**Expected Result**:
```
🚨 DoS ALERT: SMALL_PACKET_FLOOD from [IP]
   Small packets: 81 (threshold: 80)
   Packet size: ~40 bytes
   Bandwidth impact: High CPU utilization
```

#### 14. Amplification Attack (`amplify`)
**Description**: Large UDP packets (>1200 bytes) causing bandwidth exhaustion
**Detection Feature**: Packet Size Analysis (Feature 2)
**Parameters**:
- `payload_size`: Packet size (default: 1200 bytes)
- `num_sources`: Spoofed sources (default: 50)
- `packets_per_source`: Large packets per source (default: 10)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type amplify --sources 50
```

### ICMP Type Attacks (Feature 3)

#### 15. Smurf Attack Simulation (`smurf`)
**Description**: ICMP Echo Reply packets (type 0) - Smurf attack indicator
**Detection Feature**: ICMP Type Analysis (Feature 3)
**Parameters**:
- `num_sources`: Spoofed sources (default: 100)
- `packets_per_source`: Echo replies per source (default: 10)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type smurf --sources 100
```

**Expected Result**:
```
🚨 DDoS ALERT: SMURF_ATTACK_INDICATOR
   ICMP Echo Replies detected from distributed sources
```

### Port Analysis Attacks (Feature 4)

#### 16. Port Scan (`portscan`)
**Description**: Single IP scanning many different ports rapidly
**Detection Feature**: Port Analysis (Feature 4)
**Parameters**:
- `num_sources`: Sources performing scans (default: 20)
- `ports_per_source`: Ports scanned per source (default: 30)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type portscan --sources 10
```

**Expected Result**:
```
🚨 DoS ALERT: PORT_SCAN from [IP]
   Ports scanned: 31 (threshold: 15)
   Scanned ports: 22,80,443,25,53,3306,...
```

### TTL Analysis Attacks (Feature 5)

#### 17. TTL Spoofing (`ttlspoof`)
**Description**: Packets with highly varied TTL values to simulate spoofing
**Detection Feature**: TTL Anomaly Detection (Feature 5)
**Parameters**:
- `num_sources`: Spoofed sources (default: 100)
- `packets_per_source`: Packets per source with varied TTL (default: 10)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type ttlspoof --sources 100
```

**Expected Result**:
```
🚨 DoS ALERT: SPOOFED_TRAFFIC_TTL_VARIANCE from [IP]
   TTL variance: 254 (threshold: 30)
   TTL range: 1-255
   Indicator: Spoofed traffic detected
```

### Fragment Attacks (Feature 6)

#### 18. Fragment Flood (`fragment`)
**Description**: Excessive IP fragmented packets
**Detection Feature**: Fragment Attack Detection (Feature 6)
**Parameters**:
- `num_sources`: Spoofed sources (default: 50)
- `packets_per_source`: Fragmented packets per source (default: 10)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type fragment --sources 50
```

**Expected Result**:
```
🚨 DoS ALERT: FRAGMENT_FLOOD from [IP]
   Fragments: 21 (threshold: 20)
   Tiny fragments: 8
```

### Burst Attacks (Feature 8)

#### 19. Burst Attack (`burst`)
**Description**: Micro-bursts of packets within normal traffic
**Detection Feature**: Burst Detection (Feature 8)
**Parameters**:
- `num_sources`: Sources performing bursts (default: 50)
- `bursts_per_source`: Burst count per source (default: 5)
- `packets_per_burst`: Packets per burst (default: 30)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type burst --sources 50
```

**Expected Result**:
```
🚨 DoS ALERT: BURST_ATTACK from [IP]
   Burst count: 5 (threshold: 3)
   Max burst size: 30 packets
   Burst window: 100ms
```

### Application Layer Attacks (Feature 10)

#### 20. HTTP Flood (`http`)
**Description**: Excessive HTTP GET requests
**Detection Feature**: Application Layer Inspection (Feature 10)
**Parameters**:
- `num_sources`: Sources sending HTTP requests (default: 50)
- `requests_per_source`: HTTP requests per source (default: 20)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type http --sources 50
```

**Expected Result**:
```
🚨 DoS ALERT: HTTP_FLOOD from [IP]
   HTTP requests: 51 (threshold: 50)
   Target port: 80 (HTTP)
```

#### 21. DNS Flood (`dns`)
**Description**: Excessive DNS query packets
**Detection Feature**: Application Layer Inspection (Feature 10)
**Parameters**:
- `num_sources`: Sources sending DNS queries (default: 50)
- `queries_per_source`: DNS queries per source (default: 20)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type dns --sources 50
```

**Expected Result**:
```
🚨 DoS ALERT: DNS_FLOOD from [IP]
   DNS queries: 31 (threshold: 30)
   Target port: 53 (DNS)
```

### Special Testing Modes

#### 22. Run All Attacks Sequentially (`all`)
**Description**: Execute ALL 21 attack types one after another for comprehensive testing
**Detection Feature**: All 10 enhanced detection features
**Parameters**:
- `num_sources`: Sources per attack (default: 100)
- `delay`: Delay between attacks (default: 0.001s)

**Usage**:
```bash
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type all --sources 100
```

**What it does**:
1. SYN Flood
2. UDP Flood
3. ICMP Flood
4. Low-and-Slow
5. IP Spike
6. ACK Flood
7. FIN Flood
8. RST Flood
9. XMAS Scan
10. NULL Scan
11. Invalid Flags
12. Small Packet Flood
13. Amplification Attack
14. Smurf Simulation
15. Port Scan
16. TTL Spoofing
17. Fragment Flood
18. Burst Attack
19. HTTP Flood
20. DNS Flood
21. Multi-Vector (all simultaneous)

## Testing Strategy

### Comprehensive Testing Workflow

```bash
# 1. Start enhanced detector
sudo python3 src/detector.py

# 2. Test each detection feature individually
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type xmas
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type smallpkt
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type portscan
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type ttlspoof
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type burst
# ... test all types

# 3. Run comprehensive test (all attack types)
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type all

# 4. Check logs for detection results
tail -f logs/ddos_attacks.log
```

### Expected Detection Matrix

| Attack Type | Expected Alert Type | Feature Tested | Severity |
|-------------|---------------------|----------------|----------|
| XMAS Scan | `MALFORMED_TCP` | TCP Flag Analysis | CRITICAL |
| NULL Scan | `MALFORMED_TCP` | TCP Flag Analysis | CRITICAL |
| Invalid Flags | `MALFORMED_TCP` | TCP Flag Analysis | CRITICAL |
| Small Packet | `SMALL_PACKET_FLOOD` | Packet Size Analysis | HIGH |
| Amplification | `AMPLIFICATION_ATTACK` | Packet Size Analysis | HIGH |
| Smurf | `SMURF_ATTACK_INDICATOR` | ICMP Type Analysis | MEDIUM |
| Port Scan | `PORT_SCAN` | Port Analysis | MEDIUM |
| TTL Spoofing | `SPOOFED_TRAFFIC_TTL_VARIANCE` | TTL Analysis | HIGH |
| Fragment | `FRAGMENT_FLOOD` | Fragment Detection | MEDIUM |
| Burst | `BURST_ATTACK` | Burst Detection | HIGH |
| HTTP Flood | `HTTP_FLOOD` | App Layer Inspection | MEDIUM |
| DNS Flood | `DNS_FLOOD` | App Layer Inspection | MEDIUM |
| SYN Flood | `SYN_FLOOD` | Basic + Connection Tracking | HIGH |
| Low-and-Slow | `LOW_AND_SLOW_ATTACK` | Pattern Analysis | MEDIUM |
| IP Spike | `IP_SPIKE_ATTACK` | Spike Detection | HIGH |

## Configuration Options

### Attack Simulation Parameters

```python
# Default attack parameters (in config/config.py)
DEFAULT_ATTACK_TARGET = "127.0.0.1"
DEFAULT_ATTACK_PORT = 80
DEFAULT_PACKET_COUNT = 200
DEFAULT_DDOS_SOURCES = 100
DEFAULT_PACKET_DELAY = 0.001

# Enhanced attack-specific defaults
XMAS_THRESHOLD = 5              # Packets to trigger XMAS alert
SMALL_PACKET_SIZE = 64          # Size threshold for small packets
LARGE_PACKET_SIZE = 1000        # Size threshold for large packets
BURST_WINDOW_MS = 100           # Micro-burst window size
TTL_VARIANCE_THRESHOLD = 30     # TTL variance for spoofing detection
```

### Performance Tuning

```bash
# Adjust packet rates for testing
--delay 0.001     # Fast attacks (high PPS)
--delay 0.01      # Moderate attacks
--delay 0.1       # Slow attacks (low-and-slow simulation)

# Adjust source counts
--sources 10      # Quick testing
--sources 100     # Normal testing
--sources 500     # Stress testing
```

## Safety and Best Practices

### Important Safety Notes

1. **Only test on systems you own or have permission to test**
2. **Use private/localhost IPs for initial testing**:
   ```bash
   --target 127.0.0.1
   ```
3. **Start with small source counts**:
   ```bash
   --sources 10 --packets 5
   ```
4. **Monitor system resources** during testing
5. **Have iptables flush ready**:
   ```bash
   sudo iptables -F
   ```

### Testing Environment Setup

```bash
# 1. Start detector in one terminal
sudo python3 src/detector.py

# 2. Start web dashboard in another terminal
python3 src/dashboard.py

# 3. Run attack simulations in separate terminals
sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type xmas

# 4. Monitor logs in real-time
tail -f logs/ddos_attacks.log
```

### Validation Checklist

After running each attack type, verify:

- [ ] Alert appears in detector terminal
- [ ] Correct attack type detected
- [ ] IP blocked (if auto-blocking enabled)
- [ ] Alert logged to `logs/ddos_attacks.log`
- [ ] Stats updated in `stats.json`
- [ ] Web dashboard shows blocked IP

## Troubleshooting

### Common Issues

#### Attack Not Detected
**Symptoms**: No alert for expected attack type

**Solutions**:
1. Check feature is enabled in `config/config.py`
2. Verify threshold values are appropriate
3. Check detector is running with root privileges
4. Monitor packet capture with `tcpdump`

#### False Positives
**Symptoms**: Legitimate traffic blocked

**Solutions**:
1. Increase threshold values
2. Disable aggressive features temporarily
3. Add legitimate IPs to whitelist
4. Review baseline traffic patterns

#### High System Load
**Symptoms**: System becomes unresponsive

**Solutions**:
1. Reduce `--sources` parameter
2. Increase `--delay` between packets
3. Test one attack type at a time
4. Use faster hardware

#### Permission Errors
**Symptoms**: "Operation not permitted" errors

**Solutions**:
1. Run with `sudo`
2. Check network interface permissions
3. Verify Scapy installation
4. Check firewall rules

## Integration with Main Menu

The attack simulations are fully integrated with `main.py`:

```bash
# Run main menu
sudo python3 main.py

# Select option 3: Complete Environment
# Choose DoS or DDoS mode
# Select from all 21 attack types
# Attack launches automatically in new terminal
```

This provides a user-friendly interface for testing all detection capabilities without command-line complexity.

## Performance Metrics

### Attack Generation Rates

| Attack Type | Max PPS (Packets/Second) | Typical CPU Usage |
|-------------|--------------------------|-------------------|
| SYN Flood | ~1000 | Low |
| UDP Flood | ~800 | Low |
| ICMP Flood | ~1200 | Low |
| XMAS Scan | ~500 | Low |
| Small Packet | ~1500 | Medium |
| Amplification | ~300 | Low |
| HTTP Flood | ~400 | Medium |
| DNS Flood | ~600 | Low |
| Fragment Flood | ~200 | High |
| Multi-Vector | ~500 | High |

### Recommended Testing Parameters

```bash
# Quick validation (each test ~5-10 seconds)
--sources 20 --packets 5 --delay 0.01

# Normal testing (each test ~30-60 seconds)
--sources 50 --packets 10 --delay 0.001

# Stress testing (each test ~2-5 minutes)
--sources 100 --packets 20 --delay 0.0005

# Comprehensive testing (all attacks ~15-30 minutes)
--sources 100 --delay 0.001
```

## Future Enhancements

### Advanced Simulation Features

1. **Geographic Distribution**: Simulate attacks from specific countries/regions
2. **Botnet Patterns**: More realistic botnet IP distributions
3. **Application Payloads**: Real HTTP requests and DNS queries
4. **Time-based Patterns**: Attacks that vary intensity over time
5. **Multi-target Attacks**: Attacks hitting multiple IPs simultaneously
6. **Reflection Attacks**: NTP/DNS/memcached amplification simulations

### Integration Improvements

1. **Real-time Feedback**: Show attack progress in detector dashboard
2. **Automated Testing**: Script to run all attacks and validate detections
3. **Performance Benchmarking**: Measure detection latency and accuracy
4. **Attack Combination**: Allow custom attack mixes
5. **Load Testing**: Stress test detector with extreme attack volumes

## References

- [DDoS Attack Types](https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/)
- [TCP Flag Attacks](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
- [Port Scanning](https://nmap.org/book/man-port-scanning-techniques.html)
- [IP Spoofing Detection](https://tools.ietf.org/html/rfc2827)
- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)
