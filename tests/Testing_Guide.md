# DDoS Detection System - Testing Guide

**Version**: 1.0  
**Date**: November 8, 2025  
**Purpose**: Comprehensive testing procedures for validating system functionality

---

## Table of Contents

1. [Pre-Test Setup](#pre-test-setup)
2. [Test Scenarios](#test-scenarios)
3. [Screenshot Checklist](#screenshot-checklist)
4. [Verification Procedures](#verification-procedures)
5. [Performance Testing](#performance-testing)
6. [Troubleshooting](#troubleshooting)

---

## Pre-Test Setup

### 1. Environment Preparation

**System Requirements Check**:
```bash
# Check Ubuntu version
lsb_release -a

# Check Python version (should be 3.8+)
python3 --version

# Check if running as root
whoami  # Should show your username, not root

# Verify network interface
ip a  # Note your interface name (e.g., enp0s3, wlp1s0)
```

### 2. Clean Firewall State

**Important**: Start each test with a clean iptables state to avoid interference.

```bash
# Save current rules (backup)
sudo iptables-save > ~/iptables_backup.txt

# Clear all existing rules
sudo iptables -F
sudo iptables -X

# Verify clean state
sudo iptables -L -n -v
# Output should show empty chains (0 packets, 0 bytes)
```

### 3. Install Testing Tools

```bash
# Install hping3 (SYN flood tool)
sudo apt install hping3 -y

# Verify installation
hping3 --version

# Optional: Install tcpdump for packet verification
sudo apt install tcpdump -y
```

### 4. Start System Components

**Terminal 1: Detection Engine**
```bash
cd ~/pydos  # or your project path
source venv/bin/activate
sudo venv/bin/python3 ddos_detector.py
```

**Terminal 2: Web Dashboard (Optional)**
```bash
cd ~/pydos
source venv/bin/activate
python3 dashboard.py
```

**Browser**: Open http://localhost:5001

---

## Test Scenarios

### Test 1: SYN Flood Detection

**Objective**: Verify detection of TCP SYN flood attacks

#### Setup
```bash
# Terminal 1: Already running ddos_detector.py
# Terminal 2: Open a new terminal for the attack
```

#### Execution
```bash
# Terminal 2: Launch SYN flood
sudo hping3 -S --flood -p 80 127.0.0.1

# Explanation:
# -S         : Set SYN flag
# --flood    : Send packets as fast as possible
# -p 80      : Target port 80 (HTTP)
# 127.0.0.1  : Target localhost (self-test)
```

#### Expected Results

**Timeline**:
- **T+0s**: hping3 starts sending SYN packets
- **T+1-2s**: Detector shows increasing SYN count for 127.0.0.1
- **T+2-3s**: SYN threshold (50) exceeded
- **T+2-3s**: ALERT message appears: "SYN flood detected from 127.0.0.1"
- **T+2-3s**: MITIGATION message: "Blocking IP 127.0.0.1"
- **T+3s**: hping3 may freeze or show reduced rate

**Terminal 1 Output Example**:
```
Starting packet sniffer...
IP Packet: 127.0.0.1 -> 127.0.0.1 (Proto: 6)
  TCP Packet: 127.0.0.1:54321 -> 127.0.0.1:80 (Flags: S)
...
ALERT: SYN flood detected from 127.0.0.1 (Count: 68)
MITIGATION: Blocking IP 127.0.0.1
Successfully blocked 127.0.0.1
```

**Web Dashboard**:
- Traffic graph shows spike
- "127.0.0.1" appears in "Blocked IPs" list
- Statistics update in real-time

#### Verification

**Step 1: Check iptables rule**
```bash
# Terminal 3: New terminal
sudo iptables -L INPUT -n -v

# Expected output:
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source          destination
  342 17100 DROP       all  --  *      *       127.0.0.1       0.0.0.0/0
```

**Step 2: Check logs**
```bash
# Check attack log
tail -n 20 logs/ddos_attacks.log

# Expected entry:
2024-11-08 10:23:45 - WARNING - Attack detected: SYN_FLOOD from 127.0.0.1 (68 packets)
2024-11-08 10:23:45 - WARNING - IP 127.0.0.1 has been blocked
```

**Step 3: Verify JSON log**
```bash
# View structured log
cat logs/ddos_events.json | jq '.' | tail -n 20

# Expected structure:
{
  "timestamp": "2024-11-08T10:23:45",
  "event_type": "ATTACK_DETECTED",
  "attack_type": "SYN_FLOOD",
  "source_ip": "127.0.0.1",
  "packet_count": 68,
  "action": "BLOCKED"
}
```

#### Cleanup

```bash
# Stop hping3 (Ctrl+C in Terminal 2)

# Unblock IP for next test
sudo ./scripts/unblock_all.sh

# Restart detector (Ctrl+C in Terminal 1, then restart)
sudo venv/bin/python3 ddos_detector.py
```

---

### Test 2: Packet Flood Detection

**Objective**: Verify detection of general packet flooding

#### Setup
```bash
# Use the custom attack simulator
cd ~/pydos
```

#### Execution
```bash
# Terminal 2: Launch packet flood
sudo venv/bin/python3 scripts/simulate_attack.py \
    --target 127.0.0.1 \
    --type packet \
    --count 200 \
    --rate 100

# Explanation:
# --target    : Target IP address
# --type      : Attack type (packet, syn, udp)
# --count     : Total packets to send
# --rate      : Packets per second
```

#### Expected Results

**Terminal 1 Output**:
```
ALERT: Packet threshold exceeded from 127.0.0.1 (Count: 112)
MITIGATION: Blocking IP 127.0.0.1
Successfully blocked 127.0.0.1
```

**Detection Time**: Should occur within 2-3 seconds

#### Verification

Same as Test 1, but log shows "PACKET_FLOOD" instead of "SYN_FLOOD"

---

### Test 3: UDP Flood Detection

**Objective**: Test detection of UDP-based attacks

#### Execution
```bash
# Terminal 2: UDP flood with hping3
sudo hping3 --udp --flood -p 53 127.0.0.1

# Explanation:
# --udp      : Use UDP protocol
# --flood    : Maximum speed
# -p 53      : Target DNS port
```

#### Expected Results

**Terminal 1 Output**:
```
IP Packet: 127.0.0.1 -> 127.0.0.1 (Proto: 17)
  UDP Packet: 127.0.0.1:54321 -> 127.0.0.1:53
...
ALERT: Packet threshold exceeded from 127.0.0.1 (Count: 115)
MITIGATION: Blocking IP 127.0.0.1
```

**Note**: UDP flood triggers PACKET_FLOOD rule (not SYN-specific)

---

### Test 4: Multi-Source Attack

**Objective**: Test handling of attacks from multiple IPs

#### Setup

This requires multiple machines or IP spoofing (advanced).

**Simple Approach**: Use Docker containers or VMs

```bash
# From another machine on your network:
sudo hping3 -S --flood -p 80 <your-vm-ip>
```

#### Expected Results

Each unique source IP should be:
- Tracked independently
- Blocked when it exceeds thresholds
- Logged separately

**Verification**:
```bash
sudo iptables -L INPUT -n -v
# Should show multiple DROP rules (one per attacker IP)
```

---

### Test 5: Legitimate Traffic (False Positive Test)

**Objective**: Verify system doesn't block normal traffic

#### Execution

**Method 1: Web Browsing**
```bash
# From the Ubuntu VM browser, visit websites
firefox google.com
# Browse normally, open multiple tabs
```

**Method 2: File Download**
```bash
# Download a large file
wget https://releases.ubuntu.com/22.04/ubuntu-22.04-desktop-amd64.iso
```

**Method 3: Ping Test**
```bash
# Continuous ping (generates steady traffic)
ping -c 100 8.8.8.8
```

#### Expected Results

**✅ PASS Criteria**:
- No ALERT messages in detector
- No IPs blocked
- Traffic appears in dashboard but stays below thresholds
- Normal count: 10-50 packets per 5 seconds

**❌ FAIL Criteria** (indicates false positive):
- Legitimate traffic triggers alerts
- Own IP gets blocked
- Normal downloads interrupted

**If Test Fails**: Increase `PACKET_THRESHOLD` in `ddos_detector.py`:
```python
PACKET_THRESHOLD = 200  # Increase from 100
```

---

### Test 6: Threshold Boundary Testing

**Objective**: Verify thresholds are accurate

#### Test 6.1: Just Below Threshold

```bash
# Send exactly 49 SYN packets (threshold is 50)
for i in {1..49}; do 
    sudo hping3 -S -c 1 -p 80 127.0.0.1
    sleep 0.1
done
```

**Expected**: No alert (below threshold)

#### Test 6.2: Just Above Threshold

```bash
# Send exactly 51 SYN packets
for i in {1..51}; do 
    sudo hping3 -S -c 1 -p 80 127.0.0.1
    sleep 0.1
done
```

**Expected**: Alert triggered at packet 51

---

### Test 7: Time Window Reset

**Objective**: Verify 5-second window resets work

#### Execution

```bash
# Terminal 2: Send 30 SYN packets (below threshold)
for i in {1..30}; do 
    sudo hping3 -S -c 1 -p 80 127.0.0.1
    sleep 0.1
done

# Wait 6 seconds (window resets)
sleep 6

# Send another 30 SYN packets
for i in {1..30}; do 
    sudo hping3 -S -c 1 -p 80 127.0.0.1
    sleep 0.1
done
```

#### Expected Results

- First 30 packets: No alert (below 50 threshold)
- Window resets after 5 seconds
- Next 30 packets: No alert (counter was reset)
- **Total 60 packets, but never blocked** ✅

**If this test FAILS**: The time window is not working properly

---

### Test 8: Concurrent Dashboard Access

**Objective**: Test web dashboard under load

#### Execution

```bash
# Terminal 3: Generate traffic while viewing dashboard
while true; do 
    curl http://localhost:5001/api/stats
    sleep 1
done
```

**Browser**: Keep refreshing http://localhost:5001

#### Expected Results

- Dashboard responds quickly (< 100ms)
- No errors in Flask console
- Real-time updates work smoothly
- No memory leaks (check with `htop`)

---

## Screenshot Checklist

### Required Screenshots for Project Report

#### Screenshot 1: Clean System State
**Filename**: `01_clean_state.png`  
**Content**:
- Terminal showing `sudo iptables -L -n -v`
- Empty chains (no DROP rules)
- **Caption**: "Initial firewall state before testing"

#### Screenshot 2: System Running
**Filename**: `02_system_running.png`  
**Content**:
- Terminal 1: ddos_detector.py with "Starting packet sniffer..." message
- Show CLI dashboard with empty or minimal traffic
- **Caption**: "DDoS detection system operational"

#### Screenshot 3: Attack in Progress
**Filename**: `03_attack_launched.png`  
**Content**:
- Terminal 2: hping3 command running
- Show rapid packet sending
- **Caption**: "SYN flood attack simulation with hping3"

#### Screenshot 4: Attack Detected
**Filename**: `04_attack_detected.png`  
**Content**:
- Terminal 1: ALERT and MITIGATION messages highlighted
- Show actual packet counts and IP address
- **Caption**: "Real-time attack detection and automated response"

#### Screenshot 5: CLI Dashboard During Attack
**Filename**: `05_cli_dashboard.png`  
**Content**:
- Rich table showing IP with high packet count
- Color-coded status (red for attack)
- **Caption**: "CLI dashboard showing attack traffic"

#### Screenshot 6: Web Dashboard
**Filename**: `06_web_dashboard.png`  
**Content**:
- Browser showing http://localhost:5001
- Traffic graph with spike
- Blocked IPs list showing attacker
- **Caption**: "Web-based monitoring interface"

#### Screenshot 7: Firewall Rule Verification
**Filename**: `07_firewall_rules.png`  
**Content**:
- Terminal showing `sudo iptables -L -n -v`
- DROP rule for attacker IP
- Packet counter showing blocked packets
- **Caption**: "Firewall rule created by mitigation module"

#### Screenshot 8: Log Files
**Filename**: `08_log_verification.png`  
**Content**:
- Terminal showing `tail logs/ddos_attacks.log`
- Attack entries with timestamps
- **Caption**: "Attack event logging for forensic analysis"

#### Screenshot 9: JSON Structured Logs
**Filename**: `09_json_logs.png`  
**Content**:
- Terminal showing `cat logs/ddos_events.json | jq`
- Pretty-printed JSON with attack details
- **Caption**: "Structured logging for programmatic analysis"

#### Screenshot 10: Performance Metrics
**Filename**: `10_performance.png`  
**Content**:
- Terminal showing `htop` or `top` with system running
- CPU and memory usage highlighted
- **Caption**: "System resource utilization during operation"

### How to Take Screenshots

**Ubuntu Screenshot Tool**:
```bash
# Full screen
gnome-screenshot

# Select area
gnome-screenshot -a

# With delay (5 seconds)
gnome-screenshot -d 5
```

**Alternative (Shutter)**:
```bash
sudo apt install shutter
shutter
```

**Tips**:
- Use high resolution (1920x1080 minimum)
- Ensure text is readable
- Highlight important parts with arrows/boxes
- Save in PNG format for clarity
- Name files systematically

---

## Verification Procedures

### 1. Detection Accuracy Verification

**Checklist**:
- [ ] True Positive: Attack detected correctly ✅
- [ ] True Negative: Normal traffic not flagged ✅
- [ ] False Positive Rate: < 5% ✅
- [ ] False Negative Rate: < 1% ✅

**How to Calculate**:
```python
# Test with 100 attack packets
attacks_detected = 100  # Count from logs
total_attacks = 100

accuracy = (attacks_detected / total_attacks) * 100
print(f"Detection Accuracy: {accuracy}%")
```

### 2. Mitigation Effectiveness

**Test**:
```bash
# After blocking, try to connect
ping -c 5 <blocked-ip>  # Should fail or timeout
```

**Verification**:
```bash
# Check packet counter increases
sudo iptables -L INPUT -n -v
# pkts column should increase (packets are being dropped)
```

### 3. Performance Benchmarking

**CPU Usage**:
```bash
# Monitor during attack
top -p $(pgrep -f ddos_detector)

# Expected: < 50% CPU usage
```

**Memory Usage**:
```bash
# Check memory footprint
ps aux | grep ddos_detector

# Expected: < 500 MB RAM
```

**Packet Processing Rate**:
```bash
# Count packets processed
# Compare with packets sent by attacker
# Expected: > 1000 packets/second
```

### 4. Log Integrity Check

**Verify Timestamps**:
```bash
# Check log timestamps are sequential
grep "ATTACK" logs/ddos_events.log | awk '{print $1, $2}'

# All entries should be in chronological order
```

**Verify JSON Format**:
```bash
# Validate JSON syntax
cat logs/ddos_events.json | jq empty

# No output = valid JSON
# Error message = corrupted JSON
```

### 5. Dashboard Responsiveness

**Load Test**:
```bash
# Use Apache Bench (install first)
sudo apt install apache2-utils

# Send 100 requests
ab -n 100 -c 10 http://localhost:5001/api/stats

# Check "Requests per second" metric
# Expected: > 50 requests/second
```

---

## Performance Testing

### Test 1: Maximum Throughput

**Objective**: Determine maximum packets/second the system can handle

#### Execution
```bash
# Gradually increase attack rate
sudo hping3 -S --flood -p 80 127.0.0.1
# Monitor with: watch -n 1 'sudo iptables -L INPUT -n -v'
```

#### Metrics to Record
- Packets/second processed
- CPU usage (%)
- Memory usage (MB)
- Detection delay (seconds)

### Test 2: Sustained Load

**Objective**: Test system stability under prolonged attack

#### Execution
```bash
# Run attack for 10 minutes
timeout 600 sudo hping3 -S --flood -p 80 127.0.0.1
```

#### Metrics to Record
- System remains responsive ✅
- No memory leaks ✅
- Logs continue writing ✅
- Dashboard updates continue ✅

### Test 3: Multi-Vector Attack

**Objective**: Test handling of simultaneous attack types

#### Execution
```bash
# Terminal 2: SYN flood
sudo hping3 -S --flood -p 80 127.0.0.1 &

# Terminal 3: UDP flood
sudo hping3 --udp --flood -p 53 127.0.0.1 &

# Terminal 4: ICMP flood
sudo hping3 --icmp --flood 127.0.0.1 &
```

#### Expected Results
- All attack types detected ✅
- Single IP blocked once (not multiple times) ✅
- System remains stable ✅

---

## Troubleshooting

### Issue 1: No Packets Captured

**Symptoms**: Detector runs but shows no traffic

**Diagnosis**:
```bash
# Check interface name
ip a

# Verify traffic exists
sudo tcpdump -i enp0s3 -c 10
```

**Solution**:
```python
# Edit ddos_detector.py
sniff(iface="YOUR_INTERFACE_NAME", prn=process_packet, store=0)
```

### Issue 2: Permission Denied

**Symptoms**: "Operation not permitted" when blocking IP

**Solution**:
```bash
# Always use sudo
sudo venv/bin/python3 ddos_detector.py
```

### Issue 3: False Positives

**Symptoms**: Legitimate traffic triggers alerts

**Solution**:
```python
# Increase thresholds in ddos_detector.py
PACKET_THRESHOLD = 200  # Was 100
SYN_THRESHOLD = 100     # Was 50
```

### Issue 4: Attack Not Detected

**Symptoms**: Attack runs but no alerts

**Diagnosis**:
```bash
# Check if packets are being counted
# Add print statement in process_packet()
```

**Possible Causes**:
- Wrong interface name
- Thresholds too high
- Time window resetting too frequently
- Lock preventing count updates

### Issue 5: Dashboard Shows No Data

**Symptoms**: Web dashboard is blank

**Solution**:
```bash
# Check if stats.json exists
ls -lh stats.json

# Check Flask is running
ps aux | grep dashboard.py

# Check Flask logs for errors
python3 dashboard.py
# Look for error messages
```

### Issue 6: iptables Rules Don't Persist

**Symptoms**: Rules disappear after reboot

**Solution**:
```bash
# Save rules permanently
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

---

## Test Results Template

### Test Execution Summary

| Test ID | Test Name | Status | Detection Time | Notes |
|---------|-----------|--------|----------------|-------|
| T1 | SYN Flood | ✅ PASS | 1.8s | 68 packets before block |
| T2 | Packet Flood | ✅ PASS | 2.3s | 112 packets before block |
| T3 | UDP Flood | ✅ PASS | 2.1s | 105 packets before block |
| T4 | Multi-Source | ✅ PASS | 2.0s avg | 3 IPs blocked |
| T5 | Legitimate Traffic | ✅ PASS | N/A | 0 false positives |
| T6 | Threshold Boundary | ✅ PASS | Exact | Accurate at 50/51 |
| T7 | Time Window Reset | ✅ PASS | 5.0s | Counter reset correctly |
| T8 | Dashboard Load | ✅ PASS | < 100ms | Smooth updates |

### Performance Metrics

| Metric | Measured Value | Target | Status |
|--------|---------------|--------|--------|
| Detection Time | 1.8s avg | < 5s | ✅ PASS |
| Throughput | 1200 pkt/s | > 1000 pkt/s | ✅ PASS |
| CPU Usage | 12% | < 50% | ✅ PASS |
| Memory Usage | 85 MB | < 500 MB | ✅ PASS |
| False Positive Rate | 0% | < 5% | ✅ PASS |

---

## Conclusion

This testing guide provides comprehensive procedures to validate all aspects of the DDoS Detection System. Follow each test scenario, take required screenshots, and document results in your project report.

**Key Success Indicators**:
- ✅ All attacks detected within 5 seconds
- ✅ Zero false positives with legitimate traffic
- ✅ Firewall rules created correctly
- ✅ Logs written accurately
- ✅ Dashboards update in real-time
- ✅ System remains stable under load

Good luck with your testing! 🚀

---

**Document Version**: 1.0  
**Last Updated**: November 8, 2025  
**Next Review**: After Phase 5 Testing Complete
