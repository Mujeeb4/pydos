# Mitigation Module Documentation

## Overview

The Mitigation Module (`mitigator.py`) is responsible for automatically blocking malicious IP addresses using the Linux iptables firewall. It provides the "response" capability of the DDoS detection system.

## Core Functionality

### 1. IP Blocking Mechanism

The module integrates with Linux iptables to drop packets from malicious sources:

```python
class Mitigator:
    def block_ip(self, ip_address: str) -> bool:
        """Block an IP address using iptables"""
        command = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        subprocess.run(command, check=True)
```

### 2. Key Features

#### A. Thread-Safe Operations

```python
def __init__(self):
    self.blocked_ips: Set[str] = set()
    self.lock = threading.Lock()

def block_ip(self, ip_address: str) -> bool:
    with self.lock:
        # Thread-safe blocking operation
        if ip_address in self.blocked_ips:
            return False  # Already blocked
        
        self.blocked_ips.add(ip_address)
        # Execute iptables command
```

**Why Thread Safety?**
- Multiple packets may trigger blocking simultaneously
- Prevents duplicate iptables rules
- Ensures consistent state tracking

#### B. Idempotent Blocking

```python
def block_ip(self, ip_address: str) -> bool:
    # Check if already blocked
    if ip_address in self.blocked_ips:
        logger.info(f"IP {ip_address} already blocked")
        return False
    
    # Block only if not already blocked
    self._execute_iptables_block(ip_address)
    self.blocked_ips.add(ip_address)
    return True
```

**Benefits**:
- Safe to call multiple times
- No duplicate firewall rules
- Prevents iptables errors

#### C. Automatic Unblocking

```python
def __init__(self, block_duration_minutes: int = 60):
    self.block_duration = timedelta(minutes=block_duration_minutes)
    self.blocked_ips_timestamps: Dict[str, datetime] = {}
    
    # Start cleanup thread
    self.cleanup_thread = threading.Thread(
        target=self._cleanup_expired_blocks,
        daemon=True
    )
    self.cleanup_thread.start()

def _cleanup_expired_blocks(self):
    """Background thread to remove expired blocks"""
    while self.cleanup_running:
        time.sleep(60)  # Check every minute
        
        current_time = datetime.now()
        with self.lock:
            expired_ips = [
                ip for ip, blocked_time in self.blocked_ips_timestamps.items()
                if current_time - blocked_time > self.block_duration
            ]
            
            for ip in expired_ips:
                self.unblock_ip(ip)
```

**Configuration**:
- Default duration: 60 minutes
- Configurable per instance
- Automatic cleanup every 60 seconds

## iptables Integration

### Firewall Rule Structure

#### Block Command
```bash
iptables -A INPUT -s 192.168.1.100 -j DROP
```

**Breakdown**:
- `-A INPUT`: Append to INPUT chain (incoming packets)
- `-s 192.168.1.100`: Source IP address to match
- `-j DROP`: Jump to DROP target (silently discard)

#### Unblock Command
```bash
iptables -D INPUT -s 192.168.1.100 -j DROP
```

**Breakdown**:
- `-D INPUT`: Delete from INPUT chain
- Same matching criteria as block command

### Rule Verification

```python
def is_ip_blocked(self, ip_address: str) -> bool:
    """Check if IP is currently blocked in iptables"""
    try:
        # List all iptables rules
        result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n"],
            capture_output=True,
            text=True
        )
        
        # Search for IP in output
        return ip_address in result.stdout
    except subprocess.CalledProcessError:
        return False
```

### Platform Compatibility

```python
def _check_iptables_available(self) -> bool:
    """Check if iptables is available on system"""
    try:
        subprocess.run(
            ["which", "iptables"],
            capture_output=True,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("iptables not available - blocking disabled")
        return False
```

**Platform Support**:
- ✅ Linux (all distributions)
- ❌ Windows (iptables not available)
- ❌ macOS (uses pf firewall instead)

**Fallback Behavior**:
- Log blocking attempts without executing
- Continue detection without mitigation
- Notify user of platform limitation

## Block Management

### Adding Blocks

```python
def block_ip(self, ip_address: str, reason: str = "DDoS attack") -> bool:
    """
    Block an IP address with logging and validation.
    
    Args:
        ip_address: The IP to block
        reason: Reason for blocking (for logs)
        
    Returns:
        bool: True if blocked successfully, False if already blocked
    """
    # Validate IP format
    if not self._is_valid_ip(ip_address):
        logger.error(f"Invalid IP address: {ip_address}")
        return False
    
    # Check if already blocked
    with self.lock:
        if ip_address in self.blocked_ips:
            return False
        
        # Execute iptables command
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            
            # Track in memory
            self.blocked_ips.add(ip_address)
            self.blocked_ips_timestamps[ip_address] = datetime.now()
            
            # Log the action
            logger.warning(f"Blocked IP {ip_address}: {reason}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip_address}: {e}")
            return False
```

### Removing Blocks

```python
def unblock_ip(self, ip_address: str) -> bool:
    """
    Unblock a previously blocked IP address.
    
    Args:
        ip_address: The IP to unblock
        
    Returns:
        bool: True if unblocked successfully
    """
    with self.lock:
        if ip_address not in self.blocked_ips:
            logger.warning(f"IP {ip_address} not in blocked list")
            return False
        
        try:
            # Remove iptables rule
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            
            # Remove from tracking
            self.blocked_ips.remove(ip_address)
            if ip_address in self.blocked_ips_timestamps:
                del self.blocked_ips_timestamps[ip_address]
            
            logger.info(f"Unblocked IP {ip_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock {ip_address}: {e}")
            return False
```

### Bulk Operations

```python
def unblock_all(self) -> int:
    """
    Remove all blocks created by this instance.
    
    Returns:
        int: Number of IPs unblocked
    """
    count = 0
    with self.lock:
        ips_to_unblock = list(self.blocked_ips)
    
    for ip in ips_to_unblock:
        if self.unblock_ip(ip):
            count += 1
    
    logger.info(f"Unblocked {count} IP addresses")
    return count

def get_blocked_ips(self) -> List[str]:
    """
    Get list of currently blocked IPs.
    
    Returns:
        List of blocked IP addresses
    """
    with self.lock:
        return list(self.blocked_ips)
```

## Safety Mechanisms

### 1. IP Validation

```python
def _is_valid_ip(self, ip_address: str) -> bool:
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False
```

### 2. Self-Protection

```python
def _is_local_ip(self, ip_address: str) -> bool:
    """Check if IP is local/loopback"""
    import ipaddress
    ip = ipaddress.ip_address(ip_address)
    return ip.is_loopback or ip.is_private

def block_ip(self, ip_address: str) -> bool:
    # Don't block local IPs in production
    if not TESTING_MODE and self._is_local_ip(ip_address):
        logger.warning(f"Refusing to block local IP: {ip_address}")
        return False
    
    # Proceed with blocking
```

### 3. Whitelist Protection

```python
def __init__(self, whitelist: List[str] = None):
    self.whitelist = set(whitelist or [])
    # Add critical IPs
    self.whitelist.add("127.0.0.1")  # localhost
    self.whitelist.add("::1")         # IPv6 localhost

def block_ip(self, ip_address: str) -> bool:
    if ip_address in self.whitelist:
        logger.warning(f"IP {ip_address} is whitelisted - not blocking")
        return False
    
    # Proceed with blocking
```

### 4. Resource Limits

```python
MAX_BLOCKED_IPS = 10000

def block_ip(self, ip_address: str) -> bool:
    if len(self.blocked_ips) >= MAX_BLOCKED_IPS:
        logger.error("Maximum blocked IPs limit reached")
        return False
    
    # Proceed with blocking
```

## Error Handling

### Permission Errors

```python
try:
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
except subprocess.CalledProcessError as e:
    if "Permission denied" in str(e):
        logger.error("iptables requires root/sudo privileges")
    else:
        logger.error(f"iptables error: {e}")
```

**Solution**: Run with sudo
```bash
sudo python3 src/ddos_detector.py
```

### Duplicate Rule Errors

```python
# iptables errors if rule already exists
# Our idempotent design prevents this:

if ip_address in self.blocked_ips:
    return False  # Already blocked, skip iptables call
```

### iptables Not Found

```python
def __init__(self):
    self.iptables_available = self._check_iptables_available()

def block_ip(self, ip_address: str) -> bool:
    if not self.iptables_available:
        logger.warning("iptables not available - simulating block")
        self.blocked_ips.add(ip_address)  # Track only
        return True
    
    # Actual blocking
```

## Performance Considerations

### Memory Usage

```python
# Per blocked IP: ~100 bytes
# 1000 blocked IPs: ~100 KB
# 10000 blocked IPs: ~1 MB

# Tracking structures:
blocked_ips: Set[str]              # ~50 bytes per IP
blocked_ips_timestamps: Dict       # ~100 bytes per IP
```

### iptables Performance

| Blocked IPs | Rule Lookup Time | Memory Impact |
|-------------|------------------|---------------|
| 100 | <1ms | Negligible |
| 1,000 | ~2ms | ~100KB |
| 10,000 | ~10ms | ~1MB |
| 100,000 | ~100ms | ~10MB |

**Recommendation**: Keep under 10,000 rules for optimal performance

### Optimization Strategies

1. **Periodic Cleanup**: Remove expired blocks
2. **Whitelist Common IPs**: Reduce rule evaluation
3. **Use ipset**: For large blocklists (future enhancement)

```bash
# Future: Use ipset for better performance
ipset create blocklist hash:ip
ipset add blocklist 192.168.1.100
iptables -A INPUT -m set --match-set blocklist src -j DROP
```

## Logging Integration

### Block Events

```python
def block_ip(self, ip_address: str) -> bool:
    # Log to attack log
    logger.critical(f"BLOCKED: {ip_address}")
    
    # Structured logging
    log_event = {
        "timestamp": datetime.now().isoformat(),
        "event": "ip_blocked",
        "ip": ip_address,
        "reason": "DDoS attack detected",
        "duration": f"{self.block_duration.seconds // 60} minutes"
    }
    
    with open("logs/ddos_events.json", "a") as f:
        json.dump(log_event, f)
        f.write("\n")
```

### Unblock Events

```python
def unblock_ip(self, ip_address: str) -> bool:
    logger.info(f"UNBLOCKED: {ip_address}")
    
    # Calculate block duration
    if ip_address in self.blocked_ips_timestamps:
        blocked_time = self.blocked_ips_timestamps[ip_address]
        duration = datetime.now() - blocked_time
        logger.info(f"IP was blocked for {duration.seconds // 60} minutes")
```

## Testing the Mitigator

### Unit Tests

```python
def test_block_ip():
    """Test basic IP blocking"""
    mitigator = Mitigator()
    
    # Should block successfully
    assert mitigator.block_ip("192.168.1.100") == True
    
    # Should not block duplicate
    assert mitigator.block_ip("192.168.1.100") == False
    
    # Should be in blocked list
    assert "192.168.1.100" in mitigator.get_blocked_ips()

def test_unblock_ip():
    """Test IP unblocking"""
    mitigator = Mitigator()
    mitigator.block_ip("192.168.1.100")
    
    # Should unblock successfully
    assert mitigator.unblock_ip("192.168.1.100") == True
    
    # Should not be blocked anymore
    assert "192.168.1.100" not in mitigator.get_blocked_ips()
```

### Integration Tests

```bash
# Start detector
sudo python3 src/ddos_detector.py

# Simulate attack (will trigger blocking)
sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --count 200

# Verify IP is blocked
sudo iptables -L INPUT -n | grep 127.0.0.1

# Manually unblock
sudo bash scripts/unblock_all.sh
```

### Manual iptables Testing

```bash
# Add block manually
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# List all rules
sudo iptables -L INPUT -n -v

# Remove block
sudo iptables -D INPUT -s 192.168.1.100 -j DROP

# Flush all rules (CAREFUL!)
sudo iptables -F INPUT
```

## Configuration Options

### Block Duration

```python
# Short duration (testing)
mitigator = Mitigator(block_duration_minutes=5)

# Medium duration (default)
mitigator = Mitigator(block_duration_minutes=60)

# Permanent blocking (until manual removal)
mitigator = Mitigator(block_duration_minutes=0)  # 0 = no auto-unblock
```

### Whitelist Configuration

```python
# Protect critical infrastructure
whitelist = [
    "192.168.1.1",    # Gateway
    "192.168.1.10",   # DNS server
    "8.8.8.8",        # Google DNS
]

mitigator = Mitigator(whitelist=whitelist)
```

## Troubleshooting

### Problem: Permission Denied

```
Error: iptables requires root privileges
```

**Solution**:
```bash
sudo python3 src/ddos_detector.py
```

### Problem: Rules Not Persisting

```
Blocked IPs return after reboot
```

**Solution**:
```bash
# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4

# Restore on boot (systemd)
sudo systemctl enable iptables
```

### Problem: Legitimate Traffic Blocked

```
User complains about access denied
```

**Solutions**:
1. Check if IP in blocked list: `mitigator.get_blocked_ips()`
2. Manually unblock: `mitigator.unblock_ip("x.x.x.x")`
3. Add to whitelist
4. Increase detection thresholds

### Problem: iptables Rules Accumulate

```
Too many iptables rules
```

**Solution**:
```bash
# Use cleanup script
sudo bash scripts/unblock_all.sh

# Or manually flush
sudo iptables -F INPUT
```

## Best Practices

### 1. Production Deployment

```python
# Disable testing mode
TESTING_MODE = False
ALLOW_LOOPBACK_DETECTION = False

# Set reasonable duration
mitigator = Mitigator(block_duration_minutes=60)

# Configure whitelist
whitelist = load_whitelist_from_config()
mitigator = Mitigator(whitelist=whitelist)
```

### 2. Monitoring

```python
# Regular health checks
def check_mitigation_health():
    blocked_count = len(mitigator.get_blocked_ips())
    
    if blocked_count > 1000:
        logger.warning(f"High block count: {blocked_count}")
    
    # Check iptables sync
    for ip in mitigator.get_blocked_ips():
        if not mitigator.is_ip_blocked(ip):
            logger.error(f"Desync detected for {ip}")
```

### 3. Backup and Recovery

```bash
# Backup current rules
sudo iptables-save > iptables_backup.txt

# Restore if needed
sudo iptables-restore < iptables_backup.txt
```

### 4. Logging

```python
# Log all mitigation actions
logger.info(f"Blocked {ip} - Attack type: {attack_type}")
logger.info(f"Total blocked IPs: {len(blocked_ips)}")
logger.info(f"Block will expire at: {expiry_time}")
```

## Future Enhancements

### 1. ipset Integration

```python
# More efficient for large blocklists
class IpsetMitigator(Mitigator):
    def __init__(self):
        subprocess.run(["ipset", "create", "blocklist", "hash:ip"])
    
    def block_ip(self, ip: str):
        subprocess.run(["ipset", "add", "blocklist", ip])
```

### 2. Geographic Blocking

```python
# Block entire countries
def block_country(self, country_code: str):
    # Integrate with GeoIP database
    pass
```

### 3. Rate Limiting

```python
# Instead of complete block, rate limit
def rate_limit_ip(self, ip: str, rate: str = "10/minute"):
    subprocess.run([
        "iptables", "-A", "INPUT",
        "-s", ip,
        "-m", "limit", "--limit", rate,
        "-j", "ACCEPT"
    ])
```

### 4. Distributed Blocking

```python
# Sync blocks across multiple servers
class DistributedMitigator(Mitigator):
    def block_ip(self, ip: str):
        super().block_ip(ip)
        self.broadcast_block_to_cluster(ip)
```

## Security Considerations

### Defense in Depth
- Mitigator is one layer of defense
- Combine with network-level protection
- Use alongside rate limiting, WAF, CDN

### Audit Trail
- All blocks logged
- Timestamps recorded
- Reasons documented

### False Positive Mitigation
- Whitelist critical services
- Gradual threshold increases
- Manual review capability

## References

- [iptables Documentation](https://www.netfilter.org/documentation/)
- [iptables Tutorial](https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html)
- [ipset for Performance](https://ipset.netfilter.org/)
- [Linux Firewall Best Practices](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using_firewalls)
