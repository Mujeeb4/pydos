# Security Documentation

## Overview

This document outlines security considerations, best practices, and potential vulnerabilities in the DDoS Detection System.

## Security Architecture

### Defense Layers

```
┌─────────────────────────────────────┐
│     Application Layer Security      │
│  - Input validation                 │
│  - Rate limiting                    │
│  - Authentication                   │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│    System Layer Security            │
│  - Process isolation                │
│  - Privilege separation             │
│  - File permissions                 │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│    Network Layer Security           │
│  - Firewall rules (iptables)        │
│  - Network segmentation             │
│  - Encrypted communications         │
└─────────────────────────────────────┘
```

## Privilege Requirements

### Why Root Access is Required

The system requires elevated privileges for:

1. **Packet Capture**: Raw socket access requires `CAP_NET_RAW` capability
2. **iptables Management**: Firewall modification requires `CAP_NET_ADMIN` capability

### Minimizing Privilege Exposure

#### Option 1: Run with sudo (Simple)

```bash
sudo python3 src/ddos_detector.py
```

**Pros**: Easy to set up
**Cons**: Full root access

#### Option 2: Capabilities (Recommended)

```bash
# Grant specific capabilities to Python binary
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

# Now run without sudo
python3 src/ddos_detector.py

# Remove capabilities when done
sudo setcap -r $(which python3)
```

**Pros**: Minimal privileges
**Cons**: Affects all Python scripts

#### Option 3: Dedicated Binary with Capabilities

```bash
# Copy Python binary
cp $(which python3) /opt/pydos/python3-ddos

# Grant capabilities to copy
sudo setcap cap_net_raw,cap_net_admin+eip /opt/pydos/python3-ddos

# Run with dedicated binary
/opt/pydos/python3-ddos src/ddos_detector.py
```

**Pros**: Isolated privileges
**Cons**: Maintenance overhead

#### Option 4: Dedicated User with Limited sudo

```bash
# Create dedicated user
sudo useradd -r -s /bin/bash ddos

# Grant limited sudo access
sudo visudo
# Add: ddos ALL=(ALL) NOPASSWD: /usr/sbin/iptables

# Run as dedicated user
sudo -u ddos python3 src/ddos_detector.py
```

## Input Validation

### IP Address Validation

```python
import ipaddress

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logger.error(f"Invalid IP address: {ip}")
        return False

def sanitize_ip(ip: str) -> str:
    """Sanitize and validate IP"""
    try:
        # This will raise ValueError if invalid
        ip_obj = ipaddress.ip_address(ip)
        return str(ip_obj)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")
```

### Command Injection Prevention

```python
# VULNERABLE - Never do this
def block_ip_vulnerable(ip: str):
    os.system(f"iptables -A INPUT -s {ip} -j DROP")  # ❌ Injection risk

# SAFE - Always use subprocess with list arguments
def block_ip_safe(ip: str):
    # Validate first
    if not validate_ip_address(ip):
        raise ValueError("Invalid IP")
    
    # Use list arguments (prevents injection)
    subprocess.run([
        "iptables", "-A", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ], check=True)  # ✅ Safe
```

### Parameter Validation

```python
def validate_threshold(value: int) -> bool:
    """Validate threshold value"""
    if not isinstance(value, int):
        return False
    if value < 1 or value > 10000:
        return False
    return True

def validate_time_window(value: float) -> bool:
    """Validate time window"""
    if not isinstance(value, (int, float)):
        return False
    if value < 0.1 or value > 300:
        return False
    return True
```

## Access Control

### Web Dashboard Authentication

#### Basic Authentication

```python
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash

auth = HTTPBasicAuth()

# Store hashed passwords
users = {
    "admin": generate_password_hash("secure_password_here")
}

@auth.verify_password
def verify_password(username, password):
    if username in users:
        return check_password_hash(users.get(username), password)
    return False

@app.route('/api/stats')
@auth.login_required
def get_stats():
    return jsonify(stats)
```

#### Token-Based Authentication

```python
import secrets
from functools import wraps
from flask import request, jsonify

# Generate secure API key
API_KEY = secrets.token_urlsafe(32)

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/stats')
@require_api_key
def get_stats():
    return jsonify(stats)
```

### IP Whitelisting

```python
ALLOWED_IPS = {
    "127.0.0.1",
    "192.168.1.0/24",
    "10.0.0.0/8"
}

def is_ip_allowed(ip: str) -> bool:
    """Check if IP is in whitelist"""
    ip_obj = ipaddress.ip_address(ip)
    
    for allowed in ALLOWED_IPS:
        if '/' in allowed:
            # CIDR notation
            if ip_obj in ipaddress.ip_network(allowed):
                return True
        else:
            # Single IP
            if ip_obj == ipaddress.ip_address(allowed):
                return True
    
    return False
```

## Secure Communication

### HTTPS for Web Dashboard

```python
from OpenSSL import SSL

# Generate self-signed certificate (for testing)
# openssl req -x509 -newkey rsa:4096 -nodes \
#   -keyout key.pem -out cert.pem -days 365

context = SSL.Context(SSL.TLSv1_2_METHOD)
context.use_privatekey_file('key.pem')
context.use_certificate_file('cert.pem')

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5001,
        ssl_context=context
    )
```

### Using Let's Encrypt (Production)

```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d ddos.example.com

# Use in Flask
# ssl_context=('/etc/letsencrypt/live/ddos.example.com/fullchain.pem',
#              '/etc/letsencrypt/live/ddos.example.com/privkey.pem')
```

## Data Protection

### Sensitive Data Handling

```python
# DON'T log sensitive information
logger.info(f"User {username} logged in with password {password}")  # ❌

# DO log only necessary information
logger.info(f"User {username} logged in successfully")  # ✅

# Sanitize logs
def sanitize_log_message(message: str) -> str:
    """Remove sensitive patterns from logs"""
    # Remove potential passwords
    message = re.sub(r'password["\s:=]+\w+', 'password=***', message, flags=re.IGNORECASE)
    # Remove API keys
    message = re.sub(r'api[_-]?key["\s:=]+\w+', 'api_key=***', message, flags=re.IGNORECASE)
    return message
```

### Log File Security

```bash
# Secure log directory
sudo chown -R ddos:ddos /var/log/ddos-detector
sudo chmod 750 /var/log/ddos-detector

# Secure individual log files
sudo chmod 640 /var/log/ddos-detector/*.log

# Prevent unauthorized access
sudo chattr +a /var/log/ddos-detector/ddos_attacks.log  # Append-only
```

### Configuration File Security

```bash
# Secure config file
chmod 600 config/config.py
chown ddos:ddos config/config.py

# Never commit sensitive config
echo "config/config_local.py" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore
```

## Vulnerability Mitigation

### 1. Denial of Service on the Detector Itself

**Risk**: Attacker floods the detector with packets

**Mitigation**:
```python
# Rate limiting for packet processing
class RateLimiter:
    def __init__(self, max_rate=10000):  # 10k packets/sec
        self.max_rate = max_rate
        self.counter = 0
        self.last_reset = time.time()
    
    def should_process(self) -> bool:
        now = time.time()
        if now - self.last_reset >= 1.0:
            self.counter = 0
            self.last_reset = now
        
        self.counter += 1
        return self.counter <= self.max_rate

limiter = RateLimiter(max_rate=10000)

def packet_handler(packet):
    if not limiter.should_process():
        return  # Drop packet processing
    
    # Normal processing
    process_packet(packet)
```

### 2. False Positives Leading to Legitimate Blocks

**Risk**: Legitimate traffic blocked incorrectly

**Mitigation**:
```python
# Whitelist critical IPs
CRITICAL_IPS = {
    "192.168.1.1",    # Gateway
    "8.8.8.8",        # DNS
    "company-server.local"
}

def should_block_ip(ip: str) -> bool:
    """Check if IP should be blocked"""
    # Never block critical infrastructure
    if ip in CRITICAL_IPS:
        logger.warning(f"Attempted to block critical IP: {ip}")
        return False
    
    # Never block private ranges in production
    if not TESTING_MODE:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            logger.warning(f"Attempted to block private IP: {ip}")
            return False
    
    return True
```

### 3. IP Spoofing Bypassing Detection

**Risk**: Attacker spoofs source IPs

**Mitigation**:
```python
# Enable reverse path filtering (OS level)
# sudo sysctl -w net.ipv4.conf.all.rp_filter=1

# Additional verification
def verify_ip_legitimacy(ip: str, packet) -> bool:
    """Additional checks for spoofed IPs"""
    # Check TTL (spoofed packets often have unusual TTL)
    if packet.haslayer(IP):
        ttl = packet[IP].ttl
        if ttl < 30 or ttl > 128:
            logger.warning(f"Suspicious TTL from {ip}: {ttl}")
            return False
    
    return True
```

### 4. Memory Exhaustion from Tracking Many IPs

**Risk**: Memory exhaustion from tracking thousands of IPs

**Mitigation**:
```python
MAX_TRACKED_IPS = 10000

def add_to_tracking(ip: str):
    """Add IP to tracking with limit"""
    if len(ip_packet_counts) >= MAX_TRACKED_IPS:
        # Remove oldest entries
        sorted_ips = sorted(
            ip_packet_counts.items(),
            key=lambda x: x[1]
        )
        # Remove bottom 10%
        for ip, _ in sorted_ips[:int(MAX_TRACKED_IPS * 0.1)]:
            del ip_packet_counts[ip]
    
    ip_packet_counts[ip] += 1
```

### 5. Log Injection Attacks

**Risk**: Attacker crafts malicious log entries

**Mitigation**:
```python
def sanitize_for_logging(value: str) -> str:
    """Sanitize value before logging"""
    # Remove newlines and special chars
    value = value.replace('\n', ' ').replace('\r', ' ')
    value = value.replace('\0', '')
    
    # Limit length
    if len(value) > 200:
        value = value[:200] + "..."
    
    return value

# Use sanitized logging
logger.info(f"Traffic from {sanitize_for_logging(src_ip)}")
```

## Security Monitoring

### Audit Logging

```python
class AuditLogger:
    """Separate logger for security events"""
    
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
        handler = RotatingFileHandler(
            'logs/security_audit.log',
            maxBytes=10*1024*1024,
            backupCount=10
        )
        self.logger.addHandler(handler)
    
    def log_security_event(self, event_type: str, details: dict):
        """Log security-relevant events"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details,
            "severity": self._get_severity(event_type)
        }
        self.logger.warning(json.dumps(event))
    
    def _get_severity(self, event_type: str) -> str:
        """Determine event severity"""
        if event_type in ['unauthorized_access', 'injection_attempt']:
            return 'CRITICAL'
        elif event_type in ['suspicious_ip', 'invalid_input']:
            return 'WARNING'
        return 'INFO'

# Usage
audit = AuditLogger()
audit.log_security_event('ip_blocked', {
    'ip': '192.168.1.100',
    'reason': 'DDoS attack'
})
```

### Intrusion Detection

```python
def detect_anomalies():
    """Detect suspicious patterns"""
    
    # Detect rapid blocking attempts
    if len(mitigator.blocked_ips) > 100:
        audit.log_security_event('mass_blocking', {
            'count': len(mitigator.blocked_ips)
        })
    
    # Detect repeated failed API requests
    if api_failed_requests > 50:
        audit.log_security_event('api_bruteforce', {
            'count': api_failed_requests
        })
```

## Compliance Considerations

### GDPR Compliance

```python
# Data minimization
def anonymize_ip(ip: str) -> str:
    """Anonymize IP for privacy (last octet)"""
    parts = ip.split('.')
    if len(parts) == 4:
        parts[-1] = '0'
    return '.'.join(parts)

# Data retention
def cleanup_old_data():
    """Remove data older than retention period"""
    retention_days = 30
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    
    # Remove old logs
    for log_file in Path('logs').glob('*.log.*'):
        if log_file.stat().st_mtime < cutoff_date.timestamp():
            log_file.unlink()
```

### Security Audit Trail

```python
def generate_security_report():
    """Generate security audit report"""
    report = {
        "report_date": datetime.now().isoformat(),
        "blocked_ips_count": len(mitigator.blocked_ips),
        "total_attacks": count_attacks(),
        "configuration": {
            "auto_blocking": ENABLE_AUTO_BLOCKING,
            "testing_mode": TESTING_MODE
        },
        "system_status": check_system_health()
    }
    
    with open('security_report.json', 'w') as f:
        json.dump(report, f, indent=2)
```

## Security Best Practices Checklist

### Deployment

- [ ] Run with minimum required privileges
- [ ] Use dedicated user account
- [ ] Secure file permissions (600 for config, 750 for directories)
- [ ] Enable firewall (ufw/iptables)
- [ ] Restrict dashboard access (localhost or VPN only)
- [ ] Use HTTPS for web dashboard
- [ ] Implement authentication
- [ ] Enable audit logging
- [ ] Set up log rotation
- [ ] Regular security updates

### Configuration

- [ ] Disable TESTING_MODE in production
- [ ] Set ALLOW_LOOPBACK_DETECTION = False in production
- [ ] Configure whitelist for critical IPs
- [ ] Use strong API keys/passwords
- [ ] Limit log file sizes
- [ ] Enable encrypted backups

### Monitoring

- [ ] Monitor for unauthorized access attempts
- [ ] Review logs regularly
- [ ] Alert on anomalous activity
- [ ] Track blocked IP count
- [ ] Monitor system resources
- [ ] Test recovery procedures

### Code Security

- [ ] Validate all inputs
- [ ] Use parameterized commands (no string concatenation)
- [ ] Sanitize log messages
- [ ] Handle errors securely
- [ ] Keep dependencies updated
- [ ] Code review security changes

## Incident Response

### Security Incident Procedure

1. **Detect**: Monitor for security events
2. **Contain**: Isolate affected systems
3. **Analyze**: Investigate root cause
4. **Eradicate**: Remove threat
5. **Recover**: Restore normal operations
6. **Document**: Record incident details

### Emergency Procedures

```bash
# If detector is compromised:

# 1. Stop service immediately
sudo systemctl stop ddos-detector.service

# 2. Backup evidence
cp -r /var/log/ddos-detector /backup/incident-$(date +%Y%m%d)
iptables-save > /backup/incident-$(date +%Y%m%d)/iptables.rules

# 3. Flush all iptables rules
sudo iptables -F INPUT

# 4. Investigate logs
grep "suspicious\|unauthorized\|error" /var/log/ddos-detector/*.log

# 5. Update and restart (after fixing issue)
git pull
sudo systemctl start ddos-detector.service
```

## Security Contact

For security issues:
1. Do not open public GitHub issues
2. Email: security@yourdomain.com
3. Use PGP key (if available)
4. Provide detailed information

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [iptables Security](https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO.html)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)
