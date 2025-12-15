# API Reference Documentation

## Overview

The DDoS Detection System provides a RESTful API through the Flask-based web dashboard, enabling programmatic access to system statistics, logs, and monitoring data.

## Base URL

```
http://localhost:5001
```

## Authentication

Currently, the API does not require authentication. For production use, implement authentication:

```python
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    # Implement your authentication logic
    return True
```

## Endpoints

### 1. Health Check

Check if the API server is running and healthy.

#### Request

```http
GET /health
```

#### Response

**Status Code**: 200 OK

```json
{
  "status": "healthy",
  "uptime": "01:23:45",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:45.123456"
}
```

**Status Values**:
- `healthy`: System operating normally
- `degraded`: Some components not functioning
- `unhealthy`: System experiencing issues

#### Example

```bash
curl http://localhost:5001/health
```

```python
import requests
response = requests.get('http://localhost:5001/health')
print(response.json())
```

---

### 2. System Statistics

Get current system statistics and metrics.

#### Request

```http
GET /api/stats
```

#### Response

**Status Code**: 200 OK

```json
{
  "total_packets": 1234,
  "unique_ips": 45,
  "blocked_ips": 2,
  "attacks_detected": 5,
  "timestamp": "2024-01-15T10:30:45.123456",
  "uptime_seconds": 5025,
  "detector_status": "running",
  "mitigator_status": "enabled"
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `total_packets` | integer | Total packets processed |
| `unique_ips` | integer | Number of unique source IPs |
| `blocked_ips` | integer | Currently blocked IP count |
| `attacks_detected` | integer | Total attacks detected |
| `timestamp` | string (ISO 8601) | Data timestamp |
| `uptime_seconds` | integer | System uptime in seconds |
| `detector_status` | string | Detection engine status |
| `mitigator_status` | string | Mitigation system status |

#### Example

```bash
curl http://localhost:5001/api/stats
```

```python
import requests

response = requests.get('http://localhost:5001/api/stats')
stats = response.json()

print(f"Total packets: {stats['total_packets']}")
print(f"Blocked IPs: {stats['blocked_ips']}")
```

---

### 3. Recent Logs

Retrieve recent log entries with optional filtering.

#### Request

```http
GET /api/logs?limit=50&level=WARNING
```

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 100 | Maximum number of log entries |
| `level` | string | No | All | Filter by log level |

**Valid Log Levels**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

#### Response

**Status Code**: 200 OK

```json
{
  "logs": [
    {
      "timestamp": "2024-01-15T10:30:45.123456",
      "level": "CRITICAL",
      "message": "Attack detected from 192.168.1.100",
      "source_ip": "192.168.1.100",
      "attack_type": "SYN_FLOOD"
    },
    {
      "timestamp": "2024-01-15T10:30:30.123456",
      "level": "WARNING",
      "message": "High traffic from 192.168.1.50",
      "source_ip": "192.168.1.50"
    }
  ],
  "count": 2,
  "total_available": 150
}
```

#### Example

```bash
# Get last 50 warnings or higher
curl "http://localhost:5001/api/logs?limit=50&level=WARNING"

# Get all critical logs
curl "http://localhost:5001/api/logs?level=CRITICAL"
```

```python
import requests

response = requests.get(
    'http://localhost:5001/api/logs',
    params={'limit': 50, 'level': 'WARNING'}
)

for log in response.json()['logs']:
    print(f"{log['timestamp']}: {log['message']}")
```

---

### 4. Traffic Data

Get current traffic information for all monitored IPs.

#### Request

```http
GET /api/traffic
```

#### Response

**Status Code**: 200 OK

```json
{
  "current": {
    "192.168.1.100": {
      "packets": 150,
      "syn_packets": 75,
      "udp_packets": 20,
      "icmp_packets": 5,
      "blocked": true,
      "status": "ATTACK"
    },
    "192.168.1.50": {
      "packets": 45,
      "syn_packets": 20,
      "udp_packets": 15,
      "icmp_packets": 10,
      "blocked": false,
      "status": "NORMAL"
    }
  },
  "timestamp": "2024-01-15T10:30:45.123456",
  "total_ips": 2
}
```

**Status Values**:
- `NORMAL`: Below threshold
- `WARNING`: Approaching threshold (50-99%)
- `ATTACK`: Threshold exceeded

#### Example

```bash
curl http://localhost:5001/api/traffic
```

```python
import requests

response = requests.get('http://localhost:5001/api/traffic')
traffic = response.json()

for ip, data in traffic['current'].items():
    print(f"{ip}: {data['packets']} packets ({data['status']})")
```

---

### 5. Blocked IPs

Get list of currently blocked IP addresses.

#### Request

```http
GET /api/blocked
```

#### Response

**Status Code**: 200 OK

```json
{
  "blocked_ips": [
    {
      "ip": "192.168.1.100",
      "blocked_at": "2024-01-15T10:30:45.123456",
      "reason": "SYN flood attack",
      "attack_type": "SYN_FLOOD",
      "packet_count": 150,
      "expires_at": "2024-01-15T11:30:45.123456",
      "duration_minutes": 60
    },
    {
      "ip": "10.0.0.50",
      "blocked_at": "2024-01-15T10:25:30.123456",
      "reason": "Packet flood attack",
      "attack_type": "PACKET_FLOOD",
      "packet_count": 250,
      "expires_at": "2024-01-15T11:25:30.123456",
      "duration_minutes": 60
    }
  ],
  "count": 2,
  "timestamp": "2024-01-15T10:30:45.123456"
}
```

#### Example

```bash
curl http://localhost:5001/api/blocked
```

```python
import requests

response = requests.get('http://localhost:5001/api/blocked')
blocked = response.json()

print(f"Currently blocked: {blocked['count']} IPs")
for block in blocked['blocked_ips']:
    print(f"- {block['ip']}: {block['reason']}")
```

---

### 6. Attack History

Get historical attack data.

#### Request

```http
GET /api/attacks?limit=20&since=2024-01-15T00:00:00
```

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 50 | Maximum number of attacks |
| `since` | string (ISO 8601) | No | All time | Start timestamp |
| `attack_type` | string | No | All | Filter by attack type |

**Valid Attack Types**: `SYN_FLOOD`, `PACKET_FLOOD`, `UDP_FLOOD`

#### Response

**Status Code**: 200 OK

```json
{
  "attacks": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:30:45.123456",
      "source_ip": "192.168.1.100",
      "attack_type": "SYN_FLOOD",
      "packet_count": 150,
      "syn_count": 75,
      "duration_seconds": 3.5,
      "action_taken": "IP blocked",
      "resolved": true
    }
  ],
  "count": 1,
  "total_attacks": 5
}
```

#### Example

```bash
# Get recent SYN flood attacks
curl "http://localhost:5001/api/attacks?attack_type=SYN_FLOOD&limit=10"
```

```python
import requests
from datetime import datetime, timedelta

# Get attacks from last hour
since = (datetime.now() - timedelta(hours=1)).isoformat()
response = requests.get(
    'http://localhost:5001/api/attacks',
    params={'since': since}
)

for attack in response.json()['attacks']:
    print(f"{attack['timestamp']}: {attack['attack_type']} from {attack['source_ip']}")
```

---

### 7. System Configuration

Get current system configuration (read-only).

#### Request

```http
GET /api/config
```

#### Response

**Status Code**: 200 OK

```json
{
  "network_interface": "wlp1s0",
  "packet_threshold": 100,
  "syn_threshold": 50,
  "time_window": 5.0,
  "auto_blocking_enabled": true,
  "testing_mode": false,
  "dashboard_port": 5001,
  "log_directory": "logs"
}
```

#### Example

```bash
curl http://localhost:5001/api/config
```

---

## Error Responses

### Standard Error Format

```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "timestamp": "2024-01-15T10:30:45.123456"
}
```

### HTTP Status Codes

| Code | Meaning | Example |
|------|---------|---------|
| 200 | OK | Successful request |
| 400 | Bad Request | Invalid parameters |
| 404 | Not Found | Endpoint doesn't exist |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | System not ready |

### Example Error Response

```json
{
  "error": "Invalid log level specified",
  "code": "INVALID_PARAMETER",
  "timestamp": "2024-01-15T10:30:45.123456",
  "valid_values": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
}
```

## Rate Limiting

Currently not implemented. For production use:

```python
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=lambda: request.remote_addr,
    default_limits=["100 per hour", "10 per minute"]
)
```

## CORS Support

For cross-origin requests:

```python
from flask_cors import CORS

CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000"],
        "methods": ["GET", "OPTIONS"]
    }
})
```

## WebSocket Support (Future)

Real-time updates via WebSocket:

```javascript
// Future enhancement
const ws = new WebSocket('ws://localhost:5001/ws');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Real-time update:', data);
};
```

## Client Libraries

### Python Client

```python
class DDoSDetectorClient:
    def __init__(self, base_url='http://localhost:5001'):
        self.base_url = base_url
    
    def get_stats(self):
        response = requests.get(f'{self.base_url}/api/stats')
        return response.json()
    
    def get_logs(self, limit=100, level=None):
        params = {'limit': limit}
        if level:
            params['level'] = level
        response = requests.get(f'{self.base_url}/api/logs', params=params)
        return response.json()
    
    def get_blocked_ips(self):
        response = requests.get(f'{self.base_url}/api/blocked')
        return response.json()

# Usage
client = DDoSDetectorClient()
stats = client.get_stats()
print(f"Blocked IPs: {stats['blocked_ips']}")
```

### JavaScript Client

```javascript
class DDoSDetectorClient {
    constructor(baseUrl = 'http://localhost:5001') {
        this.baseUrl = baseUrl;
    }
    
    async getStats() {
        const response = await fetch(`${this.baseUrl}/api/stats`);
        return await response.json();
    }
    
    async getLogs(limit = 100, level = null) {
        const params = new URLSearchParams({ limit });
        if (level) params.append('level', level);
        
        const response = await fetch(`${this.baseUrl}/api/logs?${params}`);
        return await response.json();
    }
    
    async getBlockedIPs() {
        const response = await fetch(`${this.baseUrl}/api/blocked`);
        return await response.json();
    }
}

// Usage
const client = new DDoSDetectorClient();
const stats = await client.getStats();
console.log(`Blocked IPs: ${stats.blocked_ips}`);
```

## Integration Examples

### Monitoring Dashboard

```python
import time
import requests

def monitor_system():
    """Continuous monitoring loop"""
    while True:
        stats = requests.get('http://localhost:5001/api/stats').json()
        
        if stats['blocked_ips'] > 0:
            print(f"⚠️  {stats['blocked_ips']} IPs currently blocked")
            
            blocked = requests.get('http://localhost:5001/api/blocked').json()
            for block in blocked['blocked_ips']:
                print(f"  - {block['ip']}: {block['reason']}")
        
        time.sleep(10)

monitor_system()
```

### Alert System

```python
import requests
import smtplib

def check_for_attacks():
    """Check for new attacks and send alerts"""
    logs = requests.get(
        'http://localhost:5001/api/logs',
        params={'level': 'CRITICAL', 'limit': 10}
    ).json()
    
    for log in logs['logs']:
        if 'attack detected' in log['message'].lower():
            send_alert(
                f"DDoS Attack Detected!\n"
                f"IP: {log['source_ip']}\n"
                f"Type: {log.get('attack_type', 'Unknown')}\n"
                f"Time: {log['timestamp']}"
            )
```

### Analytics Export

```python
import requests
import csv
from datetime import datetime

def export_attack_data():
    """Export attack data to CSV"""
    attacks = requests.get('http://localhost:5001/api/attacks').json()
    
    filename = f"attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'timestamp', 'source_ip', 'attack_type',
            'packet_count', 'action_taken'
        ])
        writer.writeheader()
        writer.writerows(attacks['attacks'])
    
    print(f"Exported {len(attacks['attacks'])} attacks to {filename}")
```

## Best Practices

### 1. Error Handling

```python
import requests

try:
    response = requests.get('http://localhost:5001/api/stats', timeout=5)
    response.raise_for_status()
    stats = response.json()
except requests.exceptions.Timeout:
    print("Request timed out")
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
```

### 2. Caching

```python
import time

class CachedClient:
    def __init__(self):
        self.cache = {}
        self.cache_duration = 5  # seconds
    
    def get_stats(self):
        now = time.time()
        if 'stats' in self.cache:
            cached_time, data = self.cache['stats']
            if now - cached_time < self.cache_duration:
                return data
        
        data = requests.get('http://localhost:5001/api/stats').json()
        self.cache['stats'] = (now, data)
        return data
```

### 3. Pagination

```python
def get_all_logs():
    """Get all logs using pagination"""
    all_logs = []
    offset = 0
    limit = 100
    
    while True:
        response = requests.get(
            'http://localhost:5001/api/logs',
            params={'limit': limit, 'offset': offset}
        ).json()
        
        logs = response['logs']
        all_logs.extend(logs)
        
        if len(logs) < limit:
            break
        
        offset += limit
    
    return all_logs
```

## References

- [Flask Documentation](https://flask.palletsprojects.com/)
- [RESTful API Design](https://restfulapi.net/)
- [HTTP Status Codes](https://httpstatuses.com/)
- [JSON API Specification](https://jsonapi.org/)
