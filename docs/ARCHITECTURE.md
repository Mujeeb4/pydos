# System Architecture Documentation

## Overview

The Real-Time DDoS Detection System is built with a modular architecture that separates concerns into distinct components. This design enables maintainability, testability, and extensibility.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│                  Network Traffic                     │
└────────────────────┬────────────────────────────────┘
                     │
          ┌──────────▼──────────┐
          │   sniffer.py        │  ◄── Scapy Packet Capture
          │  (Traffic Capture)  │      Raw packet sniffing
          └──────────┬──────────┘      Protocol analysis
                     │
          ┌──────────▼──────────┐
          │ ddos_detector.py    │  ◄── Detection Engine
          │  (Main Controller)  │      Threshold monitoring
          │                     │      Attack identification
          └──────┬───────┬──────┘      Real-time analysis
                 │       │
       ┌─────────┘       └─────────┐
       │                           │
┌──────▼────────┐         ┌────────▼──────┐
│ mitigator.py  │         │  logger.py    │
│ (IP Blocking) │         │  (Logging)    │
│               │         │               │
│ - iptables    │         │ - File logs   │
│ - Block mgmt  │         │ - JSON logs   │
└───────────────┘         └────────┬──────┘
       │                           │
       │                  ┌────────▼──────────┐
       │                  │  dashboard.py     │
       │                  │  (Web Interface)  │
       │                  │                   │
       │                  │ - Flask API       │
       │                  │ - Real-time UI    │
       │                  └───────────────────┘
       │
┌──────▼──────────┐
│    iptables     │  ◄── Linux Firewall
│  (OS Firewall)  │      System-level blocking
└─────────────────┘
```

## Core Components

### 1. Traffic Capture Layer (sniffer.py)

**Responsibility**: Network packet interception and basic protocol parsing

**Key Features**:
- Raw packet capture using Scapy
- IP layer extraction
- TCP/UDP/ICMP protocol identification
- Real-time packet streaming
- Minimal processing overhead

**Technology Stack**:
- Scapy for packet manipulation
- Python threading for non-blocking capture

**Data Flow**:
```
Network Interface → Scapy Sniffer → Packet Callback → Detection Engine
```

### 2. Detection Engine (ddos_detector.py)

**Responsibility**: Main orchestration and attack detection logic

**Key Features**:
- Threshold-based detection
- Time window management (5-second rolling windows)
- Thread-safe packet counting
- Attack pattern recognition
- Real-time CLI dashboard

**Detection Algorithms**:
1. **Packet Flood Detection**: Monitors total packets per IP
2. **SYN Flood Detection**: Tracks TCP SYN flags specifically
3. **Time-based Analysis**: 5-second rolling windows with automatic reset

**Thread Safety**:
- Uses `threading.Lock()` for counter protection
- Prevents race conditions in multi-threaded packet processing

### 3. Mitigation Layer (mitigator.py)

**Responsibility**: Automated threat response and IP blocking

**Key Features**:
- iptables integration for Linux firewall control
- Thread-safe IP blocking
- Automatic duplicate prevention
- Time-based automatic unblocking
- Block expiration management

**Blocking Strategy**:
```python
iptables -A INPUT -s <MALICIOUS_IP> -j DROP
```

**Safety Features**:
- Idempotent operations (safe to call multiple times)
- Automatic cleanup of expired blocks
- Prevents self-blocking
- Error handling for iptables failures

### 4. Logging System (logger.py)

**Responsibility**: Comprehensive event logging and audit trail

**Key Features**:
- Multiple log files for different purposes
- Log rotation to prevent disk exhaustion
- Structured logging with timestamps
- JSON format for machine parsing
- Configurable log levels

**Log Files**:
1. `ddos_events.log` - All system events
2. `ddos_attacks.log` - Attack-specific logs
3. `ddos_system.log` - System operations
4. `ddos_events.json` - Structured JSON logs

### 5. Dashboard Layer (dashboard.py)

**Responsibility**: User interface and data visualization

**Components**:

#### CLI Dashboard (Rich Library)
- Real-time terminal UI
- Color-coded threat levels
- Live traffic tables
- Statistics panels

#### Web Dashboard (Flask)
- HTTP server on port 5001
- RESTful API endpoints
- Modern web interface
- Chart.js visualizations
- Auto-refresh every 2 seconds

**API Endpoints**:
- `GET /health` - System health check
- `GET /api/stats` - Current statistics
- `GET /api/logs` - Recent log entries
- `GET /` - Main dashboard UI

### 6. Analysis Module (analyzer.py)

**Responsibility**: Traffic pattern analysis and statistics

**Key Features**:
- Historical traffic tracking
- IP behavior profiling
- Statistical analysis
- Trend identification
- Top talker identification

### 7. Configuration Management (config/config.py)

**Responsibility**: Centralized system configuration

**Configurable Parameters**:
- Network interface selection
- Detection thresholds
- Time windows
- Dashboard settings
- Logging preferences
- Testing mode flags

## Data Flow Architecture

### Packet Processing Pipeline

```
1. Network Packet Arrival
   │
   ├─> Scapy Capture (sniffer.py)
   │
   ├─> Packet Parsing
   │   ├─> Extract IP addresses
   │   ├─> Identify protocol
   │   └─> Extract TCP flags
   │
   ├─> Detection Engine (ddos_detector.py)
   │   ├─> Update counters (thread-safe)
   │   ├─> Check thresholds
   │   └─> Trigger alerts if exceeded
   │
   ├─> Attack Detected?
   │   │
   │   YES─> Mitigation (mitigator.py)
   │   │     ├─> Block IP via iptables
   │   │     ├─> Log attack details
   │   │     └─> Update dashboard
   │   │
   │   NO──> Continue monitoring
   │
   └─> Log Event (logger.py)
       └─> Update Statistics
```

### Threading Model

```
Main Thread
├─> Packet Sniffing Thread (Scapy)
│   └─> Calls packet_handler() for each packet
│
├─> Dashboard Update Thread (Rich Live)
│   └─> Refreshes CLI every 1 second
│
├─> Timer Thread (Detection)
│   └─> Resets counters every 5 seconds
│
├─> Cleanup Thread (Mitigator)
│   └─> Removes expired IP blocks
│
└─> Flask Web Server (Optional)
    └─> Serves HTTP requests
```

## Design Patterns

### 1. Singleton Pattern
- Configuration management
- Logger instances

### 2. Observer Pattern
- Packet capture callbacks
- Event-driven attack detection

### 3. Strategy Pattern
- Different attack detection strategies
- Configurable thresholds

### 4. Facade Pattern
- Simplified API in dashboard
- Unified logging interface

## Security Considerations

### Privilege Requirements
- **Root/Sudo Access**: Required for:
  - Raw packet capture (CAP_NET_RAW)
  - iptables modifications (CAP_NET_ADMIN)

### Safety Mechanisms
1. **Input Validation**: All IP addresses validated
2. **Whitelist Protection**: Prevents blocking critical IPs
3. **Rate Limiting**: Prevents resource exhaustion
4. **Error Handling**: Graceful degradation on failures

### Potential Vulnerabilities
1. **False Positives**: Legitimate traffic may trigger blocks
2. **Resource Exhaustion**: Memory usage with many tracked IPs
3. **Bypass Techniques**: IP spoofing, distributed sources

## Performance Characteristics

### Scalability Limits
- **Packet Rate**: ~10,000 packets/second on commodity hardware
- **Memory**: ~100MB baseline + ~1KB per tracked IP
- **CPU**: Single-core bottleneck in packet processing

### Optimization Strategies
1. **Efficient Data Structures**: defaultdict for O(1) lookups
2. **Minimal Processing**: Only extract required packet fields
3. **Thread Safety**: Lock contention minimized
4. **Log Rotation**: Prevents disk exhaustion

## Extensibility Points

### Adding New Attack Types
1. Define new detection threshold in `config.py`
2. Add counter in `ddos_detector.py`
3. Implement detection logic
4. Update dashboard display

### Adding New Mitigation Strategies
1. Create new class in `mitigator.py`
2. Implement blocking interface
3. Integrate with detection engine

### Adding New Logging Outputs
1. Extend `DDoSLogger` class
2. Add new handler
3. Configure formatting

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Packet Capture | Scapy | Raw packet sniffing |
| Detection | Python threading | Concurrent processing |
| Mitigation | iptables | Firewall management |
| Logging | Python logging | Event recording |
| CLI Dashboard | Rich | Terminal UI |
| Web Dashboard | Flask | HTTP server |
| Visualization | Chart.js | Real-time charts |
| Configuration | Python modules | Centralized settings |

## Deployment Architecture

### Standalone Mode
```
Single Server
├─> All components on one machine
├─> Monitors local network interface
└─> Stores logs locally
```

### Future: Distributed Mode (Phase 8)
```
Sensor Nodes (Multiple)
├─> Capture traffic
└─> Send to Central Server

Central Server
├─> Aggregate detection
├─> Centralized blocking
└─> Dashboard and reporting
```

## Error Handling Strategy

### Graceful Degradation
1. **iptables Unavailable**: Log only, no blocking
2. **Network Interface Down**: Alert and retry
3. **Disk Full**: Rotate logs aggressively
4. **Memory Pressure**: Clear old tracking data

### Recovery Mechanisms
- Automatic reconnection on interface reset
- State persistence across restarts
- Health check monitoring

## Monitoring and Observability

### Metrics Collected
- Total packets processed
- Unique IPs tracked
- Attacks detected
- IPs blocked
- System uptime
- Resource utilization

### Health Indicators
- Packet processing rate
- Detection latency
- Log file sizes
- Memory usage
- Thread status

## Future Architecture Enhancements

### Phase 8: Machine Learning Integration
```
Historical Data
    │
    ├─> Feature Extraction
    │
    ├─> ML Model (scikit-learn)
    │   ├─> Training on labeled data
    │   └─> Real-time inference
    │
    └─> Enhanced Detection
        ├─> Anomaly detection
        └─> Attack classification
```

### Potential Improvements
1. **Database Integration**: PostgreSQL/InfluxDB for historical analysis
2. **Message Queue**: Redis/RabbitMQ for async processing
3. **Container Support**: Docker deployment
4. **Horizontal Scaling**: Multiple sensor nodes
5. **Cloud Integration**: AWS/Azure security services

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [iptables Tutorial](https://www.netfilter.org/documentation/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Rich Library Guide](https://rich.readthedocs.io/)
