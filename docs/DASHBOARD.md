# Dashboard Documentation

## Overview

The Dashboard system provides two interfaces for monitoring the DDoS detection system: a CLI (Command-Line Interface) dashboard using the Rich library and a Web dashboard using Flask.

## CLI Dashboard

### Technology Stack

- **Rich Library**: Terminal UI framework
- **Live Display**: Real-time updates
- **Color Coding**: Visual threat indicators
- **Tables**: Organized data presentation

### Features

#### 1. Real-time Traffic Table

Displays current packet counts per IP address:

```
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┓
┃ Source IP      ┃ Packets   ┃ SYN Count ┃ Status ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━┩
│ 192.168.1.100  │ 95/100    │ 45/50     │ 🟢 OK  │
│ 192.168.1.101  │ 150/100   │ 75/50     │ 🔴 ATK │
│ 10.0.0.5       │ 25/100    │ 10/50     │ 🟢 OK  │
└────────────────┴───────────┴───────────┴────────┘
```

**Color Coding**:
- 🟢 **Green**: < 50% of threshold (normal)
- 🟡 **Yellow**: 50-99% of threshold (warning)
- 🔴 **Red**: ≥ threshold (attack detected)

#### 2. Statistics Panel

Shows overall system metrics:

```
╭─────────── System Statistics ───────────╮
│ Total Packets:     1,234                │
│ Unique IPs:        45                   │
│ Blocked IPs:       2                    │
│ Attacks Detected:  2                    │
│ Uptime:            00:15:32             │
│ Last Update:       2024-01-15 10:30:45  │
╰─────────────────────────────────────────╯
```

#### 3. Blocked IPs List

Displays currently blocked IP addresses:

```
╭────────── Blocked IPs ──────────╮
│ 192.168.1.100 (SYN Flood)      │
│ 10.0.0.50     (Packet Flood)   │
╰─────────────────────────────────╯
```

#### 4. Alert Messages

Real-time alerts appear at the bottom:

```
⚠️  HIGH TRAFFIC: 192.168.1.100 (80/100 packets)
🚨 ATTACK DETECTED: 192.168.1.101 - IP BLOCKED
✅ System running normally
```

### Implementation

```python
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout

def generate_dashboard():
    """Generate the CLI dashboard layout"""
    layout = Layout()
    
    # Create traffic table
    traffic_table = create_traffic_table()
    
    # Create statistics panel
    stats_panel = create_stats_panel()
    
    # Create blocked IPs panel
    blocked_panel = create_blocked_panel()
    
    # Combine into layout
    layout.split_column(
        Layout(stats_panel, size=10),
        Layout(traffic_table, size=20),
        Layout(blocked_panel, size=8)
    )
    
    return layout

# Run with live updates
with Live(generate_dashboard(), refresh_per_second=1) as live:
    while running:
        live.update(generate_dashboard())
```

### Configuration

```python
# Update frequency
DASHBOARD_UPDATE_INTERVAL = 1.0  # seconds

# Table display limits
MAX_IPS_DISPLAYED = 20

# Color thresholds
WARNING_THRESHOLD_PERCENT = 0.5  # 50%
DANGER_THRESHOLD_PERCENT = 1.0   # 100%
```

## Web Dashboard

### Technology Stack

- **Flask**: Web framework
- **Chart.js**: Real-time charts
- **Bootstrap**: UI styling
- **JSON API**: Data endpoints

### URL: `http://localhost:5001`

### Features

#### 1. Real-time Statistics Cards

```html
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Total Packets   │  │ Active IPs      │  │ Blocked IPs     │
│     1,234       │  │       45        │  │       2         │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

#### 2. Live Traffic Chart

Line chart showing:
- Total packets over time
- SYN packets over time
- Blocked events

**Update Frequency**: Every 2 seconds

#### 3. Top Talkers Table

```html
┌─────────────────┬──────────┬───────────┐
│ IP Address      │ Packets  │ Status    │
├─────────────────┼──────────┼───────────┤
│ 192.168.1.100   │ 150      │ 🔴 Blocked│
│ 192.168.1.50    │ 85       │ 🟡 Warning│
│ 10.0.0.10       │ 25       │ 🟢 Normal │
└─────────────────┴──────────┴───────────┘
```

#### 4. Recent Attacks Log

```html
┌────────────────────┬─────────────────┬────────────┐
│ Timestamp          │ Source IP       │ Type       │
├────────────────────┼─────────────────┼────────────┤
│ 2024-01-15 10:30   │ 192.168.1.100   │ SYN Flood  │
│ 2024-01-15 10:25   │ 10.0.0.50       │ Pkt Flood  │
└────────────────────┴─────────────────┴────────────┘
```

#### 5. System Health Indicator

```
● System Status: ACTIVE
● Detector: Running
● Mitigator: Enabled
● Last Update: 2 seconds ago
```

### API Endpoints

#### Health Check

```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "uptime": "00:15:32",
  "version": "1.0.0"
}
```

#### System Statistics

```http
GET /api/stats
```

**Response**:
```json
{
  "total_packets": 1234,
  "unique_ips": 45,
  "blocked_ips": 2,
  "attacks_detected": 2,
  "timestamp": "2024-01-15T10:30:45.123456",
  "uptime_seconds": 932
}
```

#### Recent Logs

```http
GET /api/logs?limit=50
```

**Parameters**:
- `limit` (optional): Number of log entries (default: 100)
- `level` (optional): Filter by level (INFO, WARNING, ERROR, CRITICAL)

**Response**:
```json
{
  "logs": [
    {
      "timestamp": "2024-01-15T10:30:45",
      "level": "CRITICAL",
      "message": "Attack detected from 192.168.1.100",
      "source_ip": "192.168.1.100"
    }
  ],
  "count": 50
}
```

#### Traffic Data

```http
GET /api/traffic
```

**Response**:
```json
{
  "current": {
    "192.168.1.100": {
      "packets": 150,
      "syn_packets": 75,
      "blocked": true
    }
  },
  "timestamp": "2024-01-15T10:30:45"
}
```

#### Blocked IPs

```http
GET /api/blocked
```

**Response**:
```json
{
  "blocked_ips": [
    {
      "ip": "192.168.1.100",
      "blocked_at": "2024-01-15T10:30:45",
      "reason": "SYN flood attack",
      "expires_at": "2024-01-15T11:30:45"
    }
  ],
  "count": 1
}
```

### Implementation

#### Flask Application

```python
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    """Serve the main dashboard page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/stats')
def get_stats():
    """Return current statistics"""
    stats = load_stats_from_file()
    return jsonify(stats)

@app.route('/api/logs')
def get_logs():
    """Return recent log entries"""
    limit = request.args.get('limit', 100, type=int)
    logs = read_recent_logs(limit)
    return jsonify({'logs': logs, 'count': len(logs)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
```

#### Frontend Auto-refresh

```javascript
// Update statistics every 2 seconds
setInterval(updateStats, 2000);

function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('total-packets').textContent = data.total_packets;
            document.getElementById('unique-ips').textContent = data.unique_ips;
            document.getElementById('blocked-ips').textContent = data.blocked_ips;
            updateChart(data);
        });
}
```

#### Chart.js Integration

```javascript
const ctx = document.getElementById('trafficChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: timestamps,
        datasets: [
            {
                label: 'Total Packets',
                data: packetCounts,
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1
            },
            {
                label: 'SYN Packets',
                data: synCounts,
                borderColor: 'rgb(255, 99, 132)',
                tension: 0.1
            }
        ]
    },
    options: {
        responsive: true,
        animation: false,
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});
```

### Configuration

```python
# config/config.py
DASHBOARD_HOST = "0.0.0.0"  # Listen on all interfaces
DASHBOARD_PORT = 5001        # Web server port
ENABLE_WEB_DASHBOARD = True  # Enable/disable web interface
```

## Data Exchange Format

### stats.json

Shared file between detector and dashboards:

```json
{
  "total_packets": 1234,
  "unique_ips": 45,
  "blocked_ips": 2,
  "timestamp": "2024-01-15T10:30:45.123456",
  "traffic": {
    "192.168.1.100": {
      "packets": 150,
      "syn_packets": 75
    }
  },
  "blocked": [
    {
      "ip": "192.168.1.100",
      "blocked_at": "2024-01-15T10:30:45",
      "reason": "SYN flood"
    }
  ]
}
```

**Location**: Project root directory

**Update Frequency**: Every 1 second (by detector)

## Performance Considerations

### CLI Dashboard

**Resource Usage**:
- CPU: 1-3% (for rendering)
- Memory: ~10 MB
- Terminal I/O: Minimal

**Optimization**:
```python
# Limit displayed IPs
MAX_DISPLAY_IPS = 20

# Reduce update frequency if needed
with Live(dashboard, refresh_per_second=0.5):  # 0.5 Hz
    pass
```

### Web Dashboard

**Resource Usage**:
- CPU: 2-5% (Flask server)
- Memory: ~50 MB
- Network: Minimal (JSON only)

**Optimization**:
```python
# Enable caching
@app.route('/api/stats')
@cache.cached(timeout=2)  # Cache for 2 seconds
def get_stats():
    return jsonify(stats)

# Compress responses
from flask_compress import Compress
compress = Compress(app)
```

## Running Dashboards

### CLI Dashboard Only

```bash
# Runs automatically with detector
sudo python3 src/ddos_detector.py
```

### Web Dashboard

```bash
# Terminal 1: Detection engine
sudo python3 src/ddos_detector.py

# Terminal 2: Web dashboard
python3 src/dashboard.py
```

Then open browser: `http://localhost:5001`

### Both Dashboards

The CLI dashboard runs by default. Start web dashboard separately:

```bash
# Start detector with CLI dashboard
sudo python3 src/ddos_detector.py &

# Start web dashboard
python3 src/dashboard.py &

# View in terminal
fg 1  # Bring CLI dashboard to foreground

# View in browser
open http://localhost:5001
```

## Customization

### CLI Dashboard Colors

```python
from rich.style import Style

# Custom styles
NORMAL_STYLE = Style(color="green")
WARNING_STYLE = Style(color="yellow", bold=True)
DANGER_STYLE = Style(color="red", bold=True, blink=True)

# Apply to table rows
table.add_row(ip, count, style=DANGER_STYLE)
```

### Web Dashboard Theme

```css
/* Custom CSS in HTML template */
:root {
    --primary-color: #007bff;
    --danger-color: #dc3545;
    --warning-color: #ffc107;
    --success-color: #28a745;
}

.card {
    background: linear-gradient(135deg, var(--primary-color), #0056b3);
}
```

### Chart Customization

```javascript
chart.options.scales.y.max = 200;  // Set max Y value
chart.options.animation.duration = 0;  // Disable animation
chart.update();
```

## Troubleshooting

### Problem: CLI Dashboard Not Updating

**Symptoms**: Static display, no updates

**Solutions**:
1. Check if detector is running: `ps aux | grep ddos_detector`
2. Verify `stats.json` is being updated: `watch cat stats.json`
3. Check terminal size: `echo $COLUMNS $LINES`
4. Ensure Rich library installed: `pip install rich`

### Problem: Web Dashboard Shows "Stale Data"

**Symptoms**: "Data is stale" warning

**Solutions**:
1. Verify detector is running and updating stats.json
2. Check file permissions: `ls -la stats.json`
3. Increase stale threshold: `DATA_STALE_THRESHOLD = 30` (seconds)
4. Check Flask logs for errors

### Problem: Port Already in Use

**Symptoms**: `Address already in use` error

**Solutions**:
```bash
# Find process using port 5001
lsof -i :5001

# Kill the process
kill -9 <PID>

# Or use different port
python3 src/dashboard.py --port 5002
```

### Problem: Charts Not Displaying

**Symptoms**: Blank chart area

**Solutions**:
1. Check browser console for JavaScript errors
2. Verify Chart.js CDN is accessible
3. Check if data format is correct
4. Clear browser cache

## Security Considerations

### Web Dashboard Security

```python
# Production: Restrict access
app.config['SERVER_NAME'] = 'localhost:5001'

# Add authentication
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    return username == 'admin' and password == 'secure_password'

@app.route('/api/stats')
@auth.login_required
def get_stats():
    return jsonify(stats)
```

### CORS Configuration

```python
from flask_cors import CORS

# Allow specific origins only
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000"]
    }
})
```

### Rate Limiting

```python
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=lambda: request.remote_addr,
    default_limits=["100 per hour"]
)

@app.route('/api/stats')
@limiter.limit("60 per minute")
def get_stats():
    return jsonify(stats)
```

## Mobile Responsiveness

### Responsive CSS

```css
/* Mobile-first design */
@media (max-width: 768px) {
    .stats-card {
        width: 100%;
        margin-bottom: 10px;
    }
    
    .chart-container {
        height: 200px;
    }
}
```

### Touch Interactions

```javascript
// Enable touch scrolling on mobile
document.addEventListener('touchmove', function(e) {
    e.preventDefault();
}, { passive: false });
```

## Future Enhancements

### 1. Historical Data Visualization

```javascript
// Show data for last 24 hours
const timeRanges = ['1h', '6h', '24h', '7d'];
chart.data = fetchHistoricalData(selectedRange);
```

### 2. Alert Notifications

```javascript
// Browser notifications
if (data.blocked_ips > previousCount) {
    new Notification('DDoS Attack Detected!', {
        body: `New attack from ${newIP}`,
        icon: '/static/alert-icon.png'
    });
}
```

### 3. Export Functionality

```python
@app.route('/api/export/csv')
def export_csv():
    """Export logs as CSV"""
    logs = get_all_logs()
    csv_data = convert_to_csv(logs)
    return Response(csv_data, mimetype='text/csv')
```

### 4. Advanced Filtering

```html
<!-- Filter by IP, time range, attack type -->
<input id="ip-filter" placeholder="Filter by IP">
<select id="time-range">
    <option value="1h">Last Hour</option>
    <option value="24h">Last 24 Hours</option>
</select>
```

## Best Practices

### 1. Performance
- Cache API responses
- Limit data points in charts
- Use compression for large responses

### 2. User Experience
- Provide clear status indicators
- Show loading states
- Handle errors gracefully

### 3. Accessibility
- Use semantic HTML
- Provide alt text for icons
- Keyboard navigation support

### 4. Monitoring
- Log dashboard access
- Track API usage
- Monitor response times

## References

- [Rich Documentation](https://rich.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Chart.js Guide](https://www.chartjs.org/docs/)
- [Bootstrap](https://getbootstrap.com/)
