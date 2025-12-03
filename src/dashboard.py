"""
Phase 6.3: Web Dashboard (Optional)
Real-Time DDoS Detection System - Web Interface

This module provides a Flask-based web dashboard for monitoring
the DDoS detection system in real-time through a web browser.

Features:
- Real-time traffic visualization
- Blocked IPs list
- Attack history
- System statistics
- RESTful API for data access
"""

from flask import Flask, jsonify, render_template_string, send_from_directory
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any

app = Flask(__name__)

# Get absolute paths to prevent directory issues
PROJECT_ROOT = Path(__file__).parent.parent
STATS_FILE = str(PROJECT_ROOT / 'stats.json')
LOGS_DIR = str(PROJECT_ROOT / 'logs')
DATA_STALE_THRESHOLD = 15  # seconds - if data is older, it's considered stale


def is_data_stale(timestamp_str: str) -> bool:
    """Check if data timestamp is stale.
    
    Args:
        timestamp_str: ISO format timestamp string
        
    Returns:
        bool: True if data is stale, False otherwise
    """
    try:
        data_time = datetime.fromisoformat(timestamp_str)
        age = datetime.now() - data_time
        return age.total_seconds() > DATA_STALE_THRESHOLD
    except (ValueError, TypeError):
        return True  # Treat invalid timestamps as stale

# HTML Template for the dashboard
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Detection Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, 
                         "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            text-align: center;
        }
        
        h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #666;
            font-size: 1.1em;
        }
        
        .status-badge {
            display: inline-block;
            padding: 8px 20px;
            background: #10b981;
            color: white;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 15px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
        }
        
        .card-title {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .card-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }
        
        .card-icon {
            font-size: 2em;
            float: right;
        }
        
        .chart-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }
        
        .chart-title {
            font-size: 1.3em;
            color: #333;
            margin-bottom: 20px;
            font-weight: 600;
        }
        
        #blocked-ips-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
        }
        
        .blocked-ip-item {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 10px;
            font-weight: 500;
            display: flex;
            align-items: center;
            justify-content: space-between;
            animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(-20px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .blocked-ip-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .footer {
            text-align: center;
            color: white;
            margin-top: 30px;
            font-size: 0.9em;
        }
        
        .refresh-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(255, 255, 255, 0.9);
            padding: 10px 20px;
            border-radius: 20px;
            font-size: 0.9em;
            color: #667eea;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>
    <div class="refresh-indicator" id="refresh-indicator">
        <span id="refresh-text">⟳ Live</span>
    </div>
    
    <div class="container">
        <header>
            <h1>🛡️ DDoS Detection Dashboard</h1>
            <p class="subtitle">Real-Time Network Threat Monitoring</p>
            <span class="status-badge">● SYSTEM ACTIVE</span>
        </header>
        
        <div class="grid">
            <div class="card">
                <div class="card-icon">📊</div>
                <div class="card-title">Total Traffic</div>
                <div class="card-value" id="total-traffic">0</div>
            </div>
            
            <div class="card">
                <div class="card-icon">🚨</div>
                <div class="card-title">Attacks Detected</div>
                <div class="card-value" id="attacks-detected">0</div>
            </div>
            
            <div class="card">
                <div class="card-icon">🔒</div>
                <div class="card-title">Blocked IPs</div>
                <div class="card-value" id="blocked-count">0</div>
            </div>
            
            <div class="card">
                <div class="card-icon">⏱️</div>
                <div class="card-title">Uptime</div>
                <div class="card-value" id="uptime" style="font-size: 1.5em;">00:00:00</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3 class="chart-title">📈 Live Traffic Analysis (Top 10 IPs)</h3>
            <canvas id="trafficChart"></canvas>
        </div>
        
        <div id="blocked-ips-container">
            <h3 class="chart-title">🔒 Blocked IP Addresses</h3>
            <div id="blocked-ips-list">
                <div class="empty-state">No blocked IPs yet</div>
            </div>
        </div>
        
        <div class="footer">
            <p>DDoS Detection System v1.0 | Phase 6 Complete</p>
            <p>Updates every 2 seconds</p>
        </div>
    </div>
    
    <script>
        // Initialize Chart
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets per 5s',
                    data: [],
                    backgroundColor: 'rgba(102, 126, 234, 0.8)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2,
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        padding: 12,
                        titleFont: {
                            size: 14
                        },
                        bodyFont: {
                            size: 13
                        },
                        borderColor: 'rgba(102, 126, 234, 1)',
                        borderWidth: 1
                    }
                },
                animation: {
                    duration: 500
                }
            }
        });
        
        let startTime = Date.now();
        
        function updateUptime() {
            const elapsed = Date.now() - startTime;
            const hours = Math.floor(elapsed / 3600000);
            const minutes = Math.floor((elapsed % 3600000) / 60000);
            const seconds = Math.floor((elapsed % 60000) / 1000);
            
            document.getElementById('uptime').textContent = 
                `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }
        
        async function updateStats() {
            const refreshIndicator = document.getElementById('refresh-text');
            refreshIndicator.textContent = '⟳ Updating...';
            
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                // Update stat cards
                document.getElementById('total-traffic').textContent = 
                    (data.total_packets || 0).toLocaleString();
                document.getElementById('attacks-detected').textContent = 
                    (data.attacks_detected || 0).toLocaleString();
                document.getElementById('blocked-count').textContent = 
                    (data.blocked_ips || []).length;
                
                // Update chart
                const ips = Object.keys(data.packet_counts || {});
                const counts = Object.values(data.packet_counts || {});
                
                trafficChart.data.labels = ips;
                trafficChart.data.datasets[0].data = counts;
                trafficChart.update('none'); // Update without animation for smoothness
                
                // Update blocked IPs list
                const blockedList = document.getElementById('blocked-ips-list');
                const blockedIps = data.blocked_ips || [];
                
                if (blockedIps.length > 0) {
                    blockedList.innerHTML = blockedIps.map(ip => `
                        <div class="blocked-ip-item">
                            <span>🔒 ${ip}</span>
                            <span>BLOCKED</span>
                        </div>
                    `).join('');
                } else {
                    blockedList.innerHTML = '<div class="empty-state">No blocked IPs yet</div>';
                }
                
                refreshIndicator.textContent = '⟳ Live';
            } catch (error) {
                console.error('Error fetching stats:', error);
                refreshIndicator.textContent = '⟳ Error';
            }
        }
        
        // Update uptime every second
        setInterval(updateUptime, 1000);
        
        // Update stats every 2 seconds
        setInterval(updateStats, 2000);
        
        // Initial update
        updateStats();
        updateUptime();
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    """Serve the main dashboard page"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/stats')
def get_stats():
    """
    API endpoint to get current statistics.
    
    Returns:
        JSON response with current stats
    """
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                data = json.load(f)
                
                # Check if data is stale
                timestamp = data.get('timestamp', '')
                detector_running = data.get('detector_running', False)
                stale = is_data_stale(timestamp)
                
                # Add metadata
                data['data_stale'] = stale
                data['detector_status'] = 'running' if detector_running and not stale else 'stopped'
                
                return jsonify(data)
        else:
            # Return empty data if file doesn't exist yet
            return jsonify({
                'packet_counts': {},
                'blocked_ips': [],
                'total_packets': 0,
                'attacks_detected': 0,
                'detector_status': 'not_started',
                'data_stale': True
            })
    except json.JSONDecodeError:
        return jsonify({
            'error': 'Corrupted data file',
            'detector_status': 'error',
            'data_stale': True
        }), 500
    except Exception as e:
        return jsonify({
            'error': str(e),
            'detector_status': 'error',
            'data_stale': True
        }), 500


@app.route('/api/logs')
def get_logs():
    """
    API endpoint to get recent log entries.
    
    Returns:
        JSON response with recent log entries
    """
    try:
        logs = []
        json_log_path = os.path.join(LOGS_DIR, 'ddos_events.json')
        
        if os.path.exists(json_log_path):
            with open(json_log_path, 'r') as f:
                # Read last 50 lines
                lines = f.readlines()
                for line in lines[-50:]:
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
        
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


def run_dashboard(host='0.0.0.0', port=5001, debug=False):
    """
    Run the web dashboard server.
    
    Args:
        host (str): Host to bind to (default: 0.0.0.0 for all interfaces)
        port (int): Port to bind to (default: 5001)
        debug (bool): Enable debug mode (default: False)
    """
    print("="*70)
    print("DDoS Detection Web Dashboard")
    print("="*70)
    print(f"\n🌐 Starting web server on http://{host}:{port}")
    print(f"📊 Dashboard: http://localhost:{port}")
    print(f"🔧 API Status: http://localhost:{port}/api/stats")
    print(f"💚 Health Check: http://localhost:{port}/health")
    print("\n⚠️  Make sure detector.py is running to see live data!")
    print("\nPress Ctrl+C to stop the server\n")
    print("="*70)
    
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    run_dashboard(debug=True)
