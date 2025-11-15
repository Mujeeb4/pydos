Work Breakdown Structure: Real-Time DDoS Detection System

(Implementation Guide)

This WBS is designed for a sequential, step-by-step workflow. Complete the tasks in each phase before moving to the next.

Phase 1: Environment Setup & Foundations (1-2 Days)

Goal: Prepare your development and test environment.

1.1: Setup Virtual Environment:

[ ] How-to:

Download and install VirtualBox (or VMware Player).

Download the .iso file for Ubuntu 22.04 LTS.

In VirtualBox, click "New". Give it a name (e.g., "DDoS Server"), assign at least 2GB RAM and 2 CPU cores.

Create a virtual hard disk (25GB is fine).

Start the VM and "mount" the Ubuntu .iso file you downloaded as the virtual optical disk to install the OS.

After installation, start the VM, open a terminal, and run sudo apt update and sudo apt install net-tools (to get ifconfig).

With the VM powered off, find it in the VirtualBox list, click the menu, and select "Take Snapshot". Name it "Clean Install".

1.2: Install Core Dependencies:

[ ] How-to: Open the terminal in your new Ubuntu VM and run these commands:

# Update package lists and upgrade all packages
sudo apt update && sudo apt upgrade -y

# Install Python 3 and its package manager (pip)
sudo apt install python3 python3-pip -y

# Install hping3, our attack simulator
sudo apt install hping3 -y


1.3: Install Python Libraries:

[ ] How-to: In the same terminal, use pip3 to install your Python packages:

# Install Scapy for packet sniffing and forging
pip3 install scapy

# Install Pandas (for the optional ML phase)
pip3 install pandas


Phase 2: Traffic Capture Module - The "Sniffer" (1-2 Days)

Goal: Create a Python script that can read live network traffic.

2.1: Write Basic Sniffer Script (sniffer.py):

[ ] How-to:

Create a new file: nano sniffer.py

Paste in this code:

from scapy.all import sniff

def process_packet(packet):
    """ This function is called for every packet sniffed """
    print(packet.summary())

print("Starting packet sniffer...")
# 'iface' specifies the network interface. Find yours with `ip a`
# It's often 'enp0s3' in VirtualBox
sniff(iface="enp0s3", prn=process_packet, store=0)


Find your interface name by running ip a in the terminal (look for the one with your IP address). Update the iface= value in the script.

Test: Run the script with root privileges: sudo python3 sniffer.py. You should see a stream of packets. Press Ctrl+C to stop.

2.2: Refine Packet Processing:

[ ] How-to: Modify your sniffer.py to extract specific details.

from scapy.all import IP, TCP, sniff

def process_packet(packet):
    """ This function is called for every packet sniffed """
    # Check if it's an IP packet
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print(f"IP Packet: {src_ip} -> {dst_ip} (Proto: {proto})")

        # Check if it's a TCP packet (which is inside the IP packet)
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"  TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (Flags: {flags})")

print("Starting refined sniffer...")
sniff(iface="enp0s3", prn=process_packet, store=0)


Test: Run sudo python3 sniffer.py again. You'll now see formatted IP and TCP information.

Phase 3: Detection Engine - The "Brain" (2-3 Days)

Goal: Analyze the captured traffic in real-time to detect attack patterns. Rename sniffer.py to ddos_detector.py.

3.1: Create Data Structures for Tracking:

[ ] How-to: At the top of your ddos_detector.py script, add:

from collections import defaultdict

# defaultdict(int) automatically creates a new entry with 0 if a key is accessed
# This prevents "KeyError" and is perfect for counting
ip_packet_counts = defaultdict(int)
ip_syn_counts = defaultdict(int)


3.2: Implement Real-Time Counting Logic:

[ ] How-to: Modify your process_packet function to update these counts.

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # Increment the total packet count for this IP
        ip_packet_counts[src_ip] += 1

        # Check for SYN flood (TCP packet with only the SYN flag 'S')
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            ip_syn_counts[src_ip] += 1


(We will add the alert logic in the next step).

3.3: Implement Threshold-Based Rules:

[ ] How-to: Add constants at the top and the if checks inside process_packet.

# ... imports ...

# --- THRESHOLDS ---
# Allow 100 packets from one IP in our time window
PACKET_THRESHOLD = 100 
# Allow 50 SYN packets from one IP in our time window
SYN_THRESHOLD = 50 

# ... dictionaries ...

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_packet_counts[src_ip] += 1

        # Rule 1: Total packet flood
        if ip_packet_counts[src_ip] > PACKET_THRESHOLD:
            print(f"ALERT: Packet threshold exceeded from {src_ip} (Count: {ip_packet_counts[src_ip]})")
            # TODO: Call block_ip(src_ip)

        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            ip_syn_counts[src_ip] += 1

            # Rule 2: SYN flood
            if ip_syn_counts[src_ip] > SYN_THRESHOLD:
                print(f"ALERT: SYN flood detected from {src_ip} (Count: {ip_syn_counts[src_ip]})")
                # TODO: Call block_ip(src_ip)

# ... sniff call ...


3.4: Add a "Time Window" (Crucial Refinement):

[ ] How-to: Use Python's threading to reset the counts every 5 seconds.

import threading
from collections import defaultdict
from scapy.all import IP, TCP, sniff

# --- THRESHOLDS ---
PACKET_THRESHOLD = 100
SYN_THRESHOLD = 50

# --- DATA STRUCTURES ---
# Use locks to make dictionary access thread-safe
counts_lock = threading.Lock()
ip_packet_counts = defaultdict(int)
ip_syn_counts = defaultdict(int)

def reset_counts():
    """ Resets the traffic counters every 5 seconds """
    global ip_packet_counts, ip_syn_counts

    with counts_lock:
        print("\n--- RESETTING TRAFFIC COUNTS ---")
        ip_packet_counts.clear()
        ip_syn_counts.clear()

    # Schedule this function to run again in 5 seconds
    threading.Timer(5.0, reset_counts).start()

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        with counts_lock:
            ip_packet_counts[src_ip] += 1
            if packet.haslayer(TCP) and packet[TCP].flags == 'S':
                ip_syn_counts[src_ip] += 1

        # Check thresholds (can be outside the lock)
        if ip_packet_counts[src_ip] > PACKET_THRESHOLD:
            print(f"ALERT: Packet threshold exceeded from {src_ip} (Count: {ip_packet_counts[src_ip]})")
            # TODO: Call block_ip(src_ip)

        if ip_syn_counts[src_ip] > SYN_THRESHOLD:
            print(f"ALERT: SYN flood detected from {src_ip} (Count: {ip_syn_counts[src_ip]})")
            # TODO: Call block_ip(src_ip)

# --- MAIN EXECUTION ---
print("Starting count reset timer...")
reset_thread = threading.Timer(5.0, reset_counts)
reset_thread.daemon = True  # Allows the program to exit even if the timer is active
reset_thread.start()

print("Starting packet sniffer...")
sniff(iface="enp0s3", prn=process_packet, store=0)


Test: Run sudo python3 ddos_detector.py. You should see "RESETTING TRAFFIC COUNTS" print every 5 seconds.

Phase 4: Mitigation Module - The "Shield" (1-2 Days)

Goal: Automatically block malicious IPs using the Linux firewall.

4.1: Create Blocking Function:

[ ] How-to: Add this function to ddos_detector.py.

import subprocess
# ... other imports ...

def block_ip(ip_address):
    """ Blocks an IP address using iptables """
    print(f"MITIGATION: Blocking IP {ip_address}")
    try:
        # -I INPUT 1: Insert rule at the top of the INPUT chain to ensure it's hit first
        command = ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"]
        subprocess.run(command, check=True, capture_output=True)
        print(f"Successfully blocked {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block {ip_address}: {e.stderr.decode()}")
    except FileNotFoundError:
        print("Error: 'iptables' command not found. This script must be run on Linux.")


4.2: Integrate Detection with Mitigation:

[ ] How-to: In process_packet, replace the TODO comments with calls to block_ip().

def process_packet(packet):
    # ... (counting logic) ...

    # Check thresholds
    if ip_packet_counts[src_ip] > PACKET_THRESHOLD:
        print(f"ALERT: Packet threshold exceeded from {src_ip} (Count: {ip_packet_counts[src_ip]})")
        block_ip(src_ip) # <--- ADDED THIS

    if ip_syn_counts[src_ip] > SYN_THRESHOLD:
        print(f"ALERT: SYN flood detected from {src_ip} (Count: {ip_syn_counts[src_ip]})")
        block_ip(src_ip) # <--- ADDED THIS


4.3: Prevent Re-blocking:

[ ] How-to: Add a set to track blocked IPs and make the block_ip function "idempotent" (safe to call multiple times).

# ...
# --- DATA STRUCTURES ---
counts_lock = threading.Lock()
ip_packet_counts = defaultdict(int)
ip_syn_counts = defaultdict(int)

blocked_ips_lock = threading.Lock()
blocked_ips = set()

# ...

def block_ip(ip_address):
    """ Blocks an IP address using iptables (now thread-safe and idempotent) """
    with blocked_ips_lock:
        if ip_address in blocked_ips:
            # This IP is already blocked, do nothing
            return

        print(f"MITIGATION: Blocking IP {ip_address}")
        try:
            command = ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"]
            subprocess.run(command, check=True, capture_output=True)
            print(f"Successfully blocked {ip_address}")
            # Add to our set ONLY on success
            blocked_ips.add(ip_address) 
        except subprocess.CalledProcessError as e:
            print(f"Failed to block {ip_address}: {e.stderr.decode()}")
        except FileNotFoundError:
            print("Error: 'iptables' command not found.")


Now you can call block_ip(src_ip) 100 times, but it will only run the iptables command once.

Phase 5: Testing & Simulation (1-2 Days)

Goal: Prove that your system works by simulating a real attack.

5.1: Create attack.py (Optional but recommended):

[ ] How-to: Create a new file attack.py.

Find your VM's IP address: ip a (e.g., 10.0.2.15).

nano attack.py

Paste this code, changing YOUR_VM_IP:

# attack.py
from scapy.all import IP, TCP, send
import time

target_ip = "YOUR_VM_IP"  # <--- CHANGE THIS
target_port = 80

print(f"Attacking {target_ip} on port {target_port} with SYN flood...")

while True:
    # Forge a SYN packet
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    send(packet, verbose=0)
    # verbose=0 suppresses scapy's "Sent 1 packet" message


5.2: Test with hping3 (SYN Flood):

[ ] How-to: This is the main test.

Open two terminals in your VM.

Terminal 1: Start your detector: sudo python3 ddos_detector.py.

Terminal 2: Get your IP (ip a) and launch the hping3 attack against yourself (127.0.0.1 also works):

# -S = SYN flag, --flood = send as fast as possible, -p 80 = port 80
sudo hping3 -S --flood -p 80 127.0.0.1 


Observe (Terminal 1): Within 5 seconds, you should see the "ALERT" and "MITIGATION: Blocking IP 127.0.0.1" messages.

Verify (Terminal 2): The hping3 tool might freeze or stop. Press Ctrl+C to stop it.

Verify Firewall (New Terminal): Open a third terminal and check the firewall rules. The -n (numeric) and -v (verbose) flags give more detail.

sudo iptables -L -n -v


You should see a DROP rule for 127.0.0.1 at the top of the INPUT chain, showing how many packets it has blocked.

5.3: Create an "Unblock" Script:

[ ] How-to: Create a shell script to clean up for the next test.

nano unblock_all.sh

Paste this in:

#!/bin/bash
echo "Flushing (clearing) all iptables rules..."
sudo iptables -F
echo "Firewall rules cleared."


Make it executable: chmod +x unblock_all.sh

How to use: After a test, run ./unblock_all.sh. Important: You must also restart your ddos_detector.py script to clear its internal blocked_ips set.

Phase 6: Logging & Monitoring (1-2 Days)

Goal: Fulfill the deliverable for logging and a simple interface.

6.1: Implement File Logging:

[ ] How-to: Add Python's built-in logging to your ddos_detector.py.

import logging
# ... other imports ...

# --- LOGGING SETUP ---
logging.basicConfig(filename='ddos_events.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ...

def block_ip(ip_address):
    # ...
    try:
        # ...
        print(f"Successfully blocked {ip_address}")
        logging.warning(f"Blocked {ip_address} for suspected DDoS.") # <--- ADD THIS
        blocked_ips.add(ip_address)
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode()
        print(f"Failed to block {ip_address}: {error_msg}")
        logging.error(f"Failed to block {ip_address}: {error_msg}") # <--- ADD THIS
    # ...


Test: Run a test. After blocking an IP, stop the script and check the new file: cat ddos_events.log.

6.2: Create CLI Dashboard (Simple):

[ ] How-to: Use the rich library for a clean terminal UI.

Install: pip3 install rich

Add to ddos_detector.py:

from rich.console import Console
from rich.table import Table
# ...

console = Console()

# ...

def reset_counts():
    """ Resets counters and prints a summary table """
    global ip_packet_counts, ip_syn_counts

    with counts_lock:
        if not ip_packet_counts: # Don't print empty tables
            print("\n--- RESETTING TRAFFIC COUNTS (No traffic) ---")
            return

        print("\n--- TRAFFIC SUMMARY (5s) ---")

        # Sort IPs by packet count, descending
        top_packet_ips = sorted(ip_packet_counts.items(), key=lambda item: item[1], reverse=True)[:10]

        table = Table(title="Top 10 IPs by Packet Count")
        table.add_column("IP Address", style="cyan")
        table.add_column("Packet Count", style="magenta")
        table.add_column("SYN Count", style="yellow")

        for ip, count in top_packet_ips:
            syn_count = ip_syn_counts.get(ip, 0) # Get SYN count, default to 0
            table.add_row(ip, str(count), str(syn_count))

        console.print(table)

        # Clear counts for next window
        ip_packet_counts.clear()
        ip_syn_counts.clear()

    threading.Timer(5.0, reset_counts).start()


Test: Run sudo python3 ddos_detector.py. You'll now get a beautiful table every 5 seconds.

6.3: Create Web Dashboard (Advanced/Optional):

[ ] How-to: This involves 3 files.

Install Flask: pip3 install flask

Modify ddos_detector.py: Add this to your reset_counts function, just before clearing the dictionaries.

import json
# ...
def reset_counts():
    with counts_lock:
        # ... (logic for printing table) ...

        # --- Write stats to JSON file for dashboard ---
        try:
            top_10_dict = dict(top_packet_ips) # Convert list of tuples to dict
            stats_data = {
                'packet_counts': top_10_dict,
                'blocked_ips': list(blocked_ips)
            }
            with open('stats.json', 'w') as f:
                json.dump(stats_data, f)
        except Exception as e:
            print(f"Error writing stats.json: {e}")

        # ... (clear dictionaries) ...
    # ... (start timer) ...


Create dashboard.py:

# dashboard.py
from flask import Flask, jsonify, send_from_directory
import os

app = Flask(__name__)

# Serve the HTML file
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# API endpoint to get the stats
@app.route('/api/stats')
def get_stats():
    try:
        with open('stats.json', 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except FileNotFoundError:
        # Return empty data if detector hasn't written the file yet
        return jsonify({'packet_counts': {}, 'blocked_ips': []})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # host='0.0.0.0' makes it accessible from your host machine's browser
    app.run(debug=True, host='0.0.0.0', port=5001)


Create index.html:

<!-- index.html -->
<!DOCTYPE html>
<html>
<head>
    <title>DDoS Detector Dashboard</title>
    <script src="[https://cdn.jsdelivr.net/npm/chart.js](https://cdn.jsdelivr.net/npm/chart.js)"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: grid; grid-template-columns: 2fr 1fr; gap: 20px; padding: 20px; background: #f4f7f6; }
        .chart-container { width: 95%; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        #blocked-ips { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; }
        ul { max-height: 400px; overflow-y: auto; }
        li { background: #ffebeb; color: #c53030; padding: 8px; border-radius: 4px; margin-bottom: 5px; font-weight: 500; }
    </style>
</head>
<body>
    <div class="chart-container">
        <h2>Live Traffic (Top 10 IPs)</h2>
        <canvas id="trafficChart"></canvas>
    </div>
    <div id="blocked-ips">
        <h2>Blocked IPs</h2>
        <ul id="ip-list"></ul>
    </div>

    <script>
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(ctx, {
            type: 'bar',
            data: { labels: [], datasets: [{ label: 'Packets per 5s', data: [], backgroundColor: '#3498db' }] },
            options: { scales: { y: { beginAtZero: true } }, animation: { duration: 500 } }
        });

        async function updateStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();

                // Update Chart
                const ips = Object.keys(data.packet_counts);
                const counts = Object.values(data.packet_counts);
                trafficChart.data.labels = ips;
                trafficChart.data.datasets[0].data = counts;
                trafficChart.update();

                // Update Blocked IP List
                const ipList = document.getElementById('ip-list');
                ipList.innerHTML = ''; // Clear list
                data.blocked_ips.forEach(ip => {
                    const li = document.createElement('li');
                    li.textContent = ip;
                    ipList.appendChild(li);
                });

            } catch (error) {
                console.error('Error fetching stats:', error);
            }
        }

        setInterval(updateStats, 2000); // Update every 2 seconds
        updateStats(); // Initial load
    </script>
</body>
</html>


Test: Run the detector (sudo python3 ddos_detector.py) and the dashboard (python3 dashboard.py). Open your VM's browser to http://127.0.0.1:5001 to see it live.

Phase 7: Project Finalization (2-3 Days)

Goal: Complete all project deliverables as per your proposal.

[ ] 7.1: Write Project Documentation:

How-to: Create a Project_Report.md or Word document. Include:

Introduction: State the problem (DDoS attacks) and your solution (real-time detection).

System Architecture: Create a simple diagram (e.g., Sniffer -> Detector -> Mitigator). Explain what each module does.

Implementation Details: Show key code snippets (your process_packet and block_ip functions) and explain why they work.

Algorithm: Explain your "packet/SYN counts per 5-second time window" logic.

[ ] 7.2: Prepare Test Results:

How-to: Run your hping3 test from Phase 5.2. Take screenshots of:

Terminal 1 (Detector) showing the "ALERT" and "MITIGATION" messages.

Terminal 2 (Attacker) running hping3.

Terminal 3 (Firewall) showing the output of sudo iptables -L -n -v with the DROP rule.

(Optional) A screenshot of your web dashboard showing the attack graph and the blocked IP.

[ ] 7.3: Record Demo:

How-to: Use a screen recorder (like OBS Studio or Kazam on Ubuntu).

Script:

Start with no rules (./unblock_all.sh). Show the empty iptables -L output.

Start your detector (sudo ... ddos_detector.py).

Start your dashboard (python3 ... dashboard.py) and show it in the browser.

Start the attack (sudo ... hping3 ...).

Switch to the dashboard and show the graph spike and the IP appearing in the "Blocked" list.

Show the detector terminal and point out the "MITIGATION" log.

Show the iptables -L output again, now with the DROP rule.

Phase 8: (Optional) ML Model Integration (3-5+ Days)

Goal: Replace the simple rule-based engine with a "smarter" ML model.

[ ] 8.1: Download Dataset:

How-to: Search for "CIC-DDoS2019 dataset". You'll find it on the Canadian Institute for Cybersecurity website. You only need one of the CSV files (e.g., DrDoS_NTP.csv).

[ ] 8.2: Write Offline Trainer (train_model.py):

How-to: This is a separate script to build your model.

# train_model.py (Simplified Skeleton)
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

print("Loading dataset...")
# Download and place the CSV in the same folder
# Make sure to get the CSV with "Label" column, not just traffic flow
df = pd.read_csv('your_dataset_file.csv')

# --- Feature Engineering ---
# This is the hardest part. You must clean the data.
df.columns = df.columns.str.strip() # Clean column names

# Replace infinity values (if any)
df.replace([float('inf'), float('-inf')], float('nan'), inplace=True)
# Drop rows with any NaN values
df.dropna(inplace=True)

# Convert labels: 'BENIGN' -> 0, 'DDoS' (or other attack) -> 1
df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

# Define your features (X) and target (y)
# Use simple, easy-to-calculate features first
features = [
    'Protocol', 'Flow Duration', 'Total Fwd Packets', 
    'Total Backward Packets', 'Fwd Packet Length Max', 
    'Bwd Packet Length Max', 'Flow IAT Mean', 'Fwd IAT Mean'
]
target = 'Label'

X = df[features]
y = df[target]

if X.empty:
    print("Error: No data left after cleaning. Check features and dataset.")
else:
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    print("Training model (RandomForest)...")
    # n_estimators=50 is fast, n_jobs=-1 uses all CPU cores
    model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    print("Evaluating model...")
    preds = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, preds) * 100:.2f}%")

    print("Saving model...")
    joblib.dump(model, 'ddos_model.pkl')
    print("Model saved as ddos_model.pkl")


Run this (it might take a while): python3 train_model.py

[ ] 8.3: Modify Real-Time Engine:

How-to: This is a major change.

You can't use your simple ip_packet_counts anymore.

You must create a "Flow Manager" class that tracks traffic flows (a flow is defined by SrcIP, DstIP, SrcPort, DstPort, Protocol).

For each packet, you update its corresponding flow and calculate features like Flow Duration, Flow IAT Mean, etc., in real-time.

This is significantly more complex than the rule-based approach and requires deep knowledge of networking and data structures. I strongly recommend completing Phases 1-7 first.