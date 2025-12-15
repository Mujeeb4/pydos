
from scapy.all import IP, TCP, UDP, ICMP, sniff
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import configuration from central config file
try:
    from config.config import NETWORK_INTERFACE
except ImportError:
    NETWORK_INTERFACE = "wlp1s0"  # Fallback default

def process_packet(packet):
    """
    This function is called for every packet sniffed.
    Extracts and displays detailed IP and TCP information.
    """
    
    # Check if it's an IP packet
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Protocol mapping for readable output
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"Unknown({proto})")
        
        print(f"[IP] {src_ip:15} -> {dst_ip:15} | Protocol: {proto_name}")
        
        # Check if it's a TCP packet (which is inside the IP packet)
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # Flag interpretation
            flag_str = str(flags)
            flag_desc = []
            if 'S' in flag_str: flag_desc.append("SYN")
            if 'A' in flag_str: flag_desc.append("ACK")
            if 'F' in flag_str: flag_desc.append("FIN")
            if 'R' in flag_str: flag_desc.append("RST")
            if 'P' in flag_str: flag_desc.append("PSH")
            if 'U' in flag_str: flag_desc.append("URG")
            
            flags_readable = "|".join(flag_desc) if flag_desc else "NONE"
            
            print(f"  └─[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags_readable} ({flags})")
        
        # Check if it's a UDP packet
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  └─[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Check if it's an ICMP packet
        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"  └─[ICMP] Type: {icmp_type} | Code: {icmp_code}")
        
        print()  # Blank line for readability

def main():
    """Main function to start the packet sniffer"""
    print("="*70)
    print("="*70)
    print()
    print(f"Network Interface: {NETWORK_INTERFACE}")
    print()
    print("Capturing Details:")
    print("  • Source & Destination IP addresses")
    print("  • Protocol type (TCP/UDP/ICMP)")
    print("  • TCP/UDP port numbers")
    print("  • TCP flags (SYN, ACK, FIN, RST, PSH, URG)")
    print()
    print("Starting packet capture...")
    print("Press Ctrl+C to stop")
    print("="*70)
    print()
    
    try:
        sniff(iface=NETWORK_INTERFACE, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n")
        print("="*70)
        print("Stopping packet sniffer...")
        print("="*70)
        print("Capture complete!")
    except PermissionError:
        print("\n[ERROR] Permission denied!")
        print()
        print("This script requires root privileges to capture packets.")
        print()
        print("Run with sudo:")
        print(f"  sudo python3 sniffer.py")
        print()
        print("Or if using virtual environment:")
        print("  source venv/bin/activate")
        print(f"  sudo $(which python3) sniffer.py")
    except OSError as e:
        print(f"\n[ERROR] Network interface error: {e}")
        print()
        print(f"Interface '{NETWORK_INTERFACE}' may not exist.")
        print("Check available interfaces with: ip a")
        print()
        print("Update the NETWORK_INTERFACE variable in this script.")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")

if __name__ == "__main__":
    main()