"""
Phase 4: Mitigation Module - The "Shield"
Real-Time DDoS Detection System

This module provides IP blocking functionality using Linux iptables firewall.
Features:
- Thread-safe IP blocking
- Idempotent operations (safe to call multiple times)
- Automatic duplicate prevention
- Error handling and logging
- Integration with logging module (Phase 6)
"""

import subprocess
import threading
from typing import Set, Optional, Dict
from datetime import datetime, timedelta
import time


class Mitigator:
    """
    Handles IP address blocking using Linux iptables firewall.
    
    This class provides thread-safe methods to block malicious IP addresses
    and track which IPs have been blocked to prevent duplicate operations.
    Includes automatic IP unblocking after expiration time.
    """
    
    def __init__(self, block_duration_minutes: int = 60):
        """Initialize the Mitigator with an empty set of blocked IPs.
        
        Args:
            block_duration_minutes (int): How long to keep IPs blocked (default: 60 minutes)
        """
        self.blocked_ips: Set[str] = set()
        self.blocked_ips_timestamps: Dict[str, datetime] = {}  # Track when IPs were blocked
        self.lock = threading.Lock()
        self.block_duration = timedelta(minutes=block_duration_minutes)
        self._check_iptables_available()
        
        # Start cleanup thread for expired blocks
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_blocks, daemon=True)
        self.cleanup_running = True
        self.cleanup_thread.start()
    
    def _check_iptables_available(self) -> bool:
        """
        Check if iptables is available on the system.
        
        Returns:
            bool: True if iptables is available, False otherwise
        """
        try:
            result = subprocess.run(
                ["which", "iptables"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode != 0:
                print("[WARNING] iptables not found. Blocking will be simulated.")
                print("[INFO] This is normal on Windows. Run in Linux VM for actual blocking.")
                return False
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            print("[WARNING] Cannot check for iptables. Blocking will be simulated.")
            return False
    
    def block_ip(self, ip_address: str) -> bool:
        """
        Block an IP address using iptables firewall.
        
        This method is thread-safe and idempotent (safe to call multiple times
        for the same IP). It will only attempt to block an IP once.
        
        Args:
            ip_address (str): The IP address to block (e.g., "192.168.1.100")
        
        Returns:
            bool: True if blocking was successful or IP was already blocked,
                  False if blocking failed
        """
        with self.lock:
            # Check if IP is already blocked
            if ip_address in self.blocked_ips:
                print(f"[INFO] IP {ip_address} is already blocked. Skipping.")
                return True
            
            print(f"\n{'='*70}")
            print(f"🛡️  MITIGATION ACTION: Blocking IP {ip_address}")
            print(f"{'='*70}")
            
            try:
                # Build iptables command
                # -I INPUT 1: Insert at position 1 (top of chain) for priority
                # -s: Source IP address
                # -j DROP: Jump to DROP target (silently discard packets)
                command = [
                    "iptables",
                    "-I", "INPUT", "1",
                    "-s", ip_address,
                    "-j", "DROP"
                ]
                
                # Execute the command
                result = subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Success!
                self.blocked_ips.add(ip_address)
                self.blocked_ips_timestamps[ip_address] = datetime.now()
                print(f"✅ Successfully blocked {ip_address}")
                print(f"📊 Total blocked IPs: {len(self.blocked_ips)}")
                print(f"{'='*70}\n")
                return True
                
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr if e.stderr else str(e)
                print(f"❌ Failed to block {ip_address}")
                print(f"Error: {error_msg}")
                print(f"{'='*70}\n")
                return False
                
            except subprocess.TimeoutExpired:
                print(f"❌ Timeout while trying to block {ip_address}")
                print(f"{'='*70}\n")
                return False
                
            except FileNotFoundError:
                # iptables not found - simulate blocking for development
                print(f"⚠️  SIMULATED BLOCK (iptables not available)")
                print(f"In production Linux environment, {ip_address} would be blocked")
                self.blocked_ips.add(ip_address)
                self.blocked_ips_timestamps[ip_address] = datetime.now()
                print(f"📊 Total simulated blocks: {len(self.blocked_ips)}")
                print(f"{'='*70}\n")
                return True
                
            except Exception as e:
                print(f"❌ Unexpected error blocking {ip_address}: {e}")
                print(f"{'='*70}\n")
                return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address by removing the iptables rule.
        
        Args:
            ip_address (str): The IP address to unblock
        
        Returns:
            bool: True if unblocking was successful, False otherwise
        """
        with self.lock:
            if ip_address not in self.blocked_ips:
                print(f"[INFO] IP {ip_address} is not in blocked list.")
                return True
            
            try:
                # -D INPUT: Delete from INPUT chain
                command = [
                    "iptables",
                    "-D", "INPUT",
                    "-s", ip_address,
                    "-j", "DROP"
                ]
                
                result = subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                self.blocked_ips.remove(ip_address)
                if ip_address in self.blocked_ips_timestamps:
                    del self.blocked_ips_timestamps[ip_address]
                print(f"✅ Successfully unblocked {ip_address}")
                return True
                
            except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
                print(f"❌ Failed to unblock {ip_address}: {e}")
                return False
    
    def get_blocked_ips(self) -> Set[str]:
        """
        Get the set of currently blocked IP addresses.
        
        Returns:
            Set[str]: A copy of the blocked IPs set
        """
        with self.lock:
            return self.blocked_ips.copy()
    
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is currently blocked.
        
        Args:
            ip_address (str): The IP address to check
        
        Returns:
            bool: True if the IP is blocked, False otherwise
        """
        with self.lock:
            return ip_address in self.blocked_ips
    
    def get_blocked_count(self) -> int:
        """
        Get the total number of blocked IP addresses.
        
        Returns:
            int: Number of blocked IPs
        """
        with self.lock:
            return len(self.blocked_ips)
    
    def clear_all_blocks(self) -> int:
        """
        Clear all blocked IPs (use with caution!).
        
        Returns:
            int: Number of IPs that were unblocked
        """
        with self.lock:
            count = len(self.blocked_ips)
            ips_to_unblock = list(self.blocked_ips)
        
        # Unblock outside the lock to avoid deadlock
        for ip in ips_to_unblock:
            self.unblock_ip(ip)
        
        return count
    
    def _cleanup_expired_blocks(self):
        """
        Background thread that automatically unblocks IPs after expiration time.
        Runs every 60 seconds to check for expired blocks.
        """
        while self.cleanup_running:
            time.sleep(60)  # Check every minute
            
            now = datetime.now()
            expired_ips = []
            
            with self.lock:
                for ip, blocked_time in list(self.blocked_ips_timestamps.items()):
                    if now - blocked_time > self.block_duration:
                        expired_ips.append(ip)
            
            # Unblock expired IPs
            for ip in expired_ips:
                print(f"[INFO] Auto-unblocking {ip} (block expired)")
                self.unblock_ip(ip)
    
    def stop_cleanup(self):
        """Stop the cleanup thread (call on shutdown)."""
        self.cleanup_running = False


# Test the module if run directly
if __name__ == "__main__":
    print("="*70)
    print("MITIGATOR MODULE TEST")
    print("="*70)
    print()
    
    # Create mitigator instance
    mitigator = Mitigator()
    
    # Test blocking
    print("Test 1: Block a test IP")
    mitigator.block_ip("192.168.1.100")
    
    print("\nTest 2: Try blocking the same IP again (should skip)")
    mitigator.block_ip("192.168.1.100")
    
    print("\nTest 3: Block another IP")
    mitigator.block_ip("10.0.0.50")
    
    print("\nTest 4: Check blocked IPs")
    print(f"Blocked IPs: {mitigator.get_blocked_ips()}")
    print(f"Total blocked: {mitigator.get_blocked_count()}")
    
    print("\nTest 5: Check if IP is blocked")
    print(f"Is 192.168.1.100 blocked? {mitigator.is_blocked('192.168.1.100')}")
    print(f"Is 8.8.8.8 blocked? {mitigator.is_blocked('8.8.8.8')}")
    
    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)
