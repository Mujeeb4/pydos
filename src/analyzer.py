"""
Traffic Analyzer Module - Historical Analysis & Anomaly Detection

PURPOSE: This module provides HISTORICAL traffic analysis and anomaly detection
based on baseline patterns. It is SEPARATE from the real-time detector.

DIFFERENCE FROM detector.py:
- detector.py: Real-time detection using fixed thresholds, blocks IPs immediately
- analyzer.py: Historical analysis, builds baseline, detects deviations from normal

USE CASES:
- Post-incident analysis
- Building traffic baselines
- Statistical anomaly detection
- Traffic pattern profiling

This is an OPTIONAL component, not required for basic detection.
"""

from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Any
from datetime import datetime
import statistics


class TrafficAnalyzer:
    """
    Analyzes network traffic patterns to identify anomalies and trends.
    """
    
    def __init__(self):
        """Initialize the traffic analyzer."""
        self.traffic_history: List[Dict[str, Any]] = []
        self.ip_statistics: Dict[str, Dict[str, int]] = defaultdict(lambda: {
            'total_packets': 0,
            'syn_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0
        })
    
    def add_traffic_snapshot(self, ip_counts: Dict[str, int], syn_counts: Dict[str, int]):
        """
        Add a traffic snapshot for analysis.
        
        Args:
            ip_counts (dict): IP to packet count mapping
            syn_counts (dict): IP to SYN packet count mapping
        """
        snapshot = {
            'timestamp': datetime.now(),
            'total_packets': sum(ip_counts.values()),
            'unique_ips': len(ip_counts),
            'top_talkers': dict(Counter(ip_counts).most_common(10)),
            'syn_packets': sum(syn_counts.values())
        }
        self.traffic_history.append(snapshot)
        
        # Update IP statistics
        for ip, count in ip_counts.items():
            self.ip_statistics[ip]['total_packets'] += count
        
        for ip, count in syn_counts.items():
            self.ip_statistics[ip]['syn_packets'] += count
    
    def get_top_talkers(self, n: int = 10) -> List[Tuple[str, int]]:
        """
        Get the top N IPs by packet count.
        
        Args:
            n (int): Number of top talkers to return
            
        Returns:
            list: List of (IP, packet_count) tuples
        """
        sorted_ips = sorted(
            self.ip_statistics.items(),
            key=lambda x: x[1]['total_packets'],
            reverse=True
        )
        return [(ip, stats['total_packets']) for ip, stats in sorted_ips[:n]]
    
    def get_traffic_statistics(self) -> Dict[str, Any]:
        """
        Get overall traffic statistics.
        
        Returns:
            dict: Statistics including averages, totals, etc.
        """
        if not self.traffic_history:
            return {
                'total_packets': 0,
                'average_packets_per_window': 0,
                'unique_ips_seen': 0,
                'snapshots_recorded': 0
            }
        
        total_packets = sum(s['total_packets'] for s in self.traffic_history)
        avg_packets = statistics.mean(s['total_packets'] for s in self.traffic_history)
        
        return {
            'total_packets': total_packets,
            'average_packets_per_window': round(avg_packets, 2),
            'unique_ips_seen': len(self.ip_statistics),
            'snapshots_recorded': len(self.traffic_history)
        }
    
    def detect_anomalies(self, current_counts: Dict[str, int], threshold_multiplier: float = 3.0) -> List[str]:
        """
        Detect anomalous IPs based on historical data.
        
        Args:
            current_counts (dict): Current packet counts per IP
            threshold_multiplier (float): Standard deviations above mean to flag
            
        Returns:
            list: List of anomalous IP addresses
        """
        if len(self.traffic_history) < 3:
            return []  # Need more history for analysis
        
        anomalous_ips = []
        
        # Calculate historical average and std dev for each IP
        for ip, current_count in current_counts.items():
            if ip in self.ip_statistics:
                historical_avg = self.ip_statistics[ip]['total_packets'] / len(self.traffic_history)
                
                # Simple anomaly detection: if current is significantly higher than average
                if current_count > historical_avg * threshold_multiplier:
                    anomalous_ips.append(ip)
        
        return anomalous_ips
    
    def get_ip_profile(self, ip_address: str) -> Dict[str, Any]:
        """
        Get detailed profile for a specific IP.
        
        Args:
            ip_address (str): IP address to profile
            
        Returns:
            dict: IP profile with statistics
        """
        if ip_address not in self.ip_statistics:
            return {'error': 'IP not found in statistics'}
        
        stats = self.ip_statistics[ip_address]
        return {
            'ip_address': ip_address,
            'total_packets': stats['total_packets'],
            'syn_packets': stats['syn_packets'],
            'udp_packets': stats['udp_packets'],
            'icmp_packets': stats['icmp_packets'],
            'syn_ratio': stats['syn_packets'] / stats['total_packets'] if stats['total_packets'] > 0 else 0
        }
    
    def clear_history(self):
        """Clear all traffic history and statistics."""
        self.traffic_history.clear()
        self.ip_statistics.clear()


# Test the module if run directly
if __name__ == "__main__":
    print("="*70)
    print("TESTING TRAFFIC ANALYZER")
    print("="*70)
    print()
    
    analyzer = TrafficAnalyzer()
    
    # Simulate some traffic
    print("Test 1: Adding traffic snapshots")
    analyzer.add_traffic_snapshot(
        {'192.168.1.100': 50, '192.168.1.101': 30, '10.0.0.1': 20},
        {'192.168.1.100': 25, '192.168.1.101': 15}
    )
    analyzer.add_traffic_snapshot(
        {'192.168.1.100': 55, '192.168.1.101': 28, '10.0.0.1': 18},
        {'192.168.1.100': 27, '192.168.1.101': 14}
    )
    print("  Added 2 snapshots")
    
    print()
    print("Test 2: Get top talkers")
    top_talkers = analyzer.get_top_talkers(3)
    for ip, count in top_talkers:
        print(f"  {ip:20} - {count} packets")
    
    print()
    print("Test 3: Traffic statistics")
    stats = analyzer.get_traffic_statistics()
    for key, value in stats.items():
        print(f"  {key:30} - {value}")
    
    print()
    print("Test 4: IP profile")
    profile = analyzer.get_ip_profile('192.168.1.100')
    for key, value in profile.items():
        print(f"  {key:20} - {value}")
    
    print()
    print("="*70)
    print("ALL TESTS COMPLETE")
    print("="*70)
