"""
Tests for Unified Detector Module (detector.py)

Tests the unified detection engine for both DoS and DDoS attacks.
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from collections import defaultdict
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestUnifiedDetectorInitialization:
    """Test unified detector initialization."""
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_detector_initialization(self, mock_mitigator, mock_logger):
        """Test that detector initializes correctly."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        assert detector.total_packets == 0
        assert detector.total_syn == 0
        assert detector.total_udp == 0
        assert detector.total_icmp == 0
        assert len(detector.ip_packet_counts) == 0
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_detector_stats_initialization(self, mock_mitigator, mock_logger):
        """Test detector stats are initialized correctly."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        assert detector.stats["total_packets_all_time"] == 0
        assert detector.stats["dos_attacks_detected"] == 0
        assert detector.stats["ddos_attacks_detected"] == 0
        assert detector.stats["ips_blocked"] == 0


class TestPacketCounting:
    """Test packet counting mechanisms."""
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_update_counters_tcp(self, mock_mitigator, mock_logger):
        """Test TCP packet counter updates."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        detector._update_counters("192.168.1.100", "tcp")
        
        assert detector.ip_packet_counts["192.168.1.100"] == 1
        assert detector.total_packets == 1
        assert detector.total_syn == 0
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_update_counters_syn(self, mock_mitigator, mock_logger):
        """Test SYN packet counter updates."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        detector._update_counters("192.168.1.100", "syn")
        
        assert detector.ip_packet_counts["192.168.1.100"] == 1
        assert detector.ip_syn_counts["192.168.1.100"] == 1
        assert detector.total_syn == 1
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_update_counters_udp(self, mock_mitigator, mock_logger):
        """Test UDP packet counter updates."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        detector._update_counters("192.168.1.100", "udp")
        
        assert detector.ip_udp_counts["192.168.1.100"] == 1
        assert detector.total_udp == 1
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_update_counters_icmp(self, mock_mitigator, mock_logger):
        """Test ICMP packet counter updates."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        detector._update_counters("192.168.1.100", "icmp")
        
        assert detector.ip_icmp_counts["192.168.1.100"] == 1
        assert detector.total_icmp == 1
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_multiple_ips(self, mock_mitigator, mock_logger):
        """Test counting from multiple IPs."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        for i in range(10):
            detector._update_counters(f"192.168.1.{i}", "tcp")
        
        assert len(detector.ip_packet_counts) == 10
        assert detector.total_packets == 10
        assert len(detector.window_all_ips) == 10


class TestIPTracking:
    """Test IP tracking for spike detection."""
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_new_ip_tracking(self, mock_mitigator, mock_logger):
        """Test that new IPs are tracked correctly."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        # First IP should be new
        detector._update_counters("192.168.1.100", "tcp")
        assert "192.168.1.100" in detector.window_new_ips
        assert "192.168.1.100" in detector.window_all_ips
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_known_ip_not_new(self, mock_mitigator, mock_logger):
        """Test that known IPs are not marked as new."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        # Add IP to known set
        detector.known_ips.add("192.168.1.100")
        
        # Now send packet - should not be marked as new
        detector._update_counters("192.168.1.100", "tcp")
        assert "192.168.1.100" not in detector.window_new_ips
        assert "192.168.1.100" in detector.window_all_ips


class TestWindowReset:
    """Test detection window reset."""
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_reset_clears_counters(self, mock_mitigator, mock_logger):
        """Test that reset clears all counters."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        # Add some data
        detector._update_counters("192.168.1.100", "syn")
        detector._update_counters("192.168.1.101", "udp")
        
        assert detector.total_packets == 2
        
        # Reset
        detector.reset_window()
        
        # Check everything is cleared
        assert detector.total_packets == 0
        assert detector.total_syn == 0
        assert detector.total_udp == 0
        assert len(detector.ip_packet_counts) == 0
        assert len(detector.window_all_ips) == 0
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_reset_preserves_known_ips(self, mock_mitigator, mock_logger):
        """Test that reset moves new IPs to known IPs."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        # Add new IP
        detector._update_counters("192.168.1.100", "tcp")
        assert "192.168.1.100" in detector.window_new_ips
        
        # Reset
        detector.reset_window()
        
        # IP should now be known
        assert "192.168.1.100" in detector.known_ips
        assert "192.168.1.100" not in detector.window_new_ips


class TestSeverityCalculation:
    """Test severity calculation."""
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_severity_low(self, mock_mitigator, mock_logger):
        """Test low severity calculation."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        severity = detector._calculate_severity(110, 100)  # 1.1x
        assert severity == 'low'
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_severity_medium(self, mock_mitigator, mock_logger):
        """Test medium severity calculation."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        severity = detector._calculate_severity(250, 100)  # 2.5x
        assert severity == 'medium'
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_severity_high(self, mock_mitigator, mock_logger):
        """Test high severity calculation."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        severity = detector._calculate_severity(600, 100)  # 6x
        assert severity == 'high'
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_severity_critical(self, mock_mitigator, mock_logger):
        """Test critical severity calculation."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        severity = detector._calculate_severity(1500, 100)  # 15x
        assert severity == 'critical'


class TestAlertDataclass:
    """Test Alert dataclass."""
    
    def test_alert_creation(self):
        """Test creating an Alert."""
        from detector import Alert
        
        alert = Alert(
            timestamp=datetime.now(),
            attack_type="DoS: SYN_FLOOD",
            source_ip="192.168.1.100",
            severity="high",
            description="SYN flood attack",
            packet_count=500,
            threshold=50
        )
        
        assert alert.attack_type == "DoS: SYN_FLOOD"
        assert alert.source_ip == "192.168.1.100"
        assert alert.severity == "high"
        assert alert.packet_count == 500


class TestGetStats:
    """Test statistics retrieval."""
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_get_stats(self, mock_mitigator, mock_logger):
        """Test getting detector statistics."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        # Add some data
        for i in range(5):
            detector._update_counters(f"192.168.1.{i}", "syn")
        
        stats = detector.get_stats()
        
        assert "uptime" in stats
        assert "total_packets" in stats
        assert "dos_attacks" in stats
        assert "ddos_attacks" in stats
        assert stats["total_packets"] == 5


class TestTopSources:
    """Test top sources retrieval."""
    
    @patch('detector.get_logger')
    @patch('detector.Mitigator')
    def test_get_top_sources(self, mock_mitigator, mock_logger):
        """Test getting top source IPs."""
        mock_logger.return_value = MagicMock()
        mock_mitigator.return_value = MagicMock()
        
        from detector import UnifiedDetector
        
        detector = UnifiedDetector()
        
        # Add varying packet counts
        for _ in range(50):
            detector._update_counters("192.168.1.1", "tcp")
        for _ in range(30):
            detector._update_counters("192.168.1.2", "tcp")
        for _ in range(10):
            detector._update_counters("192.168.1.3", "tcp")
        
        top = detector._get_top_sources(2)
        
        assert len(top) == 2
        assert top[0][0] == "192.168.1.1"
        assert top[0][1] == 50
        assert top[1][0] == "192.168.1.2"
        assert top[1][1] == 30
