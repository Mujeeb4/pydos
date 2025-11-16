"""
Tests for Logger Module (logger.py)

Tests logging functionality, file rotation, and structured logging.
"""

import pytest
import os
import json
import time
from pathlib import Path
import logging

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from logger import DDoSLogger, get_logger


class TestLoggerInitialization:
    """Test logger initialization and setup."""
    
    def test_logger_creates_directory(self, temp_log_dir):
        """Test that logger creates log directory."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        assert os.path.exists(temp_log_dir)
    
    def test_logger_creates_log_files(self, temp_log_dir):
        """Test that logger creates all required log files."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        # Write some logs
        logger.log_event("Test event")
        logger.log_attack("192.168.1.100", "SYN_FLOOD", 100, 50)
        logger.log_system_event("Test system event")
        
        # Check files exist
        assert os.path.exists(os.path.join(temp_log_dir, 'ddos_events.log'))
        assert os.path.exists(os.path.join(temp_log_dir, 'ddos_attacks.log'))
        assert os.path.exists(os.path.join(temp_log_dir, 'ddos_system.log'))
    
    def test_singleton_logger(self):
        """Test that get_logger returns same instance."""
        logger1 = get_logger()
        logger2 = get_logger()
        
        assert logger1 is logger2


class TestLoggerEventLogging:
    """Test event logging functionality."""
    
    def test_log_event_basic(self, temp_log_dir):
        """Test basic event logging."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_event("Test event message")
        
        log_file = os.path.join(temp_log_dir, 'ddos_events.log')
        assert os.path.exists(log_file)
        
        with open(log_file, 'r') as f:
            content = f.read()
            assert "Test event message" in content
    
    def test_log_event_with_level(self, temp_log_dir):
        """Test logging with different levels."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_event("Info message", level="INFO")
        logger.log_event("Warning message", level="WARNING")
        logger.log_event("Error message", level="ERROR")
        
        log_file = os.path.join(temp_log_dir, 'ddos_events.log')
        
        with open(log_file, 'r') as f:
            content = f.read()
            assert "INFO" in content
            assert "WARNING" in content
            assert "ERROR" in content
    
    def test_log_packet_detection(self, temp_log_dir):
        """Test packet detection logging."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_packet_detected("192.168.1.100", "TCP")
        
        log_file = os.path.join(temp_log_dir, 'ddos_events.log')
        
        with open(log_file, 'r') as f:
            content = f.read()
            assert "192.168.1.100" in content
            assert "TCP" in content


class TestLoggerAttackLogging:
    """Test attack-specific logging."""
    
    def test_log_attack_basic(self, temp_log_dir):
        """Test basic attack logging."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_attack("192.168.1.100", "SYN_FLOOD", 150, 75)
        
        log_file = os.path.join(temp_log_dir, 'ddos_attacks.log')
        
        with open(log_file, 'r') as f:
            content = f.read()
            assert "192.168.1.100" in content
            assert "SYN_FLOOD" in content
            assert "150" in content
            assert "75" in content
    
    def test_log_attack_with_action(self, temp_log_dir):
        """Test attack logging with action taken."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_attack(
            "192.168.1.100",
            "PACKET_FLOOD",
            200,
            50,
            action="IP blocked via iptables"
        )
        
        log_file = os.path.join(temp_log_dir, 'ddos_attacks.log')
        
        with open(log_file, 'r') as f:
            content = f.read()
            assert "IP blocked via iptables" in content
    
    def test_log_ip_blocked(self, temp_log_dir):
        """Test IP blocking logging."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_ip_blocked("192.168.1.100", "DDoS attack detected")
        
        log_file = os.path.join(temp_log_dir, 'ddos_attacks.log')
        
        with open(log_file, 'r') as f:
            content = f.read()
            assert "192.168.1.100" in content
            assert "BLOCKED" in content


class TestLoggerSystemLogging:
    """Test system event logging."""
    
    def test_log_system_event(self, temp_log_dir):
        """Test system event logging."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_system_event("System started")
        
        log_file = os.path.join(temp_log_dir, 'ddos_system.log')
        
        with open(log_file, 'r') as f:
            content = f.read()
            assert "System started" in content
    
    def test_log_threshold_config(self, temp_log_dir):
        """Test threshold configuration logging."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_threshold_config(100, 50, 5.0)
        
        log_file = os.path.join(temp_log_dir, 'ddos_system.log')
        
        with open(log_file, 'r') as f:
            content = f.read()
            assert "100" in content
            assert "50" in content
            assert "5.0" in content


class TestLoggerJSONLogging:
    """Test JSON structured logging."""
    
    def test_json_log_creation(self, temp_log_dir):
        """Test that JSON log file is created."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_attack("192.168.1.100", "SYN_FLOOD", 100, 50)
        
        json_file = os.path.join(temp_log_dir, 'ddos_events.json')
        assert os.path.exists(json_file)
    
    def test_json_log_format(self, temp_log_dir):
        """Test JSON log formatting."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_attack("192.168.1.100", "SYN_FLOOD", 100, 50)
        
        json_file = os.path.join(temp_log_dir, 'ddos_events.json')
        
        with open(json_file, 'r') as f:
            # Read all lines
            lines = f.readlines()
            if lines:
                # Parse first JSON object
                data = json.loads(lines[0])
                
                assert 'timestamp' in data
                assert 'event' in data or 'ip_address' in data
    
    def test_json_log_multiple_entries(self, temp_log_dir):
        """Test multiple JSON log entries."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        logger.log_attack("192.168.1.100", "SYN_FLOOD", 100, 50)
        logger.log_attack("192.168.1.101", "PACKET_FLOOD", 200, 30)
        
        json_file = os.path.join(temp_log_dir, 'ddos_events.json')
        
        with open(json_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) >= 2


class TestLoggerRotation:
    """Test log file rotation."""
    
    def test_log_rotation_config(self, temp_log_dir):
        """Test that rotation is configured."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        # Check that handlers have rotation
        for handler in logger.event_logger.handlers:
            if hasattr(handler, 'maxBytes'):
                assert handler.maxBytes > 0
                assert handler.backupCount > 0
    
    def test_large_log_handling(self, temp_log_dir):
        """Test handling of large log files."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        # Write many log entries
        for i in range(1000):
            logger.log_event(f"Test message {i}" * 100)
        
        # Log files should exist
        log_file = os.path.join(temp_log_dir, 'ddos_events.log')
        assert os.path.exists(log_file)


class TestLoggerThreadSafety:
    """Test thread safety of logging."""
    
    def test_concurrent_logging(self, temp_log_dir):
        """Test logging from multiple threads."""
        import threading
        
        logger = DDoSLogger(log_dir=temp_log_dir)
        threads = []
        
        def log_task(thread_id):
            for i in range(100):
                logger.log_event(f"Thread {thread_id} message {i}")
        
        # Start multiple threads
        for i in range(5):
            thread = threading.Thread(target=log_task, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Log file should exist
        log_file = os.path.join(temp_log_dir, 'ddos_events.log')
        assert os.path.exists(log_file)
        
        # Should have many entries
        with open(log_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) > 400  # 5 threads * 100 messages


class TestLoggerErrorHandling:
    """Test error handling in logger."""
    
    def test_invalid_log_directory(self):
        """Test handling of invalid log directory."""
        # Try to create logger with invalid directory
        # Should handle gracefully or create directory
        logger = DDoSLogger(log_dir="/invalid/path/that/does/not/exist")
        
        # Should not crash
        assert logger is not None
    
    def test_log_with_none_values(self, temp_log_dir):
        """Test logging with None values."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        # Should handle None gracefully
        try:
            logger.log_event(None)
            logger.log_attack(None, None, None, None)
        except Exception as e:
            pytest.fail(f"Logger should handle None values: {e}")


class TestLoggerUtilityMethods:
    """Test utility methods of logger."""
    
    def test_get_recent_logs(self, temp_log_dir):
        """Test getting recent log entries."""
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        # Log some events
        for i in range(10):
            logger.log_event(f"Test event {i}")
        
        # Get recent logs
        recent = logger.get_recent_logs(limit=5)
        
        if recent:  # Method exists
            assert len(recent) <= 5


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
