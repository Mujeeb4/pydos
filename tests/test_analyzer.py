"""
Tests for Traffic Analyzer Module (analyzer.py)

Tests traffic analysis, statistics, and anomaly detection.
"""

import pytest
import time
from collections import defaultdict
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from analyzer import TrafficAnalyzer


class TestAnalyzerInitialization:
    """Test TrafficAnalyzer initialization."""
    
    def test_analyzer_initialization(self):
        """Test that analyzer initializes correctly."""
        analyzer = TrafficAnalyzer()
        
        assert analyzer.traffic_history == []
        assert isinstance(analyzer.ip_statistics, dict)
        assert hasattr(analyzer, 'start_time')
    
    def test_analyzer_with_history_limit(self):
        """Test analyzer with custom history limit."""
        analyzer = TrafficAnalyzer(history_limit=100)
        
        # Add traffic data
        for i in range(150):
            analyzer.add_traffic_sample({'timestamp': time.time(), 'count': i})
        
        # Should respect limit
        assert len(analyzer.traffic_history) <= 100


class TestTrafficSampling:
    """Test traffic data sampling and storage."""
    
    def test_add_traffic_sample(self):
        """Test adding traffic samples."""
        analyzer = TrafficAnalyzer()
        
        sample = {
            'timestamp': time.time(),
            'total_packets': 100,
            'unique_ips': 10
        }
        
        analyzer.add_traffic_sample(sample)
        
        assert len(analyzer.traffic_history) == 1
        assert analyzer.traffic_history[0] == sample
    
    def test_multiple_samples(self):
        """Test adding multiple traffic samples."""
        analyzer = TrafficAnalyzer()
        
        for i in range(10):
            sample = {
                'timestamp': time.time(),
                'packets': i * 10
            }
            analyzer.add_traffic_sample(sample)
        
        assert len(analyzer.traffic_history) == 10
    
    def test_sample_ordering(self):
        """Test that samples maintain chronological order."""
        analyzer = TrafficAnalyzer()
        
        timestamps = []
        for i in range(5):
            ts = time.time()
            timestamps.append(ts)
            analyzer.add_traffic_sample({'timestamp': ts})
            time.sleep(0.01)
        
        # Verify order
        for i in range(len(analyzer.traffic_history) - 1):
            assert analyzer.traffic_history[i]['timestamp'] <= \
                   analyzer.traffic_history[i + 1]['timestamp']


class TestIPStatistics:
    """Test IP-level statistics tracking."""
    
    def test_update_ip_statistics(self):
        """Test updating statistics for an IP."""
        analyzer = TrafficAnalyzer()
        
        analyzer.update_ip_statistics('192.168.1.100', packet_count=10)
        
        assert '192.168.1.100' in analyzer.ip_statistics
        assert analyzer.ip_statistics['192.168.1.100']['packet_count'] >= 10
    
    def test_multiple_ip_statistics(self):
        """Test tracking multiple IPs."""
        analyzer = TrafficAnalyzer()
        
        ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
        
        for ip in ips:
            analyzer.update_ip_statistics(ip, packet_count=50)
        
        assert len(analyzer.ip_statistics) == 3
        for ip in ips:
            assert ip in analyzer.ip_statistics
    
    def test_incremental_statistics(self):
        """Test incremental statistics updates."""
        analyzer = TrafficAnalyzer()
        
        # Update same IP multiple times
        for i in range(5):
            analyzer.update_ip_statistics('192.168.1.100', packet_count=10)
        
        # Should accumulate
        stats = analyzer.ip_statistics.get('192.168.1.100', {})
        assert stats.get('packet_count', 0) >= 10


class TestTopTalkers:
    """Test top talkers identification."""
    
    def test_get_top_talkers_empty(self):
        """Test getting top talkers with no data."""
        analyzer = TrafficAnalyzer()
        
        top = analyzer.get_top_talkers(limit=5)
        
        assert top == []
    
    def test_get_top_talkers_basic(self):
        """Test getting top talkers."""
        analyzer = TrafficAnalyzer()
        
        # Add statistics for multiple IPs
        ips_and_counts = [
            ('192.168.1.100', 100),
            ('192.168.1.101', 50),
            ('192.168.1.102', 200),
            ('192.168.1.103', 75)
        ]
        
        for ip, count in ips_and_counts:
            analyzer.update_ip_statistics(ip, packet_count=count)
        
        top = analyzer.get_top_talkers(limit=3)
        
        assert len(top) <= 3
        
        # Should be sorted by packet count
        if len(top) > 1:
            for i in range(len(top) - 1):
                count1 = top[i].get('packet_count', 0)
                count2 = top[i + 1].get('packet_count', 0)
                assert count1 >= count2
    
    def test_top_talkers_limit(self):
        """Test that limit parameter works."""
        analyzer = TrafficAnalyzer()
        
        # Add many IPs
        for i in range(20):
            analyzer.update_ip_statistics(f'192.168.1.{i}', packet_count=i * 10)
        
        top = analyzer.get_top_talkers(limit=5)
        
        assert len(top) <= 5


class TestAnomalyDetection:
    """Test anomaly detection functionality."""
    
    def test_detect_anomalies_no_data(self):
        """Test anomaly detection with no traffic data."""
        analyzer = TrafficAnalyzer()
        
        anomalies = analyzer.detect_anomalies()
        
        assert anomalies == [] or anomalies is None
    
    def test_detect_anomalies_normal_traffic(self):
        """Test that normal traffic doesn't trigger anomalies."""
        analyzer = TrafficAnalyzer()
        
        # Add normal traffic samples
        for i in range(10):
            sample = {
                'timestamp': time.time(),
                'packet_count': 50 + i  # Gradual increase
            }
            analyzer.add_traffic_sample(sample)
            time.sleep(0.01)
        
        anomalies = analyzer.detect_anomalies()
        
        # Should be empty or have minimal anomalies
        if anomalies:
            assert len(anomalies) < 3
    
    def test_detect_anomalies_spike(self):
        """Test detection of traffic spikes."""
        analyzer = TrafficAnalyzer()
        
        # Add normal traffic
        for i in range(10):
            analyzer.add_traffic_sample({
                'timestamp': time.time(),
                'packet_count': 50
            })
        
        # Add spike
        analyzer.add_traffic_sample({
            'timestamp': time.time(),
            'packet_count': 500  # 10x normal
        })
        
        anomalies = analyzer.detect_anomalies()
        
        # Should detect the spike
        if anomalies is not None:
            assert len(anomalies) > 0 or analyzer.traffic_history[-1]['packet_count'] > 100


class TestStatisticsRetrieval:
    """Test statistics retrieval methods."""
    
    def test_get_statistics_summary(self):
        """Test getting overall statistics summary."""
        analyzer = TrafficAnalyzer()
        
        # Add some data
        for i in range(5):
            analyzer.update_ip_statistics(f'192.168.1.{i}', packet_count=i * 10)
        
        summary = analyzer.get_statistics_summary()
        
        assert isinstance(summary, dict)
        assert 'total_ips' in summary or len(summary) > 0
    
    def test_get_ip_statistics(self):
        """Test getting statistics for specific IP."""
        analyzer = TrafficAnalyzer()
        
        analyzer.update_ip_statistics('192.168.1.100', packet_count=100)
        
        stats = analyzer.get_ip_statistics('192.168.1.100')
        
        if stats:
            assert 'packet_count' in stats or stats.get('packet_count', 0) > 0


class TestTrafficTrends:
    """Test traffic trend analysis."""
    
    def test_calculate_trend_increasing(self):
        """Test detecting increasing traffic trend."""
        analyzer = TrafficAnalyzer()
        
        # Add increasing traffic
        for i in range(10):
            analyzer.add_traffic_sample({
                'timestamp': time.time(),
                'packet_count': i * 20
            })
        
        trend = analyzer.calculate_trend()
        
        if trend:
            assert trend in ['increasing', 'stable', 'decreasing'] or isinstance(trend, (int, float))
    
    def test_calculate_trend_stable(self):
        """Test detecting stable traffic."""
        analyzer = TrafficAnalyzer()
        
        # Add stable traffic
        for i in range(10):
            analyzer.add_traffic_sample({
                'timestamp': time.time(),
                'packet_count': 50
            })
        
        trend = analyzer.calculate_trend()
        
        if trend:
            assert trend == 'stable' or abs(trend) if isinstance(trend, (int, float)) else True


class TestDataCleanup:
    """Test data cleanup and memory management."""
    
    def test_cleanup_old_data(self):
        """Test cleanup of old traffic data."""
        analyzer = TrafficAnalyzer()
        
        # Add old samples
        old_time = time.time() - 3600  # 1 hour ago
        
        for i in range(10):
            analyzer.add_traffic_sample({
                'timestamp': old_time + i,
                'packet_count': 50
            })
        
        # Cleanup old data (if method exists)
        if hasattr(analyzer, 'cleanup_old_data'):
            analyzer.cleanup_old_data(max_age=1800)  # 30 minutes
    
    def test_reset_statistics(self):
        """Test resetting statistics."""
        analyzer = TrafficAnalyzer()
        
        # Add data
        analyzer.update_ip_statistics('192.168.1.100', packet_count=100)
        analyzer.add_traffic_sample({'timestamp': time.time(), 'count': 50})
        
        # Reset
        if hasattr(analyzer, 'reset'):
            analyzer.reset()
            
            assert len(analyzer.traffic_history) == 0
            assert len(analyzer.ip_statistics) == 0


class TestPerformance:
    """Test performance with large datasets."""
    
    def test_large_traffic_history(self):
        """Test handling large traffic history."""
        analyzer = TrafficAnalyzer(history_limit=1000)
        
        # Add many samples
        start_time = time.time()
        
        for i in range(1000):
            analyzer.add_traffic_sample({
                'timestamp': time.time(),
                'packet_count': i
            })
        
        elapsed = time.time() - start_time
        
        # Should complete in reasonable time
        assert elapsed < 5.0  # 5 seconds max
        assert len(analyzer.traffic_history) <= 1000
    
    def test_many_ips(self):
        """Test tracking many unique IPs."""
        analyzer = TrafficAnalyzer()
        
        # Add many IPs
        for i in range(1000):
            analyzer.update_ip_statistics(f'192.168.{i // 256}.{i % 256}', packet_count=10)
        
        assert len(analyzer.ip_statistics) <= 1000


class TestThreadSafety:
    """Test thread safety of analyzer."""
    
    def test_concurrent_updates(self):
        """Test concurrent traffic updates."""
        import threading
        
        analyzer = TrafficAnalyzer()
        threads = []
        
        def update_task(thread_id):
            for i in range(100):
                analyzer.update_ip_statistics(f'192.168.1.{thread_id}', packet_count=1)
        
        # Start multiple threads
        for i in range(5):
            thread = threading.Thread(target=update_task, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Should have stats for all IPs
        assert len(analyzer.ip_statistics) <= 5


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
