#!/usr/bin/env python3
"""
Verification Script for DDoS Detection System
Run this to verify all fixes are working correctly
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Color codes
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text:^70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")

def test_imports():
    """Test that all modules can be imported"""
    print_header("Testing Module Imports")
    
    modules = [
        ('src.utils', 'Utility functions'),
        ('src.analyzer', 'Traffic analyzer'),
        ('src.mitigator', 'IP mitigator'),
        ('src.logger', 'Logger'),
        ('config.config', 'Configuration'),
    ]
    
    failed = []
    for module, description in modules:
        try:
            __import__(module)
            print(f"{Colors.GREEN}✓{Colors.END} {module:30} - {description}")
        except ImportError as e:
            print(f"{Colors.RED}✗{Colors.END} {module:30} - FAILED: {e}")
            failed.append(module)
    
    return len(failed) == 0

def test_utils():
    """Test utility functions"""
    print_header("Testing Utility Functions")
    
    from src.utils import validate_ip_address, is_private_or_localhost, format_bytes
    
    tests = [
        ("IP Validation - Valid", validate_ip_address("192.168.1.1"), True),
        ("IP Validation - Invalid", validate_ip_address("999.999.999.999"), False),
        ("Private IP Detection", is_private_or_localhost("192.168.1.1"), True),
        ("Public IP Detection", is_private_or_localhost("8.8.8.8"), False),
        ("Byte Formatting", "KB" in format_bytes(1024), True),
    ]
    
    passed = 0
    for test_name, result, expected in tests:
        if result == expected:
            print(f"{Colors.GREEN}✓{Colors.END} {test_name}")
            passed += 1
        else:
            print(f"{Colors.RED}✗{Colors.END} {test_name} (got {result}, expected {expected})")
    
    return passed == len(tests)

def test_analyzer():
    """Test traffic analyzer"""
    print_header("Testing Traffic Analyzer")
    
    from src.analyzer import TrafficAnalyzer
    
    analyzer = TrafficAnalyzer()
    
    tests = [
        ("Analyzer Initialization", analyzer is not None, True),
        ("Empty History", len(analyzer.traffic_history), 0),
    ]
    
    # Add snapshot
    analyzer.add_traffic_snapshot(
        {'192.168.1.1': 100, '192.168.1.2': 50},
        {'192.168.1.1': 50}
    )
    
    tests.extend([
        ("Add Snapshot", len(analyzer.traffic_history), 1),
        ("IP Statistics", '192.168.1.1' in analyzer.ip_statistics, True),
        ("Top Talkers", len(analyzer.get_top_talkers(2)), 2),
    ])
    
    passed = 0
    for test_name, result, expected in tests:
        if result == expected:
            print(f"{Colors.GREEN}✓{Colors.END} {test_name}")
            passed += 1
        else:
            print(f"{Colors.RED}✗{Colors.END} {test_name} (got {result}, expected {expected})")
    
    return passed == len(tests)

def test_mitigator():
    """Test mitigator"""
    print_header("Testing Mitigator")
    
    from src.mitigator import Mitigator
    
    mitigator = Mitigator()
    
    tests = [
        ("Mitigator Initialization", mitigator is not None, True),
        ("Initial Block Count", mitigator.get_blocked_count(), 0),
    ]
    
    # Block an IP (simulated)
    mitigator.block_ip("192.168.1.100")
    
    tests.extend([
        ("IP Blocked", mitigator.is_blocked("192.168.1.100"), True),
        ("Block Count Updated", mitigator.get_blocked_count(), 1),
        ("IP in Blocked List", "192.168.1.100" in mitigator.get_blocked_ips(), True),
    ])
    
    passed = 0
    for test_name, result, expected in tests:
        if result == expected:
            print(f"{Colors.GREEN}✓{Colors.END} {test_name}")
            passed += 1
        else:
            print(f"{Colors.RED}✗{Colors.END} {test_name} (got {result}, expected {expected})")
    
    return passed == len(tests)

def test_configuration():
    """Test configuration"""
    print_header("Testing Configuration")
    
    try:
        from config.config import (
            NETWORK_INTERFACE,
            PACKET_THRESHOLD,
            SYN_THRESHOLD,
            TIME_WINDOW
        )
        
        tests = [
            ("Network Interface Defined", NETWORK_INTERFACE is not None, True),
            ("Packet Threshold Defined", PACKET_THRESHOLD > 0, True),
            ("SYN Threshold Defined", SYN_THRESHOLD > 0, True),
            ("Time Window Defined", TIME_WINDOW > 0, True),
        ]
        
        passed = 0
        for test_name, result, expected in tests:
            if result == expected:
                print(f"{Colors.GREEN}✓{Colors.END} {test_name}")
                passed += 1
            else:
                print(f"{Colors.RED}✗{Colors.END} {test_name}")
        
        return passed == len(tests)
    except ImportError as e:
        print(f"{Colors.RED}✗{Colors.END} Configuration import failed: {e}")
        return False

def test_file_structure():
    """Test file structure"""
    print_header("Testing File Structure")
    
    project_root = Path(__file__).parent.parent
    
    required_files = [
        'src/ddos_detector.py',
        'src/mitigator.py',
        'src/logger.py',
        'src/dashboard.py',
        'src/utils.py',
        'src/analyzer.py',
        'config/config.py',
        'requirements.txt',
        'README.md',
    ]
    
    required_dirs = [
        'src',
        'config',
        'scripts',
        'tests',
        'logs',
        'docs',
    ]
    
    passed = 0
    total = len(required_files) + len(required_dirs)
    
    for file in required_files:
        if (project_root / file).exists():
            print(f"{Colors.GREEN}✓{Colors.END} {file}")
            passed += 1
        else:
            print(f"{Colors.RED}✗{Colors.END} {file} - Missing")
    
    for dir in required_dirs:
        if (project_root / dir).exists():
            print(f"{Colors.GREEN}✓{Colors.END} {dir}/")
            passed += 1
        else:
            print(f"{Colors.RED}✗{Colors.END} {dir}/ - Missing")
    
    return passed == total

def main():
    """Run all tests"""
    print(f"\n{Colors.BOLD}DDoS Detection System - Verification Script{Colors.END}")
    print(f"{Colors.BOLD}Running comprehensive checks...{Colors.END}")
    
    results = []
    
    # Run all tests
    results.append(("File Structure", test_file_structure()))
    results.append(("Module Imports", test_imports()))
    results.append(("Configuration", test_configuration()))
    results.append(("Utility Functions", test_utils()))
    results.append(("Traffic Analyzer", test_analyzer()))
    results.append(("IP Mitigator", test_mitigator()))
    
    # Print summary
    print_header("Verification Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{Colors.GREEN}✓ PASSED{Colors.END}" if result else f"{Colors.RED}✗ FAILED{Colors.END}"
        print(f"{test_name:30} {status}")
    
    print(f"\n{Colors.BOLD}Total: {passed}/{total} test suites passed{Colors.END}")
    
    if passed == total:
        print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 All verifications passed! System is ready.{Colors.END}")
        return 0
    else:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  Some tests failed. Review output above.{Colors.END}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
