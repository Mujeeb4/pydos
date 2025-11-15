# Tests Directory

This directory is for unit tests and integration tests.

## Test Structure

```
tests/
├── __init__.py              # Test package initializer
├── test_detector.py         # Tests for ddos_detector.py
├── test_sniffer.py          # Tests for sniffer.py
├── test_mitigator.py        # Tests for mitigator.py
├── test_logger.py           # Tests for logger.py
└── test_dashboard.py        # Tests for dashboard.py
```

## Running Tests

### Using pytest

```bash
# Install pytest
pip install pytest

# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_logger.py

# Run with verbose output
pytest -v tests/

# Run with coverage
pytest --cov=src tests/
```

### Using unittest

```bash
# Run all tests
python -m unittest discover tests/

# Run specific test
python -m unittest tests.test_logger
```

## Writing Tests

### Example Test File

```python
# tests/test_logger.py
import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from logger import DDoSLogger

class TestDDoSLogger(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.logger = DDoSLogger()
    
    def test_logger_creation(self):
        """Test logger is created successfully"""
        self.assertIsNotNone(self.logger)
    
    def test_log_attack(self):
        """Test attack logging"""
        self.logger.log_attack_detected("192.168.1.100", "SYN_FLOOD", 68)
        # Verify log was written
        self.assertTrue(os.path.exists("logs/ddos_attacks.log"))
    
    def tearDown(self):
        """Clean up after tests"""
        pass

if __name__ == '__main__':
    unittest.main()
```

## Test Categories

### Unit Tests
Test individual functions and classes in isolation.

**Example**:
- Test threshold checking logic
- Test packet parsing
- Test log formatting

### Integration Tests
Test multiple components working together.

**Example**:
- Test detector + logger integration
- Test detector + mitigator integration
- Test dashboard API endpoints

### System Tests
Test the complete system (requires Linux).

**Example**:
- Test actual packet capture
- Test iptables blocking
- Test end-to-end attack detection

## Test Data

Create mock data for testing:

```python
# Test packet data
mock_packet = {
    'src_ip': '192.168.1.100',
    'dst_ip': '192.168.1.1',
    'protocol': 'TCP',
    'flags': 'S'
}

# Test attack scenario
attack_data = {
    'ip': '192.168.1.100',
    'type': 'SYN_FLOOD',
    'count': 68
}
```

## Mocking

Use mocking for components that require system access:

```python
from unittest.mock import Mock, patch

@patch('subprocess.run')
def test_block_ip(self, mock_subprocess):
    """Test IP blocking without actually running iptables"""
    mock_subprocess.return_value = Mock(returncode=0)
    
    mitigator = Mitigator()
    result = mitigator.block_ip("192.168.1.100")
    
    self.assertTrue(result)
    mock_subprocess.assert_called_once()
```

## Continuous Integration

### GitHub Actions Example

```yaml
# .github/workflows/tests.yml
name: Run Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.10
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov
      - name: Run tests
        run: pytest tests/ --cov=src
```

## Coverage

Aim for:
- **Unit Tests**: 80%+ coverage
- **Integration Tests**: Key workflows covered
- **System Tests**: End-to-end scenarios

Check coverage:
```bash
pytest --cov=src --cov-report=html tests/
# Open htmlcov/index.html
```

## TODO

Tests to be implemented:

- [ ] Unit tests for detector threshold logic
- [ ] Unit tests for packet parsing
- [ ] Unit tests for logger (done above as example)
- [ ] Unit tests for mitigator
- [ ] Integration test: detector + logger
- [ ] Integration test: detector + mitigator
- [ ] Mock tests for Scapy functions
- [ ] Dashboard API endpoint tests
- [ ] Performance tests

---

**Status**: Test infrastructure ready, tests to be implemented  
**Last Updated**: November 8, 2025
