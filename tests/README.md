# Testing Guide for PyDOS

This directory contains comprehensive pytest-based tests for the Real-Time DDoS Detection System.

## Test Structure

```
tests/
├── conftest.py                 # Pytest fixtures and configuration
├── test_mitigator.py          # Tests for IP blocking/mitigation
├── test_logger.py             # Tests for logging system
├── test_utils.py              # Tests for utility functions
├── test_analyzer.py           # Tests for traffic analysis
├── test_ddos_detector.py      # Tests for main detection engine
├── test_integration.py        # Integration tests
└── README.md                  # This file
```

## Running Tests

### Run All Tests
```bash
pytest
```

### Run with Verbose Output
```bash
pytest -v
```

### Run Specific Test File
```bash
pytest tests/test_mitigator.py
```

### Run Specific Test Class
```bash
pytest tests/test_mitigator.py::TestMitigatorBasics
```

### Run Specific Test Function
```bash
pytest tests/test_mitigator.py::TestMitigatorBasics::test_block_ip_success
```

### Run with Coverage Report
```bash
pytest --cov=src --cov-report=html
```

### Run Tests in Parallel
```bash
pytest -n auto
```

## Test Categories

### Unit Tests

#### test_mitigator.py
- **TestMitigatorBasics**: Basic IP blocking functionality
- **TestMitigatorThreadSafety**: Concurrent blocking operations
- **TestMitigatorErrorHandling**: Error scenarios
- **TestMitigatorAutoCleanup**: Automatic unblocking
- **TestMitigatorIntegration**: Complete workflows
- **TestMitigatorPlatformCompatibility**: Cross-platform behavior

#### test_logger.py
- **TestLoggerInitialization**: Logger setup
- **TestLoggerEventLogging**: Event logging
- **TestLoggerAttackLogging**: Attack-specific logs
- **TestLoggerSystemLogging**: System events
- **TestLoggerJSONLogging**: Structured JSON logs
- **TestLoggerRotation**: Log rotation
- **TestLoggerThreadSafety**: Concurrent logging
- **TestLoggerErrorHandling**: Error scenarios

#### test_utils.py
- **TestIPValidation**: IP address validation
- **TestPrivateIPDetection**: Private IP detection
- **TestFileOperations**: Directory and file operations
- **TestJSONOperations**: JSON file handling
- **TestNetworkUtilities**: Network interface utilities
- **TestFormatUtilities**: Data formatting
- **TestProjectUtilities**: Project path utilities

#### test_analyzer.py
- **TestAnalyzerInitialization**: Analyzer setup
- **TestTrafficSampling**: Traffic data collection
- **TestIPStatistics**: IP-level statistics
- **TestTopTalkers**: Top traffic sources
- **TestAnomalyDetection**: Anomaly detection
- **TestStatisticsRetrieval**: Statistics queries
- **TestTrafficTrends**: Trend analysis
- **TestDataCleanup**: Memory management
- **TestPerformance**: Large dataset handling
- **TestThreadSafety**: Concurrent operations

#### test_ddos_detector.py
- **TestDetectorInitialization**: Detector setup
- **TestPacketCounting**: Packet counters
- **TestThresholdDetection**: Attack detection
- **TestMitigation**: Attack response
- **TestTimeWindow**: Time-based tracking
- **TestThreadSafety**: Concurrent packet processing
- **TestPacketHandling**: Packet processing logic
- **TestLogging**: Log integration
- **TestStatistics**: Statistics tracking
- **TestConfiguration**: Configuration validation

### Integration Tests

#### test_integration.py
- **TestSystemIntegration**: Component interaction
- **TestAnalyzerIntegration**: Analyzer with detector
- **TestConfigurationIntegration**: Config loading
- **TestUtilsIntegration**: Utilities with components
- **TestLoggingIntegration**: Cross-component logging
- **TestErrorHandling**: System-wide error handling
- **TestPerformanceIntegration**: End-to-end performance
- **TestDataPersistence**: Data storage

## Fixtures

### conftest.py Fixtures

- **temp_log_dir**: Temporary directory for test logs
- **clean_stats_file**: Managed stats.json for testing
- **sample_ip_addresses**: Various IP address samples
- **mock_packet**: Mock network packet
- **mock_tcp_syn_packet**: Mock TCP SYN packet
- **reset_environment**: Clean environment per test
- **test_config**: Test configuration values

## Platform-Specific Notes

### Linux
All tests should pass. Some tests require root privileges for actual iptables commands (mocked in tests).

### Windows
- Mitigation tests use mocked iptables (not available on Windows)
- Network interface detection may differ
- Some tests check for graceful handling of missing tools

### macOS
Similar to Linux, but iptables may not be available (tests use mocks).

## Test Coverage

Run coverage analysis:
```bash
pytest --cov=src --cov-report=term-missing
```

Generate HTML coverage report:
```bash
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

## Continuous Integration

Tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    pip install -r requirements.txt
    pytest --cov=src --cov-report=xml
```

## Troubleshooting

### Import Errors
Ensure you're running tests from the project root:
```bash
cd /path/to/pydos
pytest
```

### Permission Errors
Some tests may require elevated privileges for actual network operations. Tests use mocks to avoid this.

### Scapy Issues
If Scapy tests fail:
```bash
pip install --upgrade scapy
```

### Timeout Issues
Some tests involve delays. Increase timeout if needed:
```bash
pytest --timeout=300
```

## Writing New Tests

### Test Naming Convention
- Test files: `test_*.py`
- Test classes: `Test*`
- Test functions: `test_*`

### Example Test
```python
def test_example_function():
    """Test that example function works correctly."""
    result = example_function(input_data)
    assert result == expected_output
```

### Using Fixtures
```python
def test_with_fixture(temp_log_dir):
    """Test using a fixture."""
    logger = Logger(log_dir=temp_log_dir)
    assert os.path.exists(temp_log_dir)
```

### Mocking External Calls
```python
@patch('subprocess.run')
def test_with_mock(mock_run):
    """Test with mocked subprocess."""
    mock_run.return_value = Mock(returncode=0)
    # Test code here
```

## Performance Benchmarks

Run performance tests:
```bash
pytest tests/test_integration.py::TestPerformanceIntegration -v
```

Expected benchmarks:
- 1000 packets processed: < 5 seconds
- 1000 traffic samples: < 3 seconds
- Concurrent operations: No deadlocks

## Contributing

When adding new features:
1. Write tests first (TDD)
2. Ensure all tests pass
3. Maintain > 80% code coverage
4. Add integration tests for new components
5. Update this README if needed

## License

Same as main project.
