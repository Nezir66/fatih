# State Manager Test Suite

Comprehensive test suite for the State Manager with realistic mock data, performance tests, and thread safety tests.

## Test Structure

```
tests/
├── conftest.py                    # Pytest fixtures
├── fixtures/
│   └── mock_scan_data.py          # Realistic mock data
└── test_state_manager.py          # 75 comprehensive tests
```

## Test Categories

### 1. Unit Tests (40 tests)
- **Model Tests:** Severity, PortState, Service, Port, Vulnerability, Host, Action, Session
- **StateManager Operations:** Host/Port/Vulnerability/Action management
- **Deduplication:** Fingerprint generation, duplicate detection

### 2. Integration Tests (10 tests)
- **Persistence:** Save/Load, Atomic Writes, Auto-Save
- **AI Context:** JSON generation, Summary statistics
- **Workflows:** Full reconnaissance workflows

### 3. Performance Tests (3 tests)
- **Large Dataset:** 50 hosts, 1000+ vulnerabilities
- **Operations Speed:** < 2 seconds for 1000+ entries
- **Save/Load Speed:** < 5 seconds for large datasets

### 4. Thread Safety Tests (4 tests)
- **Concurrent Host Addition:** 10 threads, 100 hosts
- **Concurrent Vulnerability Addition:** 5 threads, 100 vulns
- **Mixed Operations:** Concurrent reads/writes
- **Concurrent Save/Load:** No corruption under load

### 5. Edge Case Tests (10 tests)
- Empty sessions
- Unicode hostnames (日本語, emoji)
- Very long strings (10k+ chars)
- Special characters (XSS payloads)
- Invalid severity handling
- None values
- Paths with spaces

### 6. Realistic Workflow Tests (2 tests)
- Full reconnaissance workflow
- Duplicate detection workflow

## Mock Data

Realistic data based on actual security tool outputs:

- **3 Nmap Hosts:** web01, api, db servers with realistic ports and services
- **10 Nuclei Vulnerabilities:** CVE-2021-44228 (Log4j), SSL issues, outdated software
- **10 Action History:** Realistic scan commands and results
- **Large Dataset Generator:** 50 hosts × 20 vulns = 1000+ entries

## Running Tests

```bash
# All tests
pytest tests/test_state_manager.py -v

# With coverage report
pytest tests/test_state_manager.py --cov=src.core.state_manager --cov-report=html

# Only unit tests (fast)
pytest tests/test_state_manager.py -v -k "not slow"

# Only performance tests
pytest tests/test_state_manager.py -v -m slow

# Only thread safety tests
pytest tests/test_state_manager.py -v -k "thread"

# Specific test class
pytest tests/test_state_manager.py::TestStateManagerPersistence -v
```

## Test Results

```
============================= test session starts ==============================
platform darwin -- Python 3.12.7, pytest-7.4.4
collected 75 items

 tests/test_state_manager.py ..................................... [100%]

============================== 75 passed in 1.13s =============================
```

## Key Features Tested

✅ **Hierarchical Data Model:** Session → Host → Port → Vulnerability  
✅ **Deduplication:** MD5 fingerprint-based duplicate detection  
✅ **Atomic Writes:** Temp file + rename pattern prevents corruption  
✅ **Auto-Save:** Automatic persistence after each modification  
✅ **Loop Prevention:** Action history prevents duplicate scans  
✅ **AI Context:** Compact JSON summaries for LLM consumption  
✅ **Thread Safety:** Concurrent operations without data corruption  
✅ **Edge Cases:** Unicode, long strings, special characters  
✅ **Performance:** Efficient handling of 1000+ entries  

## Example Usage in Tests

```python
# Using fixtures
from tests.conftest import populated_state_manager, large_state_manager

def test_example(populated_state_manager):
    sm = populated_state_manager
    
    # Test operations
    assert len(sm.session.hosts) == 3
    vulns = sm.get_vulnerabilities()
    assert len(vulns) > 0
    
    # Test AI context
    context = sm.get_context_for_ai()
    assert "corp.example.com" in context
```

## Continuous Integration

To add to CI/CD pipeline:

```yaml
# .github/workflows/test.yml (example)
- name: Run State Manager Tests
  run: |
    pip install -r requirements.txt
    pytest tests/test_state_manager.py -v --cov=src.core.state_manager
```
