"""
Comprehensive test suite for State Manager.

Tests cover:
- Unit tests for all models and methods
- Integration tests for persistence and workflows
- Performance tests with 1K+ entries
- Thread safety tests
- Edge cases and error handling
"""

import json
import os
import threading
import time
from pathlib import Path

import pytest

from src.core.state_manager import (
    StateManager, Session, Host, Port, Vulnerability, Action,
    Service, Severity, PortState,
    create_state_manager, load_state_manager
)
from tests.fixtures.mock_scan_data import (
    MOCK_NMAP_HOST_1, MOCK_NUCLEI_VULNERABILITIES,
    generate_large_dataset, EDGE_CASE_HOSTS, EDGE_CASE_VULNERABILITIES
)


# =============================================================================
# UNIT TESTS - Models
# =============================================================================

class TestSeverityEnum:
    """Test Severity enum validation."""
    
    def test_severity_values(self):
        """Test that all severity levels exist."""
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"
    
    def test_severity_from_string(self):
        """Test creating severity from string."""
        assert Severity("low") == Severity.LOW
        assert Severity("high") == Severity.HIGH
        assert Severity("critical") == Severity.CRITICAL


class TestPortStateEnum:
    """Test PortState enum validation."""
    
    def test_port_state_values(self):
        """Test that all port states exist."""
        assert PortState.OPEN.value == "open"
        assert PortState.CLOSED.value == "closed"
        assert PortState.FILTERED.value == "filtered"
        assert PortState.UNFILTERED.value == "unfiltered"
        assert PortState.OPEN_FILTERED.value == "open|filtered"
        assert PortState.CLOSED_FILTERED.value == "closed|filtered"


class TestServiceModel:
    """Test Service model."""
    
    def test_service_creation(self, sample_service):
        """Test creating a Service object."""
        assert sample_service.name == "http"
        assert sample_service.product == "Apache httpd"
        assert sample_service.version == "2.4.41"
        assert sample_service.banner == "Apache/2.4.41 (Ubuntu)"
    
    def test_service_to_summary(self, sample_service):
        """Test service summary generation."""
        summary = sample_service.to_summary()
        assert summary["name"] == "http"
        assert summary["version"] == "2.4.41"
        assert summary["product"] == "Apache httpd"
        assert "banner" not in summary  # Should be excluded


class TestPortModel:
    """Test Port model."""
    
    def test_port_creation(self, sample_port):
        """Test creating a Port object."""
        assert sample_port.number == 80
        assert sample_port.protocol == "tcp"
        assert sample_port.state == PortState.OPEN
        assert sample_port.service is not None
    
    def test_port_get_key(self, sample_port):
        """Test port key generation."""
        assert sample_port.get_key() == "80/tcp"
    
    def test_port_add_vulnerability(self, sample_port, sample_vulnerability):
        """Test adding vulnerability to port."""
        result = sample_port.add_vulnerability(sample_vulnerability)
        assert result is True
        assert len(sample_port.vulnerabilities) == 1
        
        # Try adding duplicate
        result2 = sample_port.add_vulnerability(sample_vulnerability)
        assert result2 is False
        assert len(sample_port.vulnerabilities) == 1
    
    def test_port_to_summary(self, sample_port):
        """Test port summary generation."""
        summary = sample_port.to_summary()
        assert summary["port"] == 80
        assert summary["protocol"] == "tcp"
        assert summary["state"] == "open"
        assert "service" in summary


class TestVulnerabilityModel:
    """Test Vulnerability model."""
    
    def test_vulnerability_creation(self, sample_vulnerability):
        """Test creating a Vulnerability object."""
        assert sample_vulnerability.vuln_id == "CVE-2021-44228"
        assert sample_vulnerability.title == "Log4j RCE"
        assert sample_vulnerability.severity == Severity.CRITICAL
        assert sample_vulnerability.fingerprint == "abc123"
    
    def test_vulnerability_severity_validation(self):
        """Test severity validation from string."""
        vuln = Vulnerability(
            fingerprint="test",
            vuln_id="TEST-001",
            title="Test",
            severity="high",  # String input
            location="/test",
            tool="nuclei"
        )
        assert vuln.severity == Severity.HIGH
    
    def test_vulnerability_to_summary(self, sample_vulnerability):
        """Test vulnerability summary generation."""
        summary = sample_vulnerability.to_summary()
        assert summary["id"] == "CVE-2021-44228"
        assert summary["title"] == "Log4j RCE"
        assert summary["severity"] == "critical"
        assert summary["location"] == "/api/login"
        assert "evidence" not in summary  # Should be excluded


class TestHostModel:
    """Test Host model."""
    
    def test_host_creation(self, sample_host):
        """Test creating a Host object."""
        assert sample_host.ip == "192.168.1.100"
        assert sample_host.domain == "web01.example.com"
        assert sample_host.os_info == "Linux 4.15"
    
    def test_host_get_key(self, sample_host):
        """Test host key generation."""
        assert sample_host.get_key() == "192.168.1.100"
        
        # Test with domain only
        host2 = Host(domain="example.com")
        assert host2.get_key() == "example.com"
    
    def test_host_add_port(self, sample_host):
        """Test adding port to host."""
        port = Port(number=443, protocol="tcp", state=PortState.OPEN)
        added_port = sample_host.add_port(port)
        
        assert "443/tcp" in sample_host.ports
        assert added_port.number == 443
    
    def test_host_add_duplicate_port(self, sample_host):
        """Test that duplicate ports update existing."""
        port1 = Port(number=80, protocol="tcp", state=PortState.CLOSED)
        sample_host.add_port(port1)
        
        port2 = Port(number=80, protocol="tcp", state=PortState.OPEN)
        sample_host.add_port(port2)
        
        assert len(sample_host.ports) == 1
        assert sample_host.ports["80/tcp"].state == PortState.OPEN
    
    def test_host_add_vulnerability(self, sample_host, sample_vulnerability):
        """Test adding vulnerability to host."""
        result = sample_host.add_vulnerability(sample_vulnerability)
        assert result is True
        assert len(sample_host.vulnerabilities) == 1
        
        # Try adding duplicate
        result2 = sample_host.add_vulnerability(sample_vulnerability)
        assert result2 is False
    
    def test_host_get_open_ports(self, sample_host):
        """Test getting open ports."""
        sample_host.add_port(Port(number=80, state=PortState.OPEN))
        sample_host.add_port(Port(number=443, state=PortState.CLOSED))
        sample_host.add_port(Port(number=22, state=PortState.OPEN))
        
        open_ports = sample_host.get_open_ports()
        assert len(open_ports) == 2
        assert all(p.state == PortState.OPEN for p in open_ports)
    
    def test_host_to_summary(self, sample_host):
        """Test host summary generation."""
        sample_host.add_port(Port(number=80, state=PortState.OPEN))
        sample_host.add_port(Port(number=443, state=PortState.OPEN))
        
        summary = sample_host.to_summary()
        assert summary["ip"] == "192.168.1.100"
        assert summary["domain"] == "web01.example.com"
        assert summary["open_ports"] == 2


class TestActionModel:
    """Test Action model."""
    
    def test_action_creation(self, sample_action):
        """Test creating an Action object."""
        assert sample_action.tool == "nmap"
        assert sample_action.target == "192.168.1.100"
        assert sample_action.parameters == "-sV -p 1-1000"
        assert sample_action.result_summary == "3 open ports found"
    
    def test_action_get_key(self, sample_action):
        """Test action key generation."""
        assert sample_action.get_key() == "nmap|192.168.1.100|-sV -p 1-1000"


class TestSessionModel:
    """Test Session model."""
    
    def test_session_creation(self):
        """Test creating a Session object."""
        session = Session(target="test.com")
        assert session.target == "test.com"
        assert session.id is not None
        assert len(session.hosts) == 0
    
    def test_session_get_or_create_host(self):
        """Test getting or creating hosts."""
        session = Session(target="test.com")
        
        host1 = session.get_or_create_host("192.168.1.1")
        assert host1.ip == "192.168.1.1"
        assert len(session.hosts) == 1
        
        # Get existing
        host2 = session.get_or_create_host("192.168.1.1")
        assert host2 is host1
        assert len(session.hosts) == 1
    
    def test_session_is_ip_detection(self):
        """Test IP vs domain detection."""
        session = Session(target="test.com")
        
        assert session._is_ip("192.168.1.1") is True
        assert session._is_ip("10.0.0.1") is True
        assert session._is_ip("example.com") is False
        assert session._is_ip("sub.example.com") is False
    
    def test_session_record_action(self):
        """Test recording actions."""
        session = Session(target="test.com")
        session.record_action("nmap", "192.168.1.1", "-sV")
        
        assert len(session.executed_actions) == 1
        assert session.executed_actions[0].tool == "nmap"
    
    def test_session_was_action_executed(self):
        """Test action execution check."""
        session = Session(target="test.com")
        session.record_action("nmap", "192.168.1.1", "-sV")
        
        assert session.was_action_executed("nmap", "192.168.1.1", "-sV") is True
        assert session.was_action_executed("nmap", "192.168.1.1", "-sS") is False
        assert session.was_action_executed("nuclei", "192.168.1.1", "-sV") is False
    
    def test_session_get_summary(self):
        """Test session summary."""
        session = Session(target="test.com")
        host = session.get_or_create_host("192.168.1.1")
        host.add_port(Port(number=80, state=PortState.OPEN))
        host.add_port(Port(number=443, state=PortState.OPEN))
        session.record_action("nmap", "192.168.1.1", "-sV")
        
        summary = session.get_summary()
        assert summary["target"] == "test.com"
        assert summary["hosts_discovered"] == 1
        assert summary["open_ports"] == 2
        assert summary["actions_executed"] == 1


# =============================================================================
# UNIT TESTS - StateManager Methods
# =============================================================================

class TestStateManagerHostOperations:
    """Test StateManager host operations."""
    
    def test_add_host(self, empty_state_manager):
        """Test adding a host."""
        host = empty_state_manager.add_host("192.168.1.1")
        assert host.ip == "192.168.1.1"
        assert "192.168.1.1" in empty_state_manager.session.hosts
    
    def test_add_host_normalization(self, empty_state_manager):
        """Test that host identifiers are normalized."""
        host1 = empty_state_manager.add_host("  192.168.1.1  ")
        host2 = empty_state_manager.add_host("192.168.1.1")
        assert host1 is host2
    
    def test_get_host(self, empty_state_manager):
        """Test getting a host."""
        empty_state_manager.add_host("192.168.1.1")
        host = empty_state_manager.get_host("192.168.1.1")
        assert host is not None
        assert host.ip == "192.168.1.1"
    
    def test_get_nonexistent_host(self, empty_state_manager):
        """Test getting a non-existent host."""
        host = empty_state_manager.get_host("192.168.1.999")
        assert host is None
    
    def test_link_ip_to_domain(self, empty_state_manager):
        """Test linking IP to domain."""
        empty_state_manager.add_host("192.168.1.1")
        empty_state_manager.add_host("example.com")
        empty_state_manager.link_host_ip_domain("192.168.1.1", "example.com")
        
        host = empty_state_manager.get_host("192.168.1.1")
        assert host.domain == "example.com"


class TestStateManagerPortOperations:
    """Test StateManager port operations."""
    
    def test_add_port(self, empty_state_manager):
        """Test adding a port."""
        port = empty_state_manager.add_port("192.168.1.1", 80, "tcp", "open")
        assert port.number == 80
        assert port.state == PortState.OPEN
    
    def test_add_port_creates_host(self, empty_state_manager):
        """Test that add_port creates host if needed."""
        empty_state_manager.add_port("192.168.1.1", 80, "tcp", "open")
        assert "192.168.1.1" in empty_state_manager.session.hosts
    
    def test_add_port_with_service(self, empty_state_manager):
        """Test adding a port with service info."""
        service = Service(name="http", product="Apache", version="2.4.41")
        port = empty_state_manager.add_port(
            "192.168.1.1", 80, "tcp", "open", service=service
        )
        assert port.service.name == "http"
        assert port.service.version == "2.4.41"
    
    def test_get_open_ports_by_host(self, empty_state_manager):
        """Test getting open ports for specific host."""
        empty_state_manager.add_port("192.168.1.1", 80, "tcp", "open")
        empty_state_manager.add_port("192.168.1.1", 443, "tcp", "closed")
        empty_state_manager.add_port("192.168.1.2", 22, "tcp", "open")
        
        ports = empty_state_manager.get_open_ports("192.168.1.1")
        assert len(ports) == 1
        assert ports[0].number == 80
    
    def test_get_all_open_ports(self, empty_state_manager):
        """Test getting all open ports across hosts."""
        empty_state_manager.add_port("192.168.1.1", 80, "tcp", "open")
        empty_state_manager.add_port("192.168.1.2", 22, "tcp", "open")
        empty_state_manager.add_port("192.168.1.3", 443, "tcp", "filtered")
        
        ports = empty_state_manager.get_open_ports()
        assert len(ports) == 2


class TestStateManagerVulnerabilityOperations:
    """Test StateManager vulnerability operations."""
    
    def test_add_host_level_vulnerability(self, empty_state_manager):
        """Test adding host-level vulnerability."""
        result = empty_state_manager.add_vulnerability(
            target_host="192.168.1.1",
            vuln_id="CVE-2021-44228",
            title="Log4j RCE",
            severity=Severity.CRITICAL,
            location="Host-wide",
            tool="nuclei"
        )
        assert result is True
        
        host = empty_state_manager.get_host("192.168.1.1")
        assert len(host.vulnerabilities) == 1
    
    def test_add_port_level_vulnerability(self, empty_state_manager):
        """Test adding port-level vulnerability."""
        result = empty_state_manager.add_vulnerability(
            target_host="192.168.1.1",
            vuln_id="ssl-weak-cipher",
            title="Weak SSL",
            severity=Severity.MEDIUM,
            location="Port 443",
            port_num=443,
            tool="nmap"
        )
        assert result is True
        
        host = empty_state_manager.get_host("192.168.1.1")
        assert "443/tcp" in host.ports
        assert len(host.ports["443/tcp"].vulnerabilities) == 1
    
    def test_vulnerability_deduplication(self, empty_state_manager):
        """Test that duplicate vulnerabilities are rejected."""
        empty_state_manager.add_vulnerability(
            target_host="192.168.1.1",
            vuln_id="CVE-2021-44228",
            title="Log4j RCE",
            severity=Severity.CRITICAL,
            location="/api/login",
            port_num=8080,
            tool="nuclei"
        )
        
        # Try to add same vulnerability
        result = empty_state_manager.add_vulnerability(
            target_host="192.168.1.1",
            vuln_id="CVE-2021-44228",
            title="Log4j RCE",
            severity=Severity.CRITICAL,
            location="/api/login",
            port_num=8080,
            tool="nuclei"
        )
        assert result is False
    
    def test_get_vulnerabilities_filtered(self, empty_state_manager):
        """Test getting vulnerabilities with filters."""
        # Add vulnerabilities with different severities
        empty_state_manager.add_vulnerability(
            "192.168.1.1", "CVE-001", "Critical Vuln", Severity.CRITICAL, "/api", tool="nuclei"
        )
        empty_state_manager.add_vulnerability(
            "192.168.1.1", "CVE-002", "High Vuln", Severity.HIGH, "/admin", tool="nuclei"
        )
        empty_state_manager.add_vulnerability(
            "192.168.1.1", "CVE-003", "Medium Vuln", Severity.MEDIUM, "/user", tool="nuclei"
        )
        
        # Get only high and above
        vulns = empty_state_manager.get_vulnerabilities(min_severity=Severity.HIGH)
        assert len(vulns) == 2
        assert all(v.severity in [Severity.CRITICAL, Severity.HIGH] for v in vulns)


class TestStateManagerActionOperations:
    """Test StateManager action/loop prevention operations."""
    
    def test_record_action(self, empty_state_manager):
        """Test recording an action."""
        empty_state_manager.record_action("nmap", "192.168.1.1", "-sV")
        assert len(empty_state_manager.session.executed_actions) == 1
    
    def test_was_action_executed(self, empty_state_manager):
        """Test checking if action was executed."""
        empty_state_manager.record_action("nmap", "192.168.1.1", "-sV")
        
        assert empty_state_manager.was_action_executed("nmap", "192.168.1.1", "-sV") is True
        assert empty_state_manager.was_action_executed("nmap", "192.168.1.1", "-sS") is False
    
    def test_action_case_insensitive(self, empty_state_manager):
        """Test that action matching is case insensitive."""
        empty_state_manager.record_action("Nmap", "192.168.1.1", "-sV")
        
        assert empty_state_manager.was_action_executed("nmap", "192.168.1.1", "-sV") is True
        assert empty_state_manager.was_action_executed("NMAP", "192.168.1.1", "-sV") is True


# =============================================================================
# INTEGRATION TESTS - Persistence
# =============================================================================

class TestStateManagerPersistence:
    """Test save/load functionality."""
    
    def test_save_snapshot(self, populated_state_manager, temp_dir):
        """Test saving snapshot to disk."""
        snapshot_path = temp_dir / "test_snapshot.json"
        populated_state_manager.save_snapshot(str(snapshot_path))
        
        assert snapshot_path.exists()
        # Verify it's valid JSON
        with open(snapshot_path) as f:
            data = json.load(f)
        assert data["target"] == "corp.example.com"
    
    def test_load_snapshot(self, saved_snapshot_path):
        """Test loading snapshot from disk."""
        sm = StateManager.load_snapshot(saved_snapshot_path, auto_save=False)
        
        assert sm.session.target == "corp.example.com"
        assert len(sm.session.hosts) == 3
        assert len(sm.session.executed_actions) == 10
    
    def test_save_and_load_preserves_data(self, populated_state_manager, temp_dir):
        """Test that save/load preserves all data accurately."""
        snapshot_path = temp_dir / "roundtrip.json"
        populated_state_manager.save_snapshot(str(snapshot_path))
        
        loaded_sm = StateManager.load_snapshot(str(snapshot_path), auto_save=False)
        
        # Verify all hosts
        assert len(loaded_sm.session.hosts) == len(populated_state_manager.session.hosts)
        
        # Verify vulnerabilities
        original_vulns = populated_state_manager.get_vulnerabilities()
        loaded_vulns = loaded_sm.get_vulnerabilities()
        assert len(loaded_vulns) == len(original_vulns)
        
        # Verify actions
        assert len(loaded_sm.session.executed_actions) == len(populated_state_manager.session.executed_actions)
    
    def test_atomic_write_no_corruption(self, temp_dir):
        """Test that atomic write prevents corruption."""
        sm = StateManager(target="test.com", auto_save=False)
        sm.add_host("192.168.1.1")
        
        snapshot_path = temp_dir / "atomic_test.json"
        sm.save_snapshot(str(snapshot_path))
        
        # Verify no temp files left behind
        temp_files = list(temp_dir.glob(".tmp_*"))
        assert len(temp_files) == 0
        
        # Verify file is valid
        with open(snapshot_path) as f:
            data = json.load(f)
        assert "hosts" in data
    
    def test_export_report(self, populated_state_manager, temp_dir):
        """Test report export."""
        report_path = temp_dir / "report.json"
        populated_state_manager.export_report(str(report_path))
        
        assert report_path.exists()
        with open(report_path) as f:
            report = json.load(f)
        
        assert "session" in report
        assert "summary" in report
        assert "generated_at" in report


class TestStateManagerAutoSave:
    """Test auto-save functionality."""
    
    def test_auto_save_on_add_host(self, state_manager_with_auto_save, temp_dir):
        """Test auto-save triggers on add_host."""
        state_manager_with_auto_save.add_host("192.168.1.1")
        
        # Give it a moment to save
        time.sleep(0.1)
        
        snapshot_path = temp_dir / "auto_save_snapshot.json"
        assert snapshot_path.exists()
        
        with open(snapshot_path) as f:
            data = json.load(f)
        assert "192.168.1.1" in data["hosts"]
    
    def test_auto_save_on_add_vulnerability(self, state_manager_with_auto_save, temp_dir):
        """Test auto-save triggers on add_vulnerability."""
        state_manager_with_auto_save.add_vulnerability(
            "192.168.1.1", "CVE-001", "Test", Severity.HIGH, "/test", tool="nuclei"
        )
        
        time.sleep(0.1)
        
        snapshot_path = temp_dir / "auto_save_snapshot.json"
        with open(snapshot_path) as f:
            data = json.load(f)
        assert len(data["hosts"]["192.168.1.1"]["vulnerabilities"]) == 1
    
    def test_auto_save_on_record_action(self, state_manager_with_auto_save, temp_dir):
        """Test auto-save triggers on record_action."""
        state_manager_with_auto_save.record_action("nmap", "192.168.1.1", "-sV")
        
        time.sleep(0.1)
        
        snapshot_path = temp_dir / "auto_save_snapshot.json"
        with open(snapshot_path) as f:
            data = json.load(f)
        assert len(data["executed_actions"]) == 1


# =============================================================================
# INTEGRATION TESTS - AI Context
# =============================================================================

class TestStateManagerAIContext:
    """Test AI context generation."""
    
    def test_get_context_for_ai_compact(self, populated_state_manager):
        """Test compact AI context generation."""
        context = populated_state_manager.get_context_for_ai(detailed=False)
        
        # Should be valid JSON
        data = json.loads(context)
        assert "session_id" in data
        assert "target" in data
        assert "hosts" in data
        assert "summary" in data
    
    def test_get_context_for_ai_detailed(self, populated_state_manager):
        """Test detailed AI context generation."""
        context = populated_state_manager.get_context_for_ai(detailed=True)
        
        data = json.loads(context)
        # Detailed should include full vulnerability data
        assert "hosts" in data
        assert "executed_actions" in data
    
    def test_get_summary(self, populated_state_manager):
        """Test summary statistics."""
        summary = populated_state_manager.get_summary()
        
        assert summary["target"] == "corp.example.com"
        assert summary["hosts_discovered"] == 3
        assert summary["actions_executed"] == 10
        assert summary["total_vulnerabilities"] > 0


# =============================================================================
# PERFORMANCE TESTS
# =============================================================================

@pytest.mark.slow
class TestStateManagerPerformance:
    """Performance tests with large datasets."""
    
    def test_large_dataset_operations(self, large_state_manager):
        """Test operations on 1000+ entry dataset."""
        # Should complete quickly even with many entries
        start = time.time()
        
        summary = large_state_manager.get_summary()
        context = large_state_manager.get_context_for_ai(detailed=False)
        vulns = large_state_manager.get_vulnerabilities()
        
        duration = time.time() - start
        
        # Should complete in under 2 seconds
        assert duration < 2.0
        assert summary["hosts_discovered"] == 50
        # Note: Some vulnerabilities may be deduplicated based on fingerprint
        assert summary["total_vulnerabilities"] >= 500  # At least 50% should be unique
    
    def test_large_dataset_save_load(self, large_state_manager, temp_dir):
        """Test save/load performance with large dataset."""
        snapshot_path = temp_dir / "large_perf.json"
        
        start = time.time()
        large_state_manager.save_snapshot(str(snapshot_path))
        save_duration = time.time() - start
        
        start = time.time()
        loaded = StateManager.load_snapshot(str(snapshot_path), auto_save=False)
        load_duration = time.time() - start
        
        # Should complete in reasonable time
        assert save_duration < 5.0
        assert load_duration < 5.0
        assert len(loaded.session.hosts) == 50
    
    def test_vulnerability_deduplication_performance(self, empty_state_manager):
        """Test deduplication with many vulnerabilities."""
        # Add 100 vulnerabilities
        for i in range(100):
            empty_state_manager.add_vulnerability(
                "192.168.1.1",
                f"CVE-2021-{1000 + i}",
                f"Vuln {i}",
                Severity.HIGH,
                f"/path{i}",
                tool="nuclei"
            )
        
        # Try to add duplicates
        start = time.time()
        for i in range(100):
            result = empty_state_manager.add_vulnerability(
                "192.168.1.1",
                f"CVE-2021-{1000 + i}",
                f"Vuln {i}",
                Severity.HIGH,
                f"/path{i}",
                tool="nuclei"
            )
            assert result is False
        
        duration = time.time() - start
        assert duration < 1.0  # Should be fast with hash-based lookup


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================

class TestStateManagerThreadSafety:
    """Test thread safety of StateManager operations."""
    
    def test_concurrent_host_addition(self, concurrent_runner):
        """Test adding hosts from multiple threads."""
        concurrent_runner.add_hosts_concurrently(num_threads=10, hosts_per_thread=10)
        
        # Should have exactly 100 unique hosts
        assert len(concurrent_runner.sm.session.hosts) == 100
        assert len(concurrent_runner.errors) == 0
    
    def test_concurrent_vulnerability_addition(self, concurrent_runner):
        """Test adding vulnerabilities from multiple threads."""
        # Pre-create hosts
        for i in range(10):
            concurrent_runner.sm.add_host(f"192.168.{i}.1")
        
        concurrent_runner.add_vulns_concurrently(num_threads=5, vulns_per_thread=20)
        
        # Should have 100 unique vulnerabilities
        vulns = concurrent_runner.sm.get_vulnerabilities()
        assert len(vulns) == 100
        assert len(concurrent_runner.errors) == 0
    
    def test_concurrent_mixed_operations(self, concurrent_state_manager):
        """Test mixed operations from multiple threads."""
        errors = []
        results = {"hosts": 0, "vulns": 0, "actions": 0}
        lock = threading.Lock()
        
        def host_worker(thread_id):
            try:
                for i in range(5):
                    concurrent_state_manager.add_host(f"10.{thread_id}.{i}.1")
                    with lock:
                        results["hosts"] += 1
            except Exception as e:
                with lock:
                    errors.append(str(e))
        
        def vuln_worker(thread_id):
            try:
                for i in range(5):
                    concurrent_state_manager.add_vulnerability(
                        f"10.{thread_id % 5}.0.1",
                        f"CVE-{thread_id}-{i}",
                        f"Vuln {i}",
                        Severity.MEDIUM,
                        f"/path{thread_id}-{i}",
                        tool="nuclei"
                    )
                    with lock:
                        results["vulns"] += 1
            except Exception as e:
                with lock:
                    errors.append(str(e))
        
        def action_worker(thread_id):
            try:
                for i in range(5):
                    concurrent_state_manager.record_action(
                        "nmap", f"10.{thread_id}.{i}.1", f"-p {i}"
                    )
                    with lock:
                        results["actions"] += 1
            except Exception as e:
                with lock:
                    errors.append(str(e))
        
        threads = []
        for i in range(5):
            threads.append(threading.Thread(target=host_worker, args=(i,)))
            threads.append(threading.Thread(target=vuln_worker, args=(i,)))
            threads.append(threading.Thread(target=action_worker, args=(i,)))
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert results["hosts"] == 25
        assert results["vulns"] == 25
        assert results["actions"] == 25
    
    def test_concurrent_save_load(self, temp_dir):
        """Test concurrent save operations don't corrupt data."""
        sm = StateManager(target="concurrent.com", auto_save=False)
        
        # Add initial data
        for i in range(50):
            sm.add_host(f"192.168.1.{i}")
        
        snapshot_path = temp_dir / "concurrent_save.json"
        errors = []
        
        def save_worker():
            try:
                for _ in range(10):
                    sm.save_snapshot(str(snapshot_path))
                    time.sleep(0.01)
            except Exception as e:
                errors.append(str(e))
        
        def modify_worker():
            try:
                for i in range(50, 100):
                    sm.add_host(f"192.168.1.{i}")
                    time.sleep(0.01)
            except Exception as e:
                errors.append(str(e))
        
        threads = [
            threading.Thread(target=save_worker),
            threading.Thread(target=modify_worker),
            threading.Thread(target=save_worker),
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should be able to load without errors
        loaded = StateManager.load_snapshot(str(snapshot_path), auto_save=False)
        assert len(loaded.session.hosts) >= 50  # At least initial data
        assert len(errors) == 0


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestStateManagerEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_session_save_load(self, temp_dir):
        """Test saving and loading empty session."""
        sm = StateManager(target="empty.com", auto_save=False)
        snapshot_path = temp_dir / "empty.json"
        
        sm.save_snapshot(str(snapshot_path))
        loaded = StateManager.load_snapshot(str(snapshot_path), auto_save=False)
        
        assert loaded.session.target == "empty.com"
        assert len(loaded.session.hosts) == 0
    
    def test_unicode_hostnames(self, state_manager_with_edge_cases):
        """Test handling of unicode hostnames."""
        sm = state_manager_with_edge_cases
        
        # Should handle unicode without errors
        host = sm.get_host("日本語.example.com")
        assert host is not None
        assert host.domain == "日本語.example.com"
    
    def test_very_long_strings(self, empty_state_manager):
        """Test handling of very long strings."""
        long_title = "A" * 10000
        long_location = "/path" + "x" * 5000
        
        result = empty_state_manager.add_vulnerability(
            "192.168.1.1",
            "CVE-2021-TEST",
            long_title,
            Severity.HIGH,
            long_location,
            tool="nuclei"
        )
        assert result is True
    
    def test_special_characters_in_vulnerability(self, state_manager_with_edge_cases):
        """Test handling of special characters."""
        sm = state_manager_with_edge_cases
        
        vulns = sm.get_vulnerabilities()
        # Should find the XSS-like vulnerability
        xss_vuln = [v for v in vulns if "script" in v.location]
        assert len(xss_vuln) > 0
    
    def test_invalid_severity_handling(self, empty_state_manager):
        """Test handling of invalid severity strings."""
        # Should raise ValueError for invalid severity
        with pytest.raises(ValueError):
            empty_state_manager.add_vulnerability(
                "192.168.1.1",
                "TEST-001",
                "Test",
                "invalid-severity",
                "/test",
                tool="nuclei"
            )
    
    def test_duplicate_port_updates(self, empty_state_manager):
        """Test that duplicate ports update rather than duplicate."""
        empty_state_manager.add_port("192.168.1.1", 80, "tcp", "closed")
        empty_state_manager.add_port("192.168.1.1", 80, "tcp", "open")
        empty_state_manager.add_port("192.168.1.1", 80, "tcp", "filtered")
        
        host = empty_state_manager.get_host("192.168.1.1")
        assert len(host.ports) == 1
        assert host.ports["80/tcp"].state == PortState.FILTERED
    
    def test_fingerprint_consistency(self, empty_state_manager):
        """Test that fingerprints are generated consistently."""
        # Same vulnerability should generate same fingerprint
        empty_state_manager.add_vulnerability(
            "192.168.1.1", "CVE-001", "Test", Severity.HIGH, "/api", tool="nuclei"
        )
        
        host = empty_state_manager.get_host("192.168.1.1")
        fingerprint1 = host.vulnerabilities[0].fingerprint
        
        # Try to add again - should be rejected as duplicate
        result = empty_state_manager.add_vulnerability(
            "192.168.1.1", "CVE-001", "Test", Severity.HIGH, "/api", tool="nuclei"
        )
        assert result is False
        
        # Fingerprint should be identical
        assert len(host.vulnerabilities) == 1
    
    def test_none_values_handling(self, empty_state_manager):
        """Test handling of None values in optional fields."""
        empty_state_manager.add_port(
            "192.168.1.1", 80, "tcp", "open", service=None
        )
        
        host = empty_state_manager.get_host("192.168.1.1")
        port = host.ports["80/tcp"]
        assert port.service is None
    
    def test_snapshot_path_with_spaces(self, temp_dir):
        """Test snapshot paths with spaces and special chars."""
        sm = StateManager(
            target="test.com",
            auto_save=False,
            snapshot_path=str(temp_dir / "path with spaces" / "snapshot.json")
        )
        sm.add_host("192.168.1.1")
        
        sm.save_snapshot()
        assert sm.snapshot_path.exists()


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_create_state_manager(self):
        """Test create_state_manager helper."""
        sm = create_state_manager("example.com", auto_save=False)
        assert sm.session.target == "example.com"
        assert sm.auto_save is False
    
    def test_load_state_manager(self, saved_snapshot_path):
        """Test load_state_manager helper."""
        sm = load_state_manager(saved_snapshot_path, auto_save=False)
        assert sm.session.target == "corp.example.com"


# =============================================================================
# REALISTIC WORKFLOW TESTS
# =============================================================================

class TestRealisticWorkflows:
    """Test realistic penetration testing workflows."""
    
    def test_full_recon_workflow(self, temp_dir):
        """Test a full reconnaissance workflow."""
        sm = StateManager(target="target.com", auto_save=False)
        
        # Step 1: Subdomain discovery
        sm.record_action("subfinder", "target.com", "-all", "5 subdomains found")
        subdomains = ["www", "api", "admin", "cdn", "mail"]
        for sub in subdomains:
            sm.add_host(f"{sub}.target.com")
        
        # Step 2: Port scanning
        for sub in subdomains:
            sm.record_action("nmap", f"{sub}.target.com", "-sV", "ports found")
            sm.add_port(f"{sub}.target.com", 80, "tcp", "open")
            sm.add_port(f"{sub}.target.com", 443, "tcp", "open")
            if sub == "api":
                sm.add_port(f"{sub}.target.com", 8080, "tcp", "open")
        
        # Step 3: Vulnerability scanning
        sm.record_action("nuclei", "api.target.com", "-t cves/", "2 vulns found")
        sm.add_vulnerability(
            "api.target.com", "CVE-2021-44228", "Log4j RCE",
            Severity.CRITICAL, "/api/v1/search", port_num=8080, tool="nuclei"
        )
        
        # Verify workflow results
        summary = sm.get_summary()
        assert summary["hosts_discovered"] == 5
        assert summary["actions_executed"] == 7
        
        # Save and verify persistence
        sm.save_snapshot(str(temp_dir / "workflow.json"))
        loaded = StateManager.load_snapshot(str(temp_dir / "workflow.json"))
        assert len(loaded.get_vulnerabilities()) == 1
    
    def test_duplicate_detection_workflow(self, empty_state_manager):
        """Test workflow with duplicate detection."""
        # First scan
        empty_state_manager.add_vulnerability(
            "192.168.1.1", "CVE-001", "Vuln 1", Severity.HIGH, "/api", tool="nuclei"
        )
        empty_state_manager.record_action("nuclei", "192.168.1.1", "-t cves/")
        
        # Second scan (should detect duplicates)
        is_dup = empty_state_manager.was_action_executed("nuclei", "192.168.1.1", "-t cves/")
        assert is_dup is True
        
        result = empty_state_manager.add_vulnerability(
            "192.168.1.1", "CVE-001", "Vuln 1", Severity.HIGH, "/api", tool="nuclei"
        )
        assert result is False  # Duplicate rejected
        
        # Only 1 vulnerability should exist
        assert len(empty_state_manager.get_vulnerabilities()) == 1
