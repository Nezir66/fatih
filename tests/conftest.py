"""
Pytest fixtures for State Manager tests.
"""

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Generator

import pytest

from src.core.state_manager import (
    StateManager, Session, Host, Port, Vulnerability, 
    Severity, Service, Action, PortState
)
from tests.fixtures.mock_scan_data import (
    MOCK_NMAP_HOST_1, MOCK_NMAP_HOST_2, MOCK_NMAP_HOST_3,
    MOCK_NUCLEI_VULNERABILITIES, MOCK_ACTION_HISTORY,
    generate_large_dataset
)


# =============================================================================
# Basic Fixtures
# =============================================================================

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def empty_state_manager(temp_dir: Path) -> StateManager:
    """Create an empty state manager."""
    return StateManager(
        target="test.example.com",
        auto_save=False,
        snapshot_path=str(temp_dir / "test_snapshot.json")
    )


@pytest.fixture
def state_manager_with_auto_save(temp_dir: Path) -> StateManager:
    """Create a state manager with auto-save enabled."""
    return StateManager(
        target="test.example.com",
        auto_save=True,
        snapshot_path=str(temp_dir / "auto_save_snapshot.json")
    )


# =============================================================================
# Populated Fixtures with Realistic Data
# =============================================================================

@pytest.fixture
def populated_state_manager(temp_dir: Path) -> StateManager:
    """Create a state manager populated with realistic mock data."""
    sm = StateManager(
        target="corp.example.com",
        auto_save=False,
        snapshot_path=str(temp_dir / "populated_snapshot.json")
    )
    
    # Add hosts from mock data
    for mock_host in [MOCK_NMAP_HOST_1, MOCK_NMAP_HOST_2, MOCK_NMAP_HOST_3]:
        host = sm.add_host(mock_host["ip"])
        if mock_host.get("hostname"):
            host.domain = mock_host["hostname"]
        if mock_host.get("os"):
            host.os_info = mock_host["os"]
        
        # Add ports
        for mock_port in mock_host["ports"]:
            service = None
            if mock_port.get("service"):
                svc = mock_port["service"]
                service = Service(
                    name=svc.get("name"),
                    product=svc.get("product"),
                    version=svc.get("version"),
                    banner=svc.get("banner")
                )
            
            sm.add_port(
                host_id=mock_host["ip"],
                port_num=mock_port["number"],
                protocol=mock_port["protocol"],
                state=mock_port["state"],
                service=service
            )
    
    # Add vulnerabilities
    for mock_vuln in MOCK_NUCLEI_VULNERABILITIES:
        sm.add_vulnerability(
            target_host=mock_vuln["host"],
            vuln_id=mock_vuln["vuln_id"],
            title=mock_vuln["title"],
            severity=mock_vuln["severity"],
            location=mock_vuln["location"],
            description=mock_vuln.get("description"),
            evidence=mock_vuln.get("evidence"),
            tool=mock_vuln["tool"],
            port_num=mock_vuln.get("port"),
            protocol="tcp"
        )
    
    # Add action history
    for mock_action in MOCK_ACTION_HISTORY:
        sm.record_action(
            tool=mock_action["tool"],
            target=mock_action["target"],
            parameters=mock_action["parameters"],
            result_summary=mock_action.get("result_summary")
        )
    
    return sm


@pytest.fixture
def large_state_manager(temp_dir: Path) -> StateManager:
    """Create a state manager with 1000+ entries for performance tests."""
    sm = StateManager(
        target="large.corp.com",
        auto_save=False,
        snapshot_path=str(temp_dir / "large_snapshot.json")
    )
    
    # Generate 50 hosts with 20 vulns each = 1000 vulns
    dataset = generate_large_dataset(num_hosts=50, vulns_per_host=20)
    
    for mock_host in dataset["hosts"]:
        host = sm.add_host(mock_host["ip"])
        host.domain = mock_host["hostname"]
        host.os_info = mock_host["os"]
        
        for mock_port in mock_host["ports"]:
            service = None
            if mock_port.get("service"):
                svc = mock_port["service"]
                service = Service(
                    name=svc.get("name"),
                    product=svc.get("product"),
                    version=svc.get("version")
                )
            
            sm.add_port(
                host_id=mock_host["ip"],
                port_num=mock_port["number"],
                protocol=mock_port["protocol"],
                state=mock_port["state"],
                service=service
            )
    
    for mock_vuln in dataset["vulnerabilities"]:
        sm.add_vulnerability(
            target_host=mock_vuln["host"],
            vuln_id=mock_vuln["vuln_id"],
            title=mock_vuln["title"],
            severity=mock_vuln["severity"],
            location=mock_vuln["location"],
            description=mock_vuln["description"],
            evidence=mock_vuln["evidence"],
            tool=mock_vuln["tool"],
            port_num=mock_vuln.get("port")
        )
    
    for mock_action in dataset["actions"]:
        sm.record_action(
            tool=mock_action["tool"],
            target=mock_action["target"],
            parameters=mock_action["parameters"],
            result_summary=mock_action["result_summary"]
        )
    
    return sm


# =============================================================================
# Edge Case Fixtures
# =============================================================================

@pytest.fixture
def state_manager_with_edge_cases(temp_dir: Path) -> StateManager:
    """Create a state manager with edge case data."""
    sm = StateManager(
        target="edge-cases.example.com",
        auto_save=False,
        snapshot_path=str(temp_dir / "edge_cases.json")
    )
    
    # Unicode hostnames
    sm.add_host("日本語.example.com")
    sm.add_host("emoji🚀.example.com")
    
    # Very long strings
    long_hostname = "a" * 1000 + ".example.com"
    sm.add_host(long_hostname)
    
    # Special characters
    sm.add_host("test<script>alert(1)</script>.example.com")
    
    # Add vulnerability with special characters
    sm.add_vulnerability(
        target_host="日本語.example.com",
        vuln_id="CVE-2021-44228",
        title="日本語タイトル - UTF-8 Test",
        severity=Severity.CRITICAL,
        location="/path?param=<script>alert('XSS')</script>",
        description="Description with unicode: 🚨🔒🛡️ and special chars: <>&\"'",
        evidence="Evidence: \n\t\r special chars",
        tool="nuclei"
    )
    
    return sm


# =============================================================================
# Thread Safety Fixtures
# =============================================================================

@pytest.fixture
def concurrent_state_manager(temp_dir: Path) -> StateManager:
    """Create a state manager for thread safety tests."""
    return StateManager(
        target="concurrent.example.com",
        auto_save=False,
        snapshot_path=str(temp_dir / "concurrent.json")
    )


class ConcurrentTestRunner:
    """Helper class for running concurrent operations."""
    
    def __init__(self, state_manager: StateManager):
        self.sm = state_manager
        self.errors = []
        self.results = []
        self.lock = threading.Lock()
    
    def add_hosts_concurrently(self, num_threads: int = 10, hosts_per_thread: int = 10):
        """Add hosts from multiple threads."""
        def worker(thread_id: int):
            try:
                for i in range(hosts_per_thread):
                    host_id = f"192.168.{thread_id}.{i}"
                    host = self.sm.add_host(host_id)
                    with self.lock:
                        self.results.append((thread_id, host_id, host.get_key()))
            except Exception as e:
                with self.lock:
                    self.errors.append((thread_id, str(e)))
        
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
    
    def add_vulns_concurrently(self, num_threads: int = 5, vulns_per_thread: int = 20):
        """Add vulnerabilities from multiple threads."""
        def worker(thread_id: int):
            try:
                for i in range(vulns_per_thread):
                    target = f"192.168.{thread_id % 10}.1"
                    added = self.sm.add_vulnerability(
                        target_host=target,
                        vuln_id=f"CVE-2021-{10000 + thread_id * 100 + i}",
                        title=f"Vuln {i} from thread {thread_id}",
                        severity=Severity.HIGH,
                        location=f"/path{i}",
                        tool="nuclei"
                    )
                    with self.lock:
                        self.results.append((thread_id, i, added))
            except Exception as e:
                with self.lock:
                    self.errors.append((thread_id, str(e)))
        
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()


@pytest.fixture
def concurrent_runner(concurrent_state_manager: StateManager) -> ConcurrentTestRunner:
    """Provide a concurrent test runner."""
    return ConcurrentTestRunner(concurrent_state_manager)


# =============================================================================
# Snapshot Fixtures
# =============================================================================

@pytest.fixture
def saved_snapshot_path(populated_state_manager: StateManager, temp_dir: Path) -> str:
    """Create and return path to a saved snapshot."""
    snapshot_path = temp_dir / "saved_snapshot.json"
    populated_state_manager.save_snapshot(str(snapshot_path))
    return str(snapshot_path)


# =============================================================================
# Model Fixtures
# =============================================================================

@pytest.fixture
def sample_service() -> Service:
    """Create a sample Service object."""
    return Service(
        name="http",
        product="Apache httpd",
        version="2.4.41",
        banner="Apache/2.4.41 (Ubuntu)"
    )


@pytest.fixture
def sample_port() -> Port:
    """Create a sample Port object."""
    return Port(
        number=80,
        protocol="tcp",
        state=PortState.OPEN,
        service=Service(name="http", product="Apache", version="2.4.41")
    )


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Create a sample Vulnerability object."""
    return Vulnerability(
        fingerprint="abc123",
        vuln_id="CVE-2021-44228",
        title="Log4j RCE",
        severity=Severity.CRITICAL,
        description="Apache Log4j2 vulnerability",
        location="/api/login",
        evidence="JNDI lookup detected",
        tool="nuclei"
    )


@pytest.fixture
def sample_host() -> Host:
    """Create a sample Host object."""
    return Host(
        ip="192.168.1.100",
        domain="web01.example.com",
        os_info="Linux 4.15"
    )


@pytest.fixture
def sample_action() -> Action:
    """Create a sample Action object."""
    return Action(
        tool="nmap",
        target="192.168.1.100",
        parameters="-sV -p 1-1000",
        result_summary="3 open ports found"
    )
