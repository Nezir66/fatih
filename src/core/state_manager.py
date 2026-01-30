"""
State Manager - Structured memory for the Fatih penetration testing agent.

This module provides a hierarchical data model for storing scan results,
with support for deduplication, persistence, and AI-friendly context generation.
"""

import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Vulnerability severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    INFO = "info"


class EndpointType(str, Enum):
    """Types of web endpoints discovered during crawling."""
    PAGE = "page"
    FORM = "form"
    API = "api"
    JS_ENDPOINT = "js_endpoint"
    REDIRECT = "redirect"
    STATIC_FILE = "static_file"


class PortState(str, Enum):
    """Port scan states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class Service(BaseModel):
    """Service running on a port."""
    name: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    
    def to_summary(self) -> Dict[str, Any]:
        """Return a compact summary for AI context."""
        return {
            "name": self.name,
            "version": self.version,
            "product": self.product
        }


class WebEndpoint(BaseModel):
    """Discovered web endpoint (URL, form, API)."""
    url: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.PAGE
    parameters: List[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    source: str = "crawl"  # "crawl", "js_analysis", "sitemap"
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    
    def to_summary(self) -> Dict[str, Any]:
        """Return a compact summary for AI context."""
        return {
            "url": self.url,
            "method": self.method,
            "type": self.endpoint_type.value,
            "status": self.status_code,
            "params": self.parameters
        }


class WebHost(BaseModel):
    """Web-specific host data extending Host with crawling results."""
    base_url: str
    endpoints: List[WebEndpoint] = Field(default_factory=list)
    sitemap: Optional[str] = None
    js_files: List[str] = Field(default_factory=list)
    forms: List[Dict[str, Any]] = Field(default_factory=list)
    apis: List[Dict[str, Any]] = Field(default_factory=list)
    crawl_completed: bool = False
    last_crawled: Optional[datetime] = None
    
    def add_endpoint(self, endpoint: WebEndpoint) -> bool:
        """Add endpoint if not duplicate. Returns True if added."""
        existing_urls = {e.url for e in self.endpoints}
        if endpoint.url in existing_urls:
            return False
        self.endpoints.append(endpoint)
        
        # Categorize by type
        if endpoint.endpoint_type == EndpointType.FORM:
            self.forms.append(endpoint.to_summary())
        elif endpoint.endpoint_type == EndpointType.API:
            self.apis.append(endpoint.to_summary())
        elif endpoint.endpoint_type == EndpointType.JS_ENDPOINT:
            if endpoint.url not in self.js_files:
                self.js_files.append(endpoint.url)
        
        return True
    
    def get_endpoints_by_type(self, endpoint_type: EndpointType) -> List[WebEndpoint]:
        """Get all endpoints of a specific type."""
        return [e for e in self.endpoints if e.endpoint_type == endpoint_type]
    
    def to_summary(self) -> Dict[str, Any]:
        """Return a compact summary for AI context."""
        return {
            "base_url": self.base_url,
            "total_endpoints": len(self.endpoints),
            "pages": len(self.get_endpoints_by_type(EndpointType.PAGE)),
            "forms": len(self.forms),
            "apis": len(self.apis),
            "js_files": len(self.js_files),
            "crawl_completed": self.crawl_completed
        }


class Vulnerability(BaseModel):
    """Security vulnerability finding."""
    fingerprint: str = Field(..., description="Unique hash for deduplication")
    vuln_id: str = Field(..., description="CVE ID, template ID, or identifier")
    title: str
    severity: Severity
    description: Optional[str] = None
    location: str = Field(..., description="Specific path, parameter, or port")
    evidence: Optional[str] = None
    tool: str = Field(..., description="Tool that found this (nuclei, nmap, etc.)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v):
        if isinstance(v, str):
            return Severity(v.lower())
        return v
    
    def to_summary(self) -> Dict[str, Any]:
        """Return a compact summary for AI context."""
        return {
            "id": self.vuln_id,
            "title": self.title,
            "severity": self.severity.value,
            "location": self.location
        }


class Port(BaseModel):
    """Network port on a host."""
    number: int
    protocol: str = "tcp"
    state: PortState = PortState.CLOSED
    service: Optional[Service] = None
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    
    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v):
        return v.lower()
    
    def get_key(self) -> str:
        """Return unique key for this port."""
        return f"{self.number}/{self.protocol}"
    
    def add_vulnerability(self, vuln: Vulnerability) -> bool:
        """Add vulnerability if not duplicate. Returns True if added."""
        existing_fingerprints = {v.fingerprint for v in self.vulnerabilities}
        if vuln.fingerprint in existing_fingerprints:
            return False
        self.vulnerabilities.append(vuln)
        return True
    
    def to_summary(self) -> Dict[str, Any]:
        """Return a compact summary for AI context."""
        result = {
            "port": self.number,
            "protocol": self.protocol,
            "state": self.state.value
        }
        if self.service:
            result["service"] = self.service.to_summary()
        if self.vulnerabilities:
            result["vulnerabilities"] = [v.to_summary() for v in self.vulnerabilities]
        return result


class Host(BaseModel):
    """Target host (IP or domain)."""
    ip: Optional[str] = None
    domain: Optional[str] = None
    os_info: Optional[str] = None
    ports: Dict[str, Port] = Field(default_factory=dict)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    
    def get_key(self) -> str:
        """Return unique key for this host."""
        return self.ip or self.domain or "unknown"
    
    def add_port(self, port: Port) -> Port:
        """Add or update a port. Returns the port object."""
        key = port.get_key()
        if key in self.ports:
            # Update existing port
            existing = self.ports[key]
            if port.state != PortState.CLOSED:
                existing.state = port.state
            if port.service:
                existing.service = port.service
        else:
            self.ports[key] = port
        self.last_updated = datetime.utcnow()
        return self.ports[key]
    
    def add_vulnerability(self, vuln: Vulnerability) -> bool:
        """Add host-level vulnerability if not duplicate."""
        existing_fingerprints = {v.fingerprint for v in self.vulnerabilities}
        if vuln.fingerprint in existing_fingerprints:
            return False
        self.vulnerabilities.append(vuln)
        self.last_updated = datetime.utcnow()
        return True
    
    def get_open_ports(self) -> List[Port]:
        """Return all open ports."""
        return [p for p in self.ports.values() if p.state == PortState.OPEN]
    
    def to_summary(self) -> Dict[str, Any]:
        """Return a compact summary for AI context."""
        result = {
            "ip": self.ip,
            "domain": self.domain,
            "open_ports": len(self.get_open_ports()),
            "total_vulnerabilities": len(self.vulnerabilities) + sum(
                len(p.vulnerabilities) for p in self.ports.values()
            )
        }
        if self.os_info:
            result["os"] = self.os_info
        if self.ports:
            result["ports"] = [p.to_summary() for p in self.ports.values()]
        if self.vulnerabilities:
            result["host_vulnerabilities"] = [v.to_summary() for v in self.vulnerabilities]
        return result


class Action(BaseModel):
    """Executed scan action for loop prevention."""
    tool: str
    target: str
    parameters: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    result_summary: Optional[str] = None
    
    def get_key(self) -> str:
        """Return unique key for this action."""
        return f"{self.tool}|{self.target}|{self.parameters}"


class Session(BaseModel):
    """Root session containing all scan data."""
    id: str = Field(default_factory=lambda: datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
    target: str
    start_time: datetime = Field(default_factory=datetime.utcnow)
    config: Dict[str, Any] = Field(default_factory=dict)
    hosts: Dict[str, Host] = Field(default_factory=dict)
    web_hosts: Dict[str, WebHost] = Field(default_factory=dict)
    executed_actions: List[Action] = Field(default_factory=list)
    
    def get_or_create_host(self, identifier: str) -> Host:
        """Get existing host or create new one."""
        # Normalize identifier
        identifier = identifier.strip().lower()
        
        # Check if exists
        if identifier in self.hosts:
            return self.hosts[identifier]
        
        # Determine if IP or domain
        host = Host(ip=identifier if self._is_ip(identifier) else None,
                   domain=identifier if not self._is_ip(identifier) else None)
        
        # Also store by both IP and domain if we learn the other
        self.hosts[identifier] = host
        return host
    
    def _is_ip(self, identifier: str) -> bool:
        """Check if identifier is an IP address."""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, identifier))
    
    def link_ip_to_domain(self, ip: str, domain: str) -> None:
        """Link an IP to a domain when both are discovered."""
        ip = ip.strip().lower()
        domain = domain.strip().lower()
        
        if ip in self.hosts and domain in self.hosts:
            # Merge - prefer the one with more data
            ip_host = self.hosts[ip]
            domain_host = self.hosts[domain]
            
            # Merge ports
            for port in domain_host.ports.values():
                ip_host.add_port(port)
            
            # Merge vulnerabilities
            for vuln in domain_host.vulnerabilities:
                ip_host.add_vulnerability(vuln)
            
            # Update references
            ip_host.domain = domain
            domain_host.ip = ip
    
    def record_action(self, tool: str, target: str, parameters: str, 
                     result_summary: Optional[str] = None) -> None:
        """Record an executed action."""
        action = Action(
            tool=tool.lower(),
            target=target.lower(),
            parameters=parameters,
            result_summary=result_summary
        )
        self.executed_actions.append(action)
    
    def was_action_executed(self, tool: str, target: str, parameters: str) -> bool:
        """Check if an action was already executed."""
        key = f"{tool.lower()}|{target.lower()}|{parameters}"
        return any(action.get_key() == key for action in self.executed_actions)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get high-level summary statistics."""
        total_ports = sum(len(h.ports) for h in self.hosts.values())
        open_ports = sum(len(h.get_open_ports()) for h in self.hosts.values())
        total_vulns = sum(
            len(h.vulnerabilities) + sum(len(p.vulnerabilities) for p in h.ports.values())
            for h in self.hosts.values()
        )
        
        return {
            "session_id": self.id,
            "target": self.target,
            "hosts_discovered": len(self.hosts),
            "total_ports": total_ports,
            "open_ports": open_ports,
            "total_vulnerabilities": total_vulns,
            "actions_executed": len(self.executed_actions)
        }
    
    def to_summary(self) -> Dict[str, Any]:
        """Return compact summary for AI context."""
        return {
            "session_id": self.id,
            "target": self.target,
            "hosts": {k: v.to_summary() for k, v in self.hosts.items()},
            "summary": self.get_summary()
        }


class StateManager:
    """Main interface for managing scan state."""
    
    def __init__(self, target: str, auto_save: bool = True, 
                 snapshot_path: str = "outputs/session_state.json"):
        """Initialize state manager.
        
        Args:
            target: The primary target being scanned
            auto_save: Whether to auto-save after each modification
            snapshot_path: Path for auto-save snapshots
        """
        self.session = Session(target=target)
        self.auto_save = auto_save
        self.snapshot_path = Path(snapshot_path)
        self._ensure_output_dir()
    
    def _ensure_output_dir(self) -> None:
        """Ensure output directory exists."""
        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _generate_fingerprint(self, target_id: str, vuln_id: str, location: str) -> str:
        """Generate unique fingerprint for vulnerability deduplication."""
        raw = f"{target_id}|{vuln_id}|{location}"
        return hashlib.md5(raw.encode()).hexdigest()
    
    def _trigger_auto_save(self) -> None:
        """Save snapshot if auto-save is enabled."""
        if self.auto_save:
            self.save_snapshot()
    
    # ==================== Host Management ====================
    
    def add_host(self, identifier: str) -> Host:
        """Add or retrieve a host.
        
        Args:
            identifier: IP address or domain name
            
        Returns:
            Host object
        """
        host = self.session.get_or_create_host(identifier)
        self._trigger_auto_save()
        return host
    
    def get_host(self, identifier: str) -> Optional[Host]:
        """Get host by IP or domain."""
        identifier = identifier.strip().lower()
        return self.session.hosts.get(identifier)
    
    def link_host_ip_domain(self, ip: str, domain: str) -> None:
        """Link an IP to its domain name."""
        self.session.link_ip_to_domain(ip, domain)
        self._trigger_auto_save()
    
    # ==================== Port Management ====================
    
    def add_port(self, host_id: str, port_num: int, protocol: str = "tcp",
                state: Union[str, PortState] = PortState.CLOSED,
                service: Optional[Service] = None) -> Port:
        """Add or update a port on a host.
        
        Args:
            host_id: IP or domain of the host
            port_num: Port number
            protocol: tcp or udp
            state: Port state
            service: Service information
            
        Returns:
            Port object
        """
        host = self.add_host(host_id)
        
        if isinstance(state, str):
            state = PortState(state.lower())
        
        port = Port(number=port_num, protocol=protocol, state=state, service=service)
        result = host.add_port(port)
        self._trigger_auto_save()
        return result
    
    def get_open_ports(self, host_id: Optional[str] = None) -> List[Port]:
        """Get all open ports, optionally filtered by host."""
        if host_id:
            host = self.get_host(host_id)
            return host.get_open_ports() if host else []
        
        all_ports = []
        for host in self.session.hosts.values():
            all_ports.extend(host.get_open_ports())
        return all_ports
    
    # ==================== Web Host Management ====================
    
    def add_web_host(self, base_url: str) -> WebHost:
        """Add or retrieve a web host for crawling results.
        
        Args:
            base_url: The base URL of the web application (e.g., 'https://example.com')
            
        Returns:
            WebHost object
        """
        base_url = base_url.strip().lower()
        if base_url not in self.session.web_hosts:
            self.session.web_hosts[base_url] = WebHost(base_url=base_url)
            logger.debug(f"Created WebHost for {base_url}")
        self._trigger_auto_save()
        return self.session.web_hosts[base_url]
    
    def get_web_host(self, base_url: str) -> Optional[WebHost]:
        """Get web host by base URL."""
        base_url = base_url.strip().lower()
        return self.session.web_hosts.get(base_url)
    
    def add_web_endpoint(self, base_url: str, endpoint: WebEndpoint) -> bool:
        """Add a web endpoint to a web host.
        
        Args:
            base_url: The base URL of the web application
            endpoint: WebEndpoint object to add
            
        Returns:
            True if added, False if duplicate
        """
        web_host = self.add_web_host(base_url)
        result = web_host.add_endpoint(endpoint)
        if result:
            web_host.last_crawled = datetime.utcnow()
            self._trigger_auto_save()
            logger.debug(f"Added endpoint to {base_url}: {endpoint.url}")
        return result
    
    def get_web_endpoints(self, base_url: str, 
                         endpoint_type: Optional[EndpointType] = None) -> List[WebEndpoint]:
        """Get all web endpoints for a host, optionally filtered by type.
        
        Args:
            base_url: The base URL of the web application
            endpoint_type: Optional filter by endpoint type
            
        Returns:
            List of WebEndpoint objects
        """
        web_host = self.get_web_host(base_url)
        if not web_host:
            return []
        
        if endpoint_type:
            return web_host.get_endpoints_by_type(endpoint_type)
        return web_host.endpoints
    
    def get_forms(self, base_url: str) -> List[Dict[str, Any]]:
        """Get all discovered forms for a web host."""
        web_host = self.get_web_host(base_url)
        return web_host.forms if web_host else []
    
    def get_api_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Get all discovered API endpoints for a web host."""
        web_host = self.get_web_host(base_url)
        return web_host.apis if web_host else []
    
    def complete_crawl(self, base_url: str, sitemap: Optional[str] = None) -> None:
        """Mark a web host crawl as completed.
        
        Args:
            base_url: The base URL of the web application
            sitemap: Optional XML sitemap content
        """
        web_host = self.add_web_host(base_url)
        web_host.crawl_completed = True
        web_host.last_crawled = datetime.utcnow()
        if sitemap:
            web_host.sitemap = sitemap
        self._trigger_auto_save()
        logger.info(f"Crawl completed for {base_url}: {len(web_host.endpoints)} endpoints discovered")
    
    # ==================== Vulnerability Management ====================
    
    def add_vulnerability(self, target_host: str, vuln_id: str, title: str,
                         severity: Union[str, Severity], location: str,
                         description: Optional[str] = None,
                         evidence: Optional[str] = None,
                         tool: str = "unknown",
                         port_num: Optional[int] = None,
                         protocol: str = "tcp") -> bool:
        """Add a vulnerability to a host or specific port.
        
        Args:
            target_host: IP or domain
            vuln_id: CVE ID or template ID
            title: Vulnerability title
            severity: Severity level
            location: Specific location (path, parameter, or port)
            description: Detailed description
            evidence: Raw evidence/output
            tool: Tool that found this
            port_num: If port-specific, the port number
            protocol: Port protocol
            
        Returns:
            True if added, False if duplicate
        """
        host = self.add_host(target_host)
        
        # Determine target ID for fingerprint
        if port_num:
            target_id = f"{host.get_key()}:{port_num}/{protocol}"
            # Ensure port exists
            port_key = f"{port_num}/{protocol}"
            if port_key not in host.ports:
                self.add_port(target_host, port_num, protocol, PortState.OPEN)
            target_obj = host.ports[port_key]
        else:
            target_id = host.get_key()
            target_obj = host
        
        # Create vulnerability
        fingerprint = self._generate_fingerprint(target_id, vuln_id, location)
        
        if isinstance(severity, str):
            severity = Severity(severity.lower())
        
        vuln = Vulnerability(
            fingerprint=fingerprint,
            vuln_id=vuln_id,
            title=title,
            severity=severity,
            description=description,
            location=location,
            evidence=evidence,
            tool=tool.lower()
        )
        
        # Add to target
        if isinstance(target_obj, Port):
            result = target_obj.add_vulnerability(vuln)
        else:
            result = target_obj.add_vulnerability(vuln)
        
        if result:
            self._trigger_auto_save()
        
        return result
    
    def get_vulnerabilities(self, host_id: Optional[str] = None,
                           min_severity: Optional[Severity] = None) -> List[Vulnerability]:
        """Get all vulnerabilities, optionally filtered."""
        all_vulns = []
        
        hosts = [self.get_host(host_id)] if host_id else self.session.hosts.values()
        
        for host in hosts:
            if not host:
                continue
            # Host-level vulnerabilities
            all_vulns.extend(host.vulnerabilities)
            # Port-level vulnerabilities
            for port in host.ports.values():
                all_vulns.extend(port.vulnerabilities)
        
        if min_severity:
            severity_order = {s: i for i, s in enumerate([
                Severity.INFO, Severity.LOW, Severity.MEDIUM, 
                Severity.HIGH, Severity.CRITICAL
            ])}
            min_idx = severity_order.get(min_severity, 0)
            all_vulns = [v for v in all_vulns 
                        if severity_order.get(v.severity, 0) >= min_idx]
        
        return all_vulns
    
    # ==================== Action Management (Loop Prevention) ====================
    
    def record_action(self, tool: str, target: str, parameters: str,
                     result_summary: Optional[str] = None) -> None:
        """Record an executed action to prevent loops."""
        self.session.record_action(tool, target, parameters, result_summary)
        self._trigger_auto_save()
    
    def was_action_executed(self, tool: str, target: str, parameters: str) -> bool:
        """Check if an action was already executed."""
        return self.session.was_action_executed(tool, target, parameters)
    
    def get_executed_actions(self) -> List[Action]:
        """Get list of all executed actions."""
        return self.session.executed_actions
    
    # ==================== Persistence ====================
    
    def save_snapshot(self, path: Optional[str] = None) -> None:
        """Save current state to disk atomically.
        
        Uses atomic write pattern: write to temp file, then rename.
        This prevents corruption if the process crashes during write.
        
        Args:
            path: Override path (uses default if not specified)
        """
        save_path = Path(path) if path else self.snapshot_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create temp file in same directory for atomic rename
        temp_fd, temp_path = tempfile.mkstemp(
            dir=save_path.parent,
            prefix=f".tmp_{save_path.name}.",
            suffix=".tmp"
        )
        
        try:
            with os.fdopen(temp_fd, 'w') as f:
                json.dump(self.session.model_dump(), f, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            
            # Atomic rename: either succeeds completely or fails without touching target
            os.replace(temp_path, save_path)
            
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise
    
    @classmethod
    def load_snapshot(cls, path: str, auto_save: bool = True) -> "StateManager":
        """Load state from disk.
        
        Args:
            path: Path to snapshot file
            auto_save: Enable auto-save on the new instance
            
        Returns:
            StateManager instance with loaded state
        """
        with open(path, 'r') as f:
            data = json.load(f)
        
        # Parse datetime strings back to datetime objects
        session = Session.model_validate(data)
        
        # Create manager with loaded session
        manager = cls.__new__(cls)
        manager.session = session
        manager.auto_save = auto_save
        manager.snapshot_path = Path(path)
        manager._ensure_output_dir()
        
        return manager
    
    # ==================== AI Context Generation ====================
    
    def get_context_for_ai(self, detailed: bool = False) -> str:
        """Generate compact JSON context for AI consumption.
        
        Args:
            detailed: If True, include full details; if False, just summaries
            
        Returns:
            JSON string
        """
        if detailed:
            context = self.session.model_dump()
        else:
            context = self.session.to_summary()
        
        return json.dumps(context, indent=2, default=str)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get high-level summary statistics."""
        return self.session.get_summary()
    
    # ==================== Report Generation ====================
    
    def export_report(self, path: str, format: str = "json") -> None:
        """Export final report atomically.
        
        Uses atomic write pattern: write to temp file, then rename.
        This prevents corruption if the process crashes during write.
        
        Args:
            path: Output file path
            format: Report format (json, html - currently only json supported)
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == "json":
            report = {
                "session": self.session.model_dump(),
                "summary": self.get_summary(),
                "generated_at": datetime.utcnow().isoformat()
            }
            
            # Create temp file in same directory for atomic rename
            temp_fd, temp_path = tempfile.mkstemp(
                dir=output_path.parent,
                prefix=f".tmp_{output_path.name}.",
                suffix=".tmp"
            )
            
            try:
                with os.fdopen(temp_fd, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                    f.flush()
                    os.fsync(f.fileno())
                
                # Atomic rename: either succeeds completely or fails without touching target
                os.replace(temp_path, output_path)
                
            except Exception:
                # Clean up temp file on failure
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
                raise
        else:
            raise ValueError(f"Unsupported format: {format}")


# ==================== Convenience Functions ====================

def create_state_manager(target: str, auto_save: bool = True) -> StateManager:
    """Create a new state manager for a target."""
    return StateManager(target=target, auto_save=auto_save)


def load_state_manager(path: str, auto_save: bool = True) -> StateManager:
    """Load state manager from snapshot."""
    return StateManager.load_snapshot(path, auto_save=auto_save)
