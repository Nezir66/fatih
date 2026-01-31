"""
Nmap tool wrapper for port scanning and service detection.

This module provides a Python interface to the nmap CLI tool,
parsing XML output into structured Host and Port objects.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Optional

from src.core.state_manager import Host, Port, PortState, Service
from src.tools.base import BaseTool
from src.utils.validators import is_ip_address

logger = logging.getLogger(__name__)


class NmapTool(BaseTool):
    """
    Nmap wrapper for network port scanning.
    
    Performs service detection and returns a Host object with
    populated ports list containing service information.
    
    Example:
        >>> from src.core.security import ScopeGuard, ScopeConfig
        >>> guard = ScopeGuard(ScopeConfig(["example.com"]))
        >>> tool = NmapTool(guard)
        >>> host = tool.run("example.com")
        >>> print(f"Open ports: {len(host.get_open_ports())}")
        Open ports: 3
    """
    
    tool_name = "nmap"
    
    def _build_command(self, target: str, **kwargs) -> str:
        """
        Build the nmap command.
        
        Args:
            target: Target to scan (domain or IP)
            **kwargs: Additional options:
                - ports: Specific ports to scan (e.g., "80,443" or "1-1000")
                
        Returns:
            Command string
        """
        ports = kwargs.get("ports", "")
        port_arg = f"-p {ports}" if ports else ""
        
        # -sV: Version detection
        # -T4: Aggressive timing template
        # -oX -: XML output to stdout
        return f"nmap -sV -T4 {port_arg} -oX - {target}".strip()
    
    def _parse_output(self, output: str, target: str) -> Host:
        """
        Parse nmap XML output into a Host object.
        
        Args:
            output: XML output from nmap
            target: The target that was scanned
            
        Returns:
            Host object with populated ports list
        """
        host = Host(domain=target if not self._is_ip(target) else None,
                    ip=target if self._is_ip(target) else None)
        
        if not output or not output.strip():
            logger.warning(f"Empty nmap output for {target}")
            return host
        
        try:
            root = ET.fromstring(output)
            
            # Find host element
            host_elem = root.find("host")
            if host_elem is None:
                logger.warning(f"No host element found in nmap output for {target}")
                return host
            
            # Extract IP address
            address_elem = host_elem.find("address")
            if address_elem is not None:
                addr_type = address_elem.get("addrtype", "")
                if addr_type == "ipv4":
                    host.ip = address_elem.get("addr", host.ip)
            
            # Extract OS info if available
            os_elem = host_elem.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    host.os_info = osmatch.get("name")
            
            # Extract ports
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port = self._parse_port(port_elem)
                    if port:
                        host.add_port(port)
            
            logger.info(
                f"Nmap scan complete for {target}: "
                f"{len(host.get_open_ports())} open ports found"
            )
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML output: {e}")
        except Exception as e:
            logger.error(f"Error processing nmap output: {e}")
        
        return host
    
    def _parse_port(self, port_elem: ET.Element) -> Optional[Port]:
        """
        Parse a single port element from nmap XML.
        
        Args:
            port_elem: XML element representing a port
            
        Returns:
            Port object or None if parsing fails
        """
        try:
            port_id = port_elem.get("portid", "")
            protocol = port_elem.get("protocol", "tcp")
            
            if not port_id or not port_id.isdigit():
                return None
            
            port_num = int(port_id)
            
            # Get port state
            state_elem = port_elem.find("state")
            state = PortState.CLOSED
            if state_elem is not None:
                state_str = state_elem.get("state", "closed").lower()
                try:
                    state = PortState(state_str)
                except ValueError:
                    # Handle nmap-specific states like "open|filtered"
                    if "open" in state_str:
                        state = PortState.OPEN
                    elif "filtered" in state_str:
                        state = PortState.FILTERED
            
            # Get service info
            service = None
            service_elem = port_elem.find("service")
            if service_elem is not None:
                service = Service(
                    name=service_elem.get("name"),
                    product=service_elem.get("product"),
                    version=service_elem.get("version"),
                    banner=service_elem.get("extrainfo"),
                    cpe=service_elem.get("cpe")
                )
            
            return Port(
                number=port_num,
                protocol=protocol,
                state=state,
                service=service
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse port element: {e}")
            return None
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        return is_ip_address(target)
    
    def _get_empty_result(self, target: str) -> Host:
        """Return empty Host object when nmap fails."""
        return Host(domain=target if not self._is_ip(target) else None,
                    ip=target if self._is_ip(target) else None)
