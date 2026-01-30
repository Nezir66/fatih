"""
Subfinder tool wrapper for subdomain discovery.

This module provides a Python interface to the subfinder CLI tool,
returning discovered subdomains as structured Host objects.
"""

import json
import logging
from typing import List

from src.core.state_manager import Host
from src.tools.base import BaseTool

logger = logging.getLogger(__name__)


class SubfinderTool(BaseTool):
    """
    Subfinder wrapper for subdomain enumeration.
    
    Discovers subdomains using passive sources and returns them as
    a list of Host objects ready for further scanning.
    
    Example:
        >>> from src.core.security import ScopeGuard, ScopeConfig
        >>> guard = ScopeGuard(ScopeConfig(["example.com"]))
        >>> tool = SubfinderTool(guard)
        >>> hosts = tool.run("example.com")
        >>> print([h.domain for h in hosts])
        ['www.example.com', 'api.example.com', 'mail.example.com']
    """
    
    tool_name = "subfinder"
    
    def _build_command(self, target: str, **kwargs) -> str:
        """
        Build the subfinder command.
        
        Args:
            target: Domain to enumerate (e.g., "example.com")
            **kwargs: Additional options (not used)
            
        Returns:
            Command string
        """
        # Extract domain from URL if needed
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        return f"subfinder -d {domain} -json -silent"
    
    def _parse_output(self, output: str, target: str) -> List[Host]:
        """
        Parse subfinder JSON output into Host objects.
        
        Args:
            output: JSON lines output from subfinder
            target: The original target domain
            
        Returns:
            List of Host objects, one per discovered subdomain
        """
        hosts = []
        
        if not output or not output.strip():
            logger.info(f"No subdomains found for {target}")
            return hosts
        
        try:
            # Subfinder outputs JSON Lines format (one JSON object per line)
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    subdomain = data.get("host", "").strip()
                    
                    if subdomain:
                        host = Host(domain=subdomain)
                        hosts.append(host)
                        logger.debug(f"Discovered subdomain: {subdomain}")
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse subfinder line: {line}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error parsing subfinder output: {e}")
        
        logger.info(f"Discovered {len(hosts)} subdomains for {target}")
        return hosts
    
    def _get_empty_result(self, target: str) -> List[Host]:
        """Return empty list when subfinder fails."""
        return []
