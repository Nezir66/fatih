"""
Httpx tool wrapper for HTTP probing and technology detection.

This module provides a Python interface to the httpx CLI tool,
parsing JSON Lines output into structured HTTP service data.

Features:
- Tech Stack Detection (Wappalyzer-style)
- Status Code & Response Analysis
- Virtual Host Discovery

Note: For screenshots, use PlaywrightCrawlerTool instead (better ARM64 support).
"""

import base64
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.tools.base import BaseTool

logger = logging.getLogger(__name__)


class HttpxTool(BaseTool):
    """
    Httpx wrapper for HTTP probing and web technology detection.
    
    Performs HTTP probing on targets to detect:
    - HTTP status codes and response information
    - Technology stack (web frameworks, CMS, etc.)
    - Web server information
    - Virtual hosts
    - Screenshots of web pages
    
    Supports both single URLs and lists of URLs (e.g., from subfinder).
    
    Example:
        >>> from src.core.security import ScopeGuard, ScopeConfig
        >>> guard = ScopeGuard(ScopeConfig(["example.com"]))
        >>> tool = HttpxTool(guard)
        >>> 
        >>> # Single URL probe
        >>> result = tool.run("https://example.com", mode="probe")
        >>> 
        >>> # Multiple URLs from subfinder
        >>> urls = ["https://sub1.example.com", "https://sub2.example.com"]
        >>> result = tool.run(urls, mode="probe")
    """
    
    tool_name = "httpx"
    
    def __init__(self, scope_guard):
        """
        Initialize the httpx tool.
        
        Args:
            scope_guard: ScopeGuard instance for validating targets
        """
        super().__init__(scope_guard)
    
    def _build_command(self, target: Union[str, List[str]], **kwargs) -> str:
        """
        Build the httpx command.
        
        Args:
            target: Single URL (e.g., "https://example.com") or list of URLs
            **kwargs: Additional options:
                - mode: Operation mode ("probe", "vhost")
                - follow_redirects: Follow HTTP redirects (default: True)
                - threads: Number of concurrent threads (default: 50)
                - timeout: HTTP timeout in seconds (default: 10)
                
        Returns:
            Command string ready for execution
        """
        mode = kwargs.get("mode", "probe")
        follow_redirects = kwargs.get("follow_redirects", True)
        threads = kwargs.get("threads", 50)
        timeout = kwargs.get("timeout", 10)
        
        cmd_parts = ["/usr/local/bin/httpx"]
        
        # Handle target input - single URL or list
        if isinstance(target, list):
            # Multiple URLs - use stdin
            # Store URLs for later use in execution
            self._target_urls = target
            target_arg = ""
        else:
            # Single URL
            self._target_urls = [target]
            target_arg = f"-u {target}"
        
        # JSON output for parsing
        cmd_parts.append("-json")
        cmd_parts.append("-silent")
        
        # Standard probing options (always included)
        cmd_parts.append("-status-code")
        cmd_parts.append("-title")
        cmd_parts.append("-web-server")
        cmd_parts.append("-content-length")
        cmd_parts.append("-tech-detect")
        
        # Mode-specific options
        if mode == "vhost":
            # Virtual host discovery mode
            cmd_parts.append("-vhost")
            logger.debug("Vhost discovery mode enabled")
        
        # Follow redirects (default True)
        if follow_redirects:
            cmd_parts.append("-follow-redirects")
        
        # Performance settings
        cmd_parts.extend(["-threads", str(threads)])
        cmd_parts.extend(["-timeout", str(timeout)])
        
        # Add target argument if not using stdin
        if target_arg:
            cmd_parts.append(target_arg)
        
        return " ".join(cmd_parts)
    
    def run(self, target: Union[str, List[str]], **kwargs) -> Any:
        """
        Execute httpx against target(s).
        
        Overrides base run() to handle list inputs and stdin piping.
        
        Args:
            target: Single URL or list of URLs to probe
            **kwargs: Tool-specific parameters (mode, threads, etc.)
            
        Returns:
            Parsed results as dictionary
        """
        # Validate all targets if list provided
        if isinstance(target, list):
            for t in target:
                if not self.scope_guard.is_in_scope(t):
                    from src.core.exceptions import TargetOutOfScopeError
                    raise TargetOutOfScopeError(
                        f"Target '{t}' is not in authorized scope. "
                        f"Operation blocked for security."
                    )
        else:
            # Validate single target
            if not self.scope_guard.is_in_scope(target):
                from src.core.exceptions import TargetOutOfScopeError
                raise TargetOutOfScopeError(
                    f"Target '{target}' is not in authorized scope. "
                    f"Operation blocked for security."
                )
        
        # Build command
        command = self._build_command(target, **kwargs)
        
        # Execute with stdin if needed
        import subprocess
        
        try:
            docker_command = f"docker exec fatih-agent {command}"
            
            # Prepare stdin data if we have multiple URLs
            stdin_data = None
            if isinstance(target, list):
                stdin_data = "\\n".join(target)
            
            result = subprocess.run(
                docker_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
                input=stdin_data
            )
            
            output = result.stdout
            
            # Check for errors
            if result.returncode != 0:
                if result.stderr:
                    logger.debug(f"{self.tool_name} stderr: {result.stderr}")
                # Try to parse stdout even if command failed
                if result.stdout:
                    try:
                        return self._parse_output(result.stdout, target)
                    except Exception:
                        pass
                # Convert target to string identifier for empty result
                target_id = target[0] if isinstance(target, list) else target
                return self._get_empty_result(target_id)
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Httpx scan timed out for {target}")
            target_id = target[0] if isinstance(target, list) else target
            return self._get_empty_result(target_id)
        except Exception as e:
            from src.core.exceptions import ToolExecutionError
            raise ToolExecutionError(
                f"Failed to execute {self.tool_name}: {str(e)}"
            ) from e
        
        # Parse the output
        return self._parse_output(output, target)
    
    def _parse_output(self, output: str, target: Union[str, List[str]]) -> Dict[str, Any]:
        """
        Parse httpx JSON Lines output into structured data.
        
        Args:
            output: JSON Lines output from httpx
            target: The target(s) that were probed
            
        Returns:
            Dictionary containing:
            - services: List of parsed HTTP service data
            - total_count: int
            - vhosts: List of discovered virtual hosts
        """
        services = []
        all_vhosts = []
        
        if not output or not output.strip():
            logger.info(f"No HTTP probing results for {target}")
            return {
                "services": services,
                "total_count": 0,
                "vhosts": all_vhosts
            }
        
        try:
            # Httpx outputs JSON Lines format
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    service = self._parse_service(data)
                    if service:
                        services.append(service)
                        
                        # Collect vhosts if present
                        if data.get("vhost"):
                            vhost = data["vhost"]
                            if vhost not in all_vhosts:
                                all_vhosts.append(vhost)
                        
                        logger.debug(f"Parsed HTTP service: {service.get('url')} - "
                                   f"status={service.get('status_code')}")
                        
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse httpx line: {line}")
                    continue
                except Exception as e:
                    logger.warning(f"Error processing httpx entry: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error parsing httpx output: {e}")
        
        # Log summary
        logger.info(
            f"HTTP probing complete: {len(services)} services scanned, "
            f"{len(all_vhosts)} vhosts discovered"
        )
        
        return {
            "services": services,
            "total_count": len(services),
            "vhosts": all_vhosts
        }
    
    def _parse_service(self, data: dict) -> Optional[Dict[str, Any]]:
        """
        Parse a single httpx JSON entry into service data.
        
        Args:
            data: JSON object from httpx output
            
        Returns:
            Dictionary with service information or None if parsing fails
        """
        try:
            url = data.get("url", "").strip()
            if not url:
                return None
            
            # Extract technology stack (Wappalyzer-style detection)
            tech_stack = []
            if "tech" in data:
                tech_data = data["tech"]
                if isinstance(tech_data, list):
                    tech_stack = tech_data
                elif isinstance(tech_data, dict):
                    # Handle different httpx versions
                    tech_stack = list(tech_data.keys()) if tech_data else []
            
            # Alternative tech detection fields
            if not tech_stack and "technologies" in data:
                tech = data["technologies"]
                if isinstance(tech, list):
                    tech_stack = tech
            
            service = {
                "url": url,
                "status_code": data.get("status_code"),
                "title": data.get("title", ""),
                "web_server": data.get("webserver", ""),
                "content_length": data.get("content_length"),
                "content_type": data.get("content_type", ""),
                "tech_stack": tech_stack,
                "host": data.get("host", ""),
                "port": data.get("port"),
                "scheme": data.get("scheme", ""),
                "method": data.get("method", "GET"),
                "response_time": data.get("response_time", ""),
                "chain": data.get("chain", []),  # Redirect chain
                "final_url": data.get("final_url", url),
            }
            
            # Add vhost if present
            if "vhost" in data:
                service["vhost"] = data["vhost"]
            
            return service
            
        except Exception as e:
            logger.warning(f"Failed to parse httpx service entry: {e}")
            return None
    
    def _get_empty_result(self, target: str) -> Dict[str, Any]:
        """
        Return empty result structure.
        
        Args:
            target: The target that was being probed
            
        Returns:
            Empty result dictionary
        """
        return {
            "services": [],
            "total_count": 0,
            "vhosts": []
        }
