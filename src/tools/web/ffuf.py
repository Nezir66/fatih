"""
Ffuf tool wrapper for directory and file brute forcing.

This module provides a Python interface to the ffuf CLI tool,
enabling directory enumeration, file discovery, and fuzzing with
various wordlists and filtering options.
"""

import json
import logging
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from src.core.state_manager import EndpointType, WebEndpoint
from src.tools.base import BaseTool

logger = logging.getLogger(__name__)


# Default wordlist paths (installed via SecLists in Docker)
WORDLISTS = {
    "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "raft-small-directories": "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "raft-medium-directories": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "raft-large-directories": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "raft-small-files": "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
    "raft-medium-files": "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
    "directory-list-2.3-small": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "directory-list-2.3-medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "api-endpoints": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "backup-files": "/usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt",
}

# File extensions for fuzzing
EXTENSION_SETS = {
    "common": ".php,.html,.js,.txt,.xml,.json",
    "backup": ".bak,.old,.orig,.backup,.swp,.tmp,.zip,.tar,.gz,.7z,.rar",
    "config": ".conf,.cfg,.ini,.env,.yaml,.yml,.properties",
    "source": ".php,.asp,.aspx,.jsp,.py,.rb,.java,.cs",
    "all": ".php,.html,.js,.txt,.xml,.json,.bak,.old,.zip,.tar,.gz,.conf,.env",
}


class FfufTool(BaseTool):
    """
    Ffuf wrapper for directory and file brute forcing.
    
    Performs directory enumeration and file discovery using wordlists.
    Returns structured endpoint data for further security testing.
    
    Example:
        >>> from src.core.security import ScopeGuard, ScopeConfig
        >>> guard = ScopeGuard(ScopeConfig(["example.com"]))
        >>> tool = FfufTool(guard)
        >>> result = tool.run("https://example.com", wordlist="common")
        >>> print(f"Found {len(result['endpoints'])} directories/files")
        Found 23 directories/files
    """
    
    tool_name = "ffuf"
    
    def _build_command(self, target: str, **kwargs) -> str:
        """
        Build the ffuf command.
        
        Args:
            target: Target URL with FUZZ placeholder or base URL
            **kwargs: Additional options:
                - wordlist: Wordlist name or custom path (default: "common")
                - extensions: Extension set name or custom list (default: None)
                - filter_codes: Status codes to filter out (e.g., "404,403")
                - match_codes: Status codes to match (e.g., "200,301,302")
                - threads: Number of concurrent threads (default: 50)
                - recursion: Enable recursive scanning (default: False)
                - recursion_depth: Max recursion depth (default: 2)
                - timeout: Request timeout in seconds (default: 10)
                - auto_calibrate: Use auto-calibration to filter false positives (default: False)
                  Note: auto-calibration can be too aggressive on some servers
                
        Returns:
            Command string
        """
        wordlist = kwargs.get("wordlist", "common")
        extensions = kwargs.get("extensions")
        filter_codes = kwargs.get("filter_codes", "404")
        match_codes = kwargs.get("match_codes")
        threads = kwargs.get("threads", 50)
        recursion = kwargs.get("recursion", False)
        recursion_depth = kwargs.get("recursion_depth", 2)
        timeout = kwargs.get("timeout", 10)
        auto_calibrate = kwargs.get("auto_calibrate", False)  # Disabled by default - too aggressive
        
        # Resolve wordlist path
        if wordlist in WORDLISTS:
            wordlist_path = WORDLISTS[wordlist]
        else:
            # Assume custom path
            wordlist_path = wordlist
        
        # Build target URL with FUZZ placeholder if not present
        if "FUZZ" not in target:
            # Add FUZZ to the URL path
            if not target.endswith("/"):
                target = target + "/"
            target = target + "FUZZ"
        
        # Base command
        cmd_parts = [
            "ffuf",
            "-u", target,
            "-w", wordlist_path,
        ]
        
        # Generate unique output file to prevent race conditions in parallel scans
        output_file = f"/tmp/ffuf_output_{uuid.uuid4().hex}.json"
        
        # Output format: JSON
        cmd_parts.extend(["-of", "json", "-o", output_file])
        
        # Silent mode (less noise)
        cmd_parts.append("-s")
        
        # Thread configuration
        cmd_parts.extend(["-t", str(threads)])
        
        # Timeout
        cmd_parts.extend(["-timeout", str(timeout)])
        
        # Extensions (file fuzzing)
        if extensions:
            if extensions in EXTENSION_SETS:
                ext_list = EXTENSION_SETS[extensions]
            else:
                ext_list = extensions
            cmd_parts.extend(["-e", ext_list])
        
        # Status code filtering
        if filter_codes:
            cmd_parts.extend(["-fc", str(filter_codes)])
        
        if match_codes:
            cmd_parts.extend(["-mc", str(match_codes)])
        
        # Recursion
        if recursion:
            cmd_parts.append("-recursion")
            cmd_parts.extend(["-recursion-depth", str(recursion_depth)])
        
        # Auto-calibration to filter false positives (optional - can be too aggressive)
        if auto_calibrate:
            cmd_parts.append("-ac")
        
        # Build the ffuf command
        ffuf_cmd = " ".join(cmd_parts)
        
        # Wrap in bash -c to properly handle && chain in docker exec
        # We run ffuf, cat the output, then remove the temp file
        full_cmd = f"bash -c '{ffuf_cmd} && cat {output_file} && rm -f {output_file}'"
        
        return full_cmd
    
    def _parse_output(self, output: str, target: str) -> Dict[str, Any]:
        """
        Parse ffuf JSON output into structured data.
        
        Args:
            output: JSON output from ffuf
            target: The target URL that was fuzzed
            
        Returns:
            Dictionary containing:
            - endpoints: List[WebEndpoint]
            - total_count: int
            - statistics: Dict with scan stats
        """
        endpoints = []
        statistics = {
            "total_requests": 0,
            "found": 0,
            "filtered": 0,
            "errors": 0,
        }
        
        if not output or not output.strip():
            logger.info(f"No results found for {target}")
            return {
                "endpoints": endpoints,
                "total_count": 0,
                "statistics": statistics
            }
        
        try:
            # ffuf outputs results to stdout even in silent mode, then cat outputs JSON
            # We need to find the JSON portion (starts with '{')
            json_start = output.find('{')
            if json_start == -1:
                logger.warning("No JSON found in ffuf output")
                return {
                    "endpoints": endpoints,
                    "total_count": 0,
                    "statistics": statistics
                }
            
            json_output = output[json_start:]
            
            # Parse JSON output
            data = json.loads(json_output)
            
            # Extract results
            results = data.get("results", [])
            
            # Parse statistics if available
            if "commandline" in data:
                logger.debug(f"ffuf command: {data['commandline']}")
            
            # Process each result
            for result in results:
                endpoint = self._parse_result(result, target)
                if endpoint:
                    endpoints.append(endpoint)
            
            statistics["found"] = len(endpoints)
            
            # Extract time and requests from config if available
            config = data.get("config", {})
            if config:
                statistics["total_requests"] = config.get("requestcount", 0)
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse ffuf JSON output: {e}")
            # Try to extract results from raw output if JSON fails
            endpoints = self._parse_fallback(output, target)
            statistics["found"] = len(endpoints)
        except Exception as e:
            logger.error(f"Error parsing ffuf output: {e}")
        
        # Categorize findings
        directories = [e for e in endpoints if e.url.endswith("/")]
        files = [e for e in endpoints if not e.url.endswith("/")]
        
        logger.info(
            f"Ffuf scan complete for {target}: "
            f"{len(endpoints)} results found "
            f"({len(directories)} directories, {len(files)} files)"
        )
        
        return {
            "endpoints": endpoints,
            "total_count": len(endpoints),
            "directories": len(directories),
            "files": len(files),
            "statistics": statistics
        }
    
    def _parse_result(self, result: dict, base_target: str) -> Optional[WebEndpoint]:
        """
        Parse a single ffuf result into a WebEndpoint object.
        
        Args:
            result: JSON object from ffuf results
            base_target: The target that was fuzzed
            
        Returns:
            WebEndpoint object or None if parsing fails
        """
        try:
            # Extract basic info
            input_value = result.get("input", {})
            fuzz_value = input_value.get("FUZZ", "")
            
            # Construct full URL
            url = result.get("url", "")
            if not url and fuzz_value:
                # Reconstruct from base target
                base_url = base_target.replace("FUZZ", "")
                url = urljoin(base_url, fuzz_value)
            
            if not url:
                return None
            
            # Extract response info
            status_code = result.get("status", 200)
            content_length = result.get("length", 0)
            content_type = result.get("content-type", "")
            
            # Determine endpoint type based on response
            endpoint_type = self._classify_result(url, status_code, content_type)
            
            return WebEndpoint(
                url=url,
                method="GET",
                endpoint_type=endpoint_type,
                parameters=[],
                status_code=status_code,
                content_type=content_type,
                source="ffuf"
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse ffuf result: {e}")
            return None
    
    def _classify_result(self, url: str, status_code: int, content_type: str) -> EndpointType:
        """
        Classify the endpoint type based on ffuf result.
        
        Args:
            url: Discovered URL
            status_code: HTTP status code
            content_type: Content-Type header
            
        Returns:
            EndpointType enum value
        """
        url_lower = url.lower()
        content_type_lower = content_type.lower()
        
        # Check for API indicators
        api_indicators = ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/swagger", "/openapi"]
        if any(indicator in url_lower for indicator in api_indicators):
            return EndpointType.API
        
        if "application/json" in content_type_lower:
            return EndpointType.API
        
        # Check for JavaScript files
        if url_lower.endswith(".js"):
            return EndpointType.JS_ENDPOINT
        
        # Check for static files
        static_extensions = [".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", 
                           ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".doc", ".docx"]
        if any(url_lower.endswith(ext) for ext in static_extensions):
            return EndpointType.STATIC_FILE
        
        # Check for redirects
        if 300 <= status_code < 400:
            return EndpointType.REDIRECT
        
        # Check for directories (end with /)
        if url_lower.endswith("/"):
            return EndpointType.PAGE
        
        # Default to page
        return EndpointType.PAGE
    
    def _parse_fallback(self, output: str, target: str) -> List[WebEndpoint]:
        """
        Fallback parser for non-JSON output.
        
        Args:
            output: Raw output from ffuf
            target: The target URL
            
        Returns:
            List of WebEndpoint objects
        """
        endpoints = []
        
        # Try to extract URLs from the output
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Simple extraction: look for URLs
            if line.startswith("http"):
                endpoints.append(WebEndpoint(
                    url=line,
                    method="GET",
                    endpoint_type=EndpointType.PAGE,
                    parameters=[],
                    source="ffuf"
                ))
        
        return endpoints
    
    def _get_empty_result(self, target: str) -> Dict[str, Any]:
        """Return empty result when ffuf fails."""
        return {
            "endpoints": [],
            "total_count": 0,
            "directories": 0,
            "files": 0,
            "statistics": {
                "total_requests": 0,
                "found": 0,
                "filtered": 0,
                "errors": 0,
            }
        }
    
    def _handle_error(self, error, target: str) -> Dict[str, Any]:
        """
        Handle ffuf execution errors gracefully.
        
        Ffuf may return non-zero exit codes for various reasons,
        but still produce valid output. We try to parse any output.
        """
        # Try to parse stdout even if command failed
        if hasattr(error, 'stdout') and error.stdout:
            try:
                return self._parse_output(error.stdout, target)
            except Exception:
                pass
        
        return self._get_empty_result(target)
