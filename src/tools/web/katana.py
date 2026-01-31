"""
Katana tool wrapper for web crawling and endpoint discovery.

This module provides a Python interface to the katana CLI tool,
parsing JSON Lines output into structured WebEndpoint objects.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from src.core.state_manager import EndpointType, WebEndpoint
from src.tools.base import BaseTool

logger = logging.getLogger(__name__)


class KatanaTool(BaseTool):
    """
    Katana wrapper for web crawling and endpoint discovery.
    
    Crawls websites to discover URLs, forms, API endpoints, and JavaScript files.
    Returns structured endpoint data for further security testing.
    
    Example:
        >>> from src.core.security import ScopeGuard, ScopeConfig
        >>> guard = ScopeGuard(ScopeConfig(["example.com"]))
        >>> tool = KatanaTool(guard)
        >>> result = tool.run("https://example.com", mode="standard")
        >>> print(f"Found {len(result['endpoints'])} endpoints")
        Found 42 endpoints
    """
    
    tool_name = "katana"
    
    def _build_command(self, target: str, **kwargs) -> str:
        """
        Build the katana command.
        
        Args:
            target: Target URL to crawl (e.g., "https://example.com")
            **kwargs: Additional options:
                - mode: Crawl mode ("standard", "deep", "javascript", "sitemap")
                - depth: Maximum crawl depth (default: 3)
                - rate_limit: Requests per second (default: 100)
                
        Returns:
            Command string
        """
        mode = kwargs.get("mode", "standard")
        depth = kwargs.get("depth", 3)
        rate_limit = kwargs.get("rate_limit", 100)
        
        # Base command
        cmd_parts = ["katana", "-u", target]
        
        # Output format: JSON Lines
        cmd_parts.append("-jsonl")
        cmd_parts.append("-silent")
        
        # Crawl depth
        cmd_parts.extend(["-d", str(depth)])
        
        # Rate limiting
        cmd_parts.extend(["-rate-limit", str(rate_limit)])
        
        # Mode-specific options
        if mode == "deep":
            # Deep crawling: higher depth, follow redirects
            cmd_parts.extend(["-d", "5"])
            cmd_parts.append("-follow-redirects")
        elif mode == "javascript":
            # JavaScript parsing mode
            cmd_parts.append("-jc")  # Crawl JavaScript
            cmd_parts.append("-js-crawl")  # Parse JS for endpoints
        elif mode == "sitemap":
            # Generate sitemap
            cmd_parts.append("-sitemap")
        
        # Standard mode optimizations
        if mode in ["standard", "deep"]:
            # Include form extraction
            cmd_parts.append("-form-extraction")
        
        return " ".join(cmd_parts)
    
    def _parse_output(self, output: str, target: str) -> Dict[str, Any]:
        """
        Parse katana JSON Lines output into structured data.
        
        Args:
            output: JSON Lines output from katana
            target: The target URL that was crawled
            
        Returns:
            Dictionary containing:
            - endpoints: List[WebEndpoint]
            - total_count: int
            - sitemap: Optional[str]
        """
        endpoints = []
        sitemap_content = None
        
        if not output or not output.strip():
            logger.info(f"No endpoints found for {target}")
            return {
                "endpoints": endpoints,
                "total_count": 0,
                "sitemap": None
            }
        
        try:
            # Katana outputs JSON Lines format (one JSON object per line)
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Check if this is a sitemap entry
                    if data.get("type") == "sitemap":
                        sitemap_content = data.get("content")
                        continue
                    
                    # Parse regular endpoint
                    endpoint = self._parse_endpoint(data, target)
                    if endpoint:
                        endpoints.append(endpoint)
                        
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse katana line: {line}")
                    continue
                except Exception as e:
                    logger.warning(f"Error processing katana entry: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error parsing katana output: {e}")
        
        # Count by type for logging
        type_counts = {}
        for e in endpoints:
            type_counts[e.endpoint_type.value] = type_counts.get(e.endpoint_type.value, 0) + 1
        
        logger.info(
            f"Katana crawl complete for {target}: "
            f"{len(endpoints)} endpoints found "
            f"({type_counts})"
        )
        
        return {
            "endpoints": endpoints,
            "total_count": len(endpoints),
            "sitemap": sitemap_content
        }
    
    def _parse_endpoint(self, data: dict, base_target: str) -> Optional[WebEndpoint]:
        """
        Parse a single katana entry into a WebEndpoint object.
        
        Args:
            data: JSON object from katana output
            base_target: The target that was crawled
            
        Returns:
            WebEndpoint object or None if parsing fails
        """
        try:
            # Katana uses nested structure: request.endpoint, request.method, response.status_code
            request = data.get("request", {})
            response = data.get("response", {})
            
            url = request.get("endpoint", "").strip()
            if not url:
                return None
            
            # Determine endpoint type
            endpoint_type = self._classify_endpoint(data)
            
            # Extract method
            method = request.get("method", "GET").upper()
            
            # Extract parameters from URL query string
            parameters = []
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                parameters = list(query_params.keys())
            
            # Add form parameters if present (forms are in response.body or separate forms field)
            if "forms" in response and response["forms"]:
                for form in response["forms"]:
                    if "parameters" in form:
                        parameters.extend(form["parameters"])
            
            # Extract status code
            status_code = response.get("status_code")
            if status_code:
                try:
                    status_code = int(status_code)
                except (ValueError, TypeError):
                    status_code = None
            
            # Extract content type from headers
            headers = response.get("headers", {})
            content_type = headers.get("content_type", "")
            
            # Determine source
            source = "crawl"
            if data.get("tag") == "script" or url.endswith(".js"):
                source = "js_analysis"
            
            return WebEndpoint(
                url=url,
                method=method,
                endpoint_type=endpoint_type,
                parameters=parameters,
                status_code=status_code,
                content_type=content_type,
                source=source
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse katana endpoint: {e}")
            return None
    
    def _classify_endpoint(self, data: dict) -> EndpointType:
        """
        Classify the endpoint type based on katana output.
        
        Args:
            data: JSON object from katana output
            
        Returns:
            EndpointType enum value
        """
        request = data.get("request", {})
        response = data.get("response", {})
        
        url = request.get("endpoint", "").lower()
        headers = response.get("headers", {})
        content_type = headers.get("content_type", "").lower()
        
        # Check for forms in response
        if "forms" in response and response["forms"]:
            return EndpointType.FORM
        
        # Check for API indicators
        api_indicators = ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/swagger", "/openapi"]
        if any(indicator in url for indicator in api_indicators):
            return EndpointType.API
        
        if any(ct in content_type for ct in ["application/json", "application/xml"]):
            return EndpointType.API
        
        # Check for JavaScript endpoints
        if data.get("tag") == "script" or url.endswith(".js"):
            return EndpointType.JS_ENDPOINT
        
        # Check for static files
        static_extensions = [".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"]
        if any(url.endswith(ext) for ext in static_extensions):
            return EndpointType.STATIC_FILE
        
        # Check for redirects (3xx status codes)
        status_code = response.get("status_code", 0)
        if 300 <= status_code < 400:
            return EndpointType.REDIRECT
        
        # Default to page
        return EndpointType.PAGE
    
    def _get_empty_result(self, target: str) -> Dict[str, Any]:
        """Return empty result when katana fails."""
        return {
            "endpoints": [],
            "total_count": 0,
            "sitemap": None
        }
    
    def _handle_error(self, error, target: str) -> Dict[str, Any]:
        """
        Handle katana execution errors gracefully.
        
        Katana may return non-zero exit codes for various reasons,
        but still produce valid output. We try to parse any output.
        """
        # Try to parse stdout even if command failed
        if hasattr(error, 'stdout') and error.stdout:
            try:
                return self._parse_output(error.stdout, target)
            except Exception:
                pass
        
        return self._get_empty_result(target)
