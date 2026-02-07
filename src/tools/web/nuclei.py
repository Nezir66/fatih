"""
Nuclei tool wrapper for vulnerability scanning.

This module provides a Python interface to the nuclei CLI tool,
parsing JSON Lines output into structured Vulnerability objects.
"""

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

from src.core.state_manager import Severity, Vulnerability
from src.tools.base import BaseTool

logger = logging.getLogger(__name__)

# Predefined template categories for targeted scanning (using template directories)
TEMPLATE_CATEGORIES = {
    "quick": "http/exposures/,http/misconfiguration/",  # Fast scan for common issues (~800 templates)
    "full": "",  # All templates (slow but comprehensive)
    "cves": "http/cves/",  # CVE checks
    "exposures": "http/exposures/",  # Information disclosure
    "misconfig": "http/misconfiguration/",  # Misconfigurations
    "vulns": "http/vulnerabilities/",  # Vulnerability templates
    "default-logins": "http/default-logins/",  # Default credentials
    "fuzzing": "http/fuzzing/",  # Fuzzing templates (SQL injection, XSS, etc.)
    "panels": "http/exposed-panels/",  # Exposed admin panels
    "tech": "http/technologies/",  # Technology detection
}


class NucleiTool(BaseTool):
    """
    Nuclei wrapper for vulnerability detection.
    
    Scans targets for known vulnerabilities using nuclei templates
    and returns findings as Vulnerability objects.
    
    Example:
        >>> from src.core.security import ScopeGuard, ScopeConfig
        >>> guard = ScopeGuard(ScopeConfig(["example.com"]))
        >>> tool = NucleiTool(guard)
        >>> vulns = tool.run("https://example.com")
        >>> for v in vulns:
        ...     print(f"{v.severity}: {v.title}")
        high: CVE-2021-44228 Log4j RCE
    """
    
    tool_name = "nuclei"
    
    def _build_command(self, target: str, **kwargs) -> str:
        """
        Build the nuclei command.
        
        Args:
            target: Target URL to scan
            **kwargs: Additional options:
                - templates: Specific template directory or file
                - severity: Filter by severity (e.g., "high,critical")
                - category: Predefined category (quick, full, web, sqli, xss, lfi, rce)
                - rate_limit: Requests per second (default: 150)
                - timeout: HTTP timeout per request in seconds (default: 10)
                - retries: Number of retries for failed requests (default: 1)
                
        Returns:
            Command string
        """
        templates = kwargs.get("templates", "")
        severity = kwargs.get("severity", "")
        category = kwargs.get("category", "quick")  # Default to quick scan
        rate_limit = kwargs.get("rate_limit", 150)
        timeout = kwargs.get("timeout", 10)
        retries = kwargs.get("retries", 1)
        
        # Build base command parts
        cmd_parts = ["nuclei", "-u", target]
        
        # Template selection
        if templates:
            cmd_parts.extend(["-t", templates])
        elif category in TEMPLATE_CATEGORIES and TEMPLATE_CATEGORIES[category]:
            # Use predefined category template directories
            cmd_parts.extend(["-t", TEMPLATE_CATEGORIES[category]])
        # If category is "full" or not found, don't add -t or -tags (runs all)
        
        # Severity filtering
        if severity:
            cmd_parts.extend(["-severity", severity])
        
        # Rate limiting to avoid overwhelming target
        cmd_parts.extend(["-rate-limit", str(rate_limit)])
        
        # HTTP timeout
        cmd_parts.extend(["-timeout", str(timeout)])
        
        # Retries
        cmd_parts.extend(["-retries", str(retries)])
        
        # Output format
        cmd_parts.extend(["-jsonl", "-silent"])
        
        return " ".join(cmd_parts)
    
    def _parse_output(self, output: str, target: str) -> List[Vulnerability]:
        """
        Parse nuclei JSON Lines output into Vulnerability objects.
        
        Args:
            output: JSON Lines output from nuclei
            target: The target URL that was scanned
            
        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []
        
        if not output or not output.strip():
            logger.info(f"No vulnerabilities found for {target}")
            return vulnerabilities
        
        try:
            # Nuclei outputs JSON Lines format (one JSON object per line)
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    vuln = self._parse_finding(data, target)
                    if vuln:
                        vulnerabilities.append(vuln)
                        logger.debug(f"Found vulnerability: {vuln.vuln_id} - {vuln.title}")
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse nuclei line: {line}")
                    continue
                except Exception as e:
                    logger.warning(f"Error processing nuclei finding: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error parsing nuclei output: {e}")
        
        # Count by severity for logging
        severity_counts = {}
        for v in vulnerabilities:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
        
        logger.info(
            f"Nuclei scan complete for {target}: "
            f"{len(vulnerabilities)} vulnerabilities found "
            f"({severity_counts})"
        )
        
        return vulnerabilities
    
    def _parse_finding(self, data: dict, target: str) -> Optional[Vulnerability]:
        """
        Parse a single nuclei finding into a Vulnerability object.
        
        Args:
            data: JSON object from nuclei output
            target: The target that was scanned
            
        Returns:
            Vulnerability object or None if parsing fails
        """
        try:
            # Extract template ID
            template_id = data.get("template-id", "unknown")
            
            # Extract info
            info = data.get("info", {})
            title = info.get("name", "Unknown Vulnerability")
            severity_str = info.get("severity", "info").lower()
            description = info.get("description", "")
            
            # Map severity string to enum
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.INFO
            
            # Extract location (matched-at field)
            location = data.get("matched-at", target)
            
            # Extract evidence (curl-command or extracted-results)
            evidence_parts = []
            
            if "curl-command" in data:
                evidence_parts.append(f"Curl: {data['curl-command']}")
            
            if "extracted-results" in data:
                results = data["extracted-results"]
                if isinstance(results, list):
                    evidence_parts.append(f"Extracted: {', '.join(results)}")
                else:
                    evidence_parts.append(f"Extracted: {results}")
            
            if "request" in data:
                evidence_parts.append(f"Request: {data['request']}")
            
            if "response" in data:
                evidence_parts.append(f"Response: {data['response']}")
            
            evidence = "\n".join(evidence_parts) if evidence_parts else None
            
            # Generate fingerprint for deduplication
            fingerprint = self._generate_fingerprint(target, template_id, location)
            
            return Vulnerability(
                fingerprint=fingerprint,
                vuln_id=template_id,
                title=title,
                severity=severity,
                description=description,
                location=location,
                evidence=evidence,
                tool="nuclei"
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse nuclei finding: {e}")
            return None
    
    def _generate_fingerprint(self, target: str, vuln_id: str, location: str) -> str:
        """Generate unique fingerprint for vulnerability deduplication."""
        raw = f"{target}|{vuln_id}|{location}"
        return hashlib.sha256(raw.encode()).hexdigest()
    
    def _get_empty_result(self, target: str) -> List[Vulnerability]:
        """Return empty list when nuclei fails."""
        return []
