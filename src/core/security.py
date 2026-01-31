"""
Scope Guard - Security boundary enforcement for the Fatih penetration testing agent.

This module ensures all security operations stay within authorized boundaries.
It acts as a safety barrier before any tool execution, preventing the AI from
accidentally scanning unauthorized targets through hallucinations or malformed input.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Set, Union
from dataclasses import dataclass

from src.utils.validators import is_ip_address


@dataclass
class ScopeConfig:
    """Configuration for scope enforcement."""
    allowed_targets: List[str]
    allow_localhost: bool = False
    allow_private_ips: bool = False


class ScopeGuard:
    """
    Security filter that validates targets before tool execution.
    
    The Scope Guard ensures:
    1. Only whitelisted domains/IPs are scanned
    2. Subdomains of allowed domains are automatically permitted
    3. Malformed URLs are normalized before validation
    4. Localhost and private IPs are blocked by default (safety brake)
    """
    
    # Localhost patterns that should never be scanned (unless explicitly allowed)
    LOCALHOST_PATTERNS = {
        'localhost', '127.0.0.1', '::1', '0.0.0.0',
        '127.0.0.0', '127.255.255.255', '127.0.0.0/8'
    }
    
    def __init__(self, config: ScopeConfig):
        """
        Initialize the Scope Guard with allowed targets.
        
        Args:
            config: ScopeConfig containing allowed targets and security settings
        """
        self.config = config
        self._normalized_allowlist = self._normalize_allowlist(config.allowed_targets)
    
    def _normalize_allowlist(self, targets: List[str]) -> Set[str]:
        """
        Normalize the allowlist for efficient lookup.
        
        Automatically adds both www and non-www variants for domains,
        and extracts root domains to allow all subdomains.
        
        Args:
            targets: List of allowed domains/IPs
            
        Returns:
            Set of normalized target strings including www variants and root domains
        """
        normalized = set()
        for target in targets:
            # Check if it's a CIDR range (IP with /) - preserve these as-is
            if '/' in target:
                normalized.add(target.lower())
                continue
            
            cleaned = self._extract_hostname(target)
            if cleaned:
                cleaned = cleaned.lower()
                normalized.add(cleaned)
                
                # For domains (not IPs), add www variant and root domain
                if not self._is_ip(cleaned):
                    # Add www variant if not present
                    if cleaned.startswith('www.'):
                        # www.example.com -> example.com (root domain)
                        root_domain = cleaned[4:]
                        normalized.add(root_domain)
                    else:
                        # example.com -> www.example.com
                        www_variant = f'www.{cleaned}'
                        normalized.add(www_variant)
                    
                    # Also extract and add root domain for any subdomain
                    # api.sub.example.com -> sub.example.com -> example.com
                    parts = cleaned.split('.')
                    if len(parts) > 2:
                        # Could be a subdomain like api.example.com or api.sub.example.com
                        # Add the root domain (last 2 parts)
                        root_domain = '.'.join(parts[-2:])
                        normalized.add(root_domain)
                        # And www variant of root
                        www_root = f'www.{root_domain}'
                        normalized.add(www_root)
        
        return normalized
    
    def _extract_hostname(self, target: str) -> str:
        """
        Extract clean hostname from various input formats.
        
        Handles:
        - Full URLs: https://www.target.com/login?id=1 → www.target.com
        - IPs with ports: 192.168.1.5:8080 → 192.168.1.5
        - IPv6 addresses: [::1]:8080 → [::1], ::1 → ::1
        - Domains with paths: target.com/api/v1 → target.com
        
        Args:
            target: Raw target string (URL, domain, or IP)
            
        Returns:
            Clean hostname or IP address
        """
        if not target or not isinstance(target, str):
            return ""
        
        target = target.strip()
        
        # Handle URLs with protocol
        if '://' in target:
            try:
                parsed = urlparse(target)
                hostname = parsed.hostname
                if hostname:
                    return hostname.lower()
            except Exception:
                pass
        
        # Handle IPv6 addresses with brackets and ports: [::1]:8080
        if target.startswith('['):
            # IPv6 with brackets
            if ']:' in target:
                target = target.split(']:')[0] + ']'
            # Just remove the brackets for normalization [::1] → ::1
            target = target[1:-1] if target.endswith(']') else target[1:]
            return target.lower()
        
        # Handle IPv6 addresses without brackets: ::1, 2001:db8::1
        # IPv6 addresses contain multiple colons
        if target.count(':') > 1 and not target.endswith(':'):
            # This looks like an IPv6 address, return as-is
            # (could be ::1, 2001:db8::1, etc.)
            try:
                ipaddress.ip_address(target)
                return target.lower()
            except ValueError:
                pass
        
        # Remove port numbers for IPv4 and domains (e.g., target.com:8080, 192.168.1.5:8080)
        if ':' in target:
            # Single colon - likely IPv4:port or domain:port
            parts = target.rsplit(':', 1)
            if len(parts) == 2:
                # Check if second part is a port number
                if parts[1].isdigit():
                    target = parts[0]
        
        # Remove paths (anything after /)
        if '/' in target:
            target = target.split('/')[0]
        
        # Remove query parameters (anything after ?)
        if '?' in target:
            target = target.split('?')[0]
        
        # Remove fragment (anything after #)
        if '#' in target:
            target = target.split('#')[0]
        
        # Remove trailing dots
        target = target.rstrip('.')
        
        return target.lower() if target else ""
    
    def _is_localhost(self, target: str) -> bool:
        """
        Check if target is localhost or loopback address.
        
        Args:
            target: Normalized target string
            
        Returns:
            True if target is localhost/loopback
        """
        target_lower = target.lower()
        
        # Check explicit localhost patterns
        if target_lower in self.LOCALHOST_PATTERNS:
            return True
        
        # Check for localhost variations
        if 'localhost' in target_lower:
            return True
        
        # Check for loopback IP ranges
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_loopback:
                return True
        except ValueError:
            pass
        
        return False
    
    def _is_private_ip(self, target: str) -> bool:
        """
        Check if target is a private/internal IP address.
        
        Args:
            target: Normalized target string
            
        Returns:
            True if target is a private IP
        """
        try:
            ip = ipaddress.ip_address(target)
            return ip.is_private
        except ValueError:
            return False
    
    def _is_subdomain(self, target: str, allowed_domain: str) -> bool:
        """
        Check if target is a subdomain of allowed_domain.
        
        Examples:
        - api.target.com is subdomain of target.com ✓
        - target.com.evil.com is NOT subdomain of target.com ✗
        
        Args:
            target: The target to check
            allowed_domain: The allowed parent domain
            
        Returns:
            True if target is a valid subdomain
        """
        target = target.lower().rstrip('.')
        allowed_domain = allowed_domain.lower().rstrip('.')
        
        # Exact match
        if target == allowed_domain:
            return True
        
        # Subdomain check: target must end with .allowed_domain
        # This prevents target.com.evil.com matching target.com
        suffix = '.' + allowed_domain
        if target.endswith(suffix):
            return True
        
        return False
    
    def _is_ip_in_range(self, target: str, allowed_target: str) -> bool:
        """
        Check if an IP address is within an allowed CIDR range.
        
        Args:
            target: The IP to check
            allowed_target: Allowed IP or CIDR (e.g., "192.168.1.0/24")
            
        Returns:
            True if target is within the allowed range
        """
        try:
            target_ip = ipaddress.ip_address(target)
            
            # Check if allowed_target is a network
            if '/' in allowed_target:
                network = ipaddress.ip_network(allowed_target, strict=False)
                return target_ip in network
            else:
                # Single IP comparison
                allowed_ip = ipaddress.ip_address(allowed_target)
                return target_ip == allowed_ip
        except ValueError:
            return False
    
    def is_in_scope(self, target: str) -> bool:
        """
        Validate if a target is within the authorized scope.
        
        This is the main entry point - call this before executing any tool.
        
        Args:
            target: The target to validate (URL, domain, or IP)
            
        Returns:
            True if target is authorized, False otherwise
            
        Example:
            >>> guard = ScopeGuard(ScopeConfig(["target.com"]))
            >>> guard.is_in_scope("https://api.target.com/login")
            True
            >>> guard.is_in_scope("target.com.evil.com")
            False
        """
        if not target or not isinstance(target, str):
            return False
        
        # Normalize the target
        normalized = self._extract_hostname(target)
        if not normalized:
            return False
        
        # Check if explicitly allowed (bypasses safety checks)
        is_explicitly_allowed = self._is_explicitly_allowed(normalized)
        if is_explicitly_allowed:
            return True
        
        # Safety brake: Block localhost unless explicitly allowed
        is_localhost = self._is_localhost(normalized)
        if is_localhost:
            if not self.config.allow_localhost:
                return False
        
        # Safety brake: Block private IPs unless explicitly allowed
        # Skip this check for localhost (loopback) addresses as they are handled above
        if not is_localhost and self._is_private_ip(normalized):
            if not self.config.allow_private_ips:
                return False
        
        # Not in scope
        return False
    
    def _is_explicitly_allowed(self, normalized: str) -> bool:
        """
        Check if a normalized target is explicitly in the allowlist.
        
        Args:
            normalized: Normalized target string
            
        Returns:
            True if explicitly allowed, False otherwise
        """
        for allowed in self._normalized_allowlist:
            # Check if it's a CIDR range
            if '/' in allowed:
                if self._is_ip_in_range(normalized, allowed):
                    return True
                continue
            
            # Check if it's an IP
            try:
                ipaddress.ip_address(allowed)
                # It's an IP - check for match
                if normalized == allowed:
                    return True
                continue
            except ValueError:
                pass
            
            # It's a domain - check for exact match or subdomain
            if self._is_subdomain(normalized, allowed):
                return True
        
        return False
    
    def validate_command(self, command: str) -> bool:
        """
        Validate that a command doesn't contain out-of-scope targets.
        
        This is useful for checking raw command strings before execution.
        
        Args:
            command: The command string to validate
            
        Returns:
            True if all targets in command are in scope
        """
        # Extract potential targets from command
        # This is a simple regex-based extraction - may need refinement
        url_pattern = r'(?:https?://)?(?:[\w-]+\.)+[\w-]+(?:/[\w-./?%&=]*)?'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        targets = re.findall(url_pattern, command, re.IGNORECASE)
        targets.extend(re.findall(ip_pattern, command))
        
        # Validate all found targets
        for target in targets:
            if not self.is_in_scope(target):
                return False
        
        return True
    
    def get_scope_summary(self) -> str:
        """
        Get a human-readable summary of the current scope.
        
        Returns:
            String describing the allowed scope
        """
        lines = ["Authorized Scope:"]
        
        for target in self.config.allowed_targets:
            lines.append(f"  - {target} (and subdomains)" if '.' in target and not self._is_ip(target) else f"  - {target}")
        
        if not self.config.allow_localhost:
            lines.append("  - localhost/loopback: BLOCKED")
        
        if not self.config.allow_private_ips:
            lines.append("  - private IPs: BLOCKED")
        
        return "\n".join(lines)
    
    def _is_ip(self, target: str) -> bool:
        """Helper to check if target is an IP address."""
        return is_ip_address(target)


# Convenience function for quick validation
def validate_target(target: str, allowed_targets: List[str], allow_localhost: bool = False) -> bool:
    """
    Quick validation without creating a ScopeGuard instance.
    
    Args:
        target: Target to validate
        allowed_targets: List of allowed domains/IPs
        allow_localhost: Whether to allow localhost targets
        
    Returns:
        True if target is in scope
    """
    config = ScopeConfig(
        allowed_targets=allowed_targets,
        allow_localhost=allow_localhost
    )
    guard = ScopeGuard(config)
    return guard.is_in_scope(target)
