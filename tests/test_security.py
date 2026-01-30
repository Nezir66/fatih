"""
Tests for the Scope Guard security module.
"""

import pytest
from src.core.security import ScopeGuard, ScopeConfig, validate_target


class TestScopeGuard:
    """Test cases for ScopeGuard class."""
    
    def test_exact_domain_match(self):
        """Test exact domain matching."""
        config = ScopeConfig(allowed_targets=["target.com"])
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("target.com") is True
        assert guard.is_in_scope("other.com") is False
    
    def test_subdomain_matching(self):
        """Test that subdomains are automatically allowed."""
        config = ScopeConfig(allowed_targets=["target.com"])
        guard = ScopeGuard(config)
        
        # Valid subdomains
        assert guard.is_in_scope("api.target.com") is True
        assert guard.is_in_scope("www.target.com") is True
        assert guard.is_in_scope("sub.domain.target.com") is True
        
        # Invalid - not a subdomain
        assert guard.is_in_scope("target.com.evil.com") is False
        assert guard.is_in_scope("not-target.com") is False
    
    def test_url_normalization(self):
        """Test URL parsing and normalization."""
        config = ScopeConfig(allowed_targets=["target.com"])
        guard = ScopeGuard(config)
        
        # Various URL formats should all work
        assert guard.is_in_scope("https://target.com") is True
        assert guard.is_in_scope("http://api.target.com/login") is True
        assert guard.is_in_scope("https://www.target.com:8080/path?query=1") is True
        assert guard.is_in_scope("target.com/api/v1") is True
        assert guard.is_in_scope("target.com:443") is True
    
    def test_localhost_blocking(self):
        """Test that localhost is blocked by default."""
        config = ScopeConfig(allowed_targets=["target.com"])
        guard = ScopeGuard(config)
        
        # All localhost variants should be blocked
        assert guard.is_in_scope("localhost") is False
        assert guard.is_in_scope("127.0.0.1") is False
        assert guard.is_in_scope("::1") is False
        assert guard.is_in_scope("http://localhost:8080") is False
        assert guard.is_in_scope("127.0.0.1:3000") is False
    
    def test_localhost_allowed(self):
        """Test that localhost can be allowed with flag."""
        config = ScopeConfig(
            allowed_targets=["localhost", "127.0.0.1"],
            allow_localhost=True
        )
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("localhost") is True
        assert guard.is_in_scope("127.0.0.1") is True
    
    def test_private_ip_blocking(self):
        """Test that private IPs are blocked by default."""
        config = ScopeConfig(allowed_targets=["target.com"])
        guard = ScopeGuard(config)
        
        # Private IPs should be blocked
        assert guard.is_in_scope("192.168.1.1") is False
        assert guard.is_in_scope("10.0.0.1") is False
        assert guard.is_in_scope("172.16.0.1") is False
    
    def test_private_ip_allowed(self):
        """Test that private IPs can be allowed with flag."""
        config = ScopeConfig(
            allowed_targets=["192.168.1.0/24"],
            allow_private_ips=True
        )
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("192.168.1.5") is True
        assert guard.is_in_scope("192.168.1.100") is True
        assert guard.is_in_scope("192.168.2.1") is False  # Outside range
    
    def test_ip_range_matching(self):
        """Test CIDR range matching."""
        config = ScopeConfig(allowed_targets=["10.0.0.0/8"])
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("10.0.0.1") is True
        assert guard.is_in_scope("10.255.255.255") is True
        assert guard.is_in_scope("11.0.0.1") is False
    
    def test_multiple_targets(self):
        """Test with multiple allowed targets."""
        config = ScopeConfig(allowed_targets=["target.com", "example.org", "192.168.1.5"])
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("target.com") is True
        assert guard.is_in_scope("api.target.com") is True
        assert guard.is_in_scope("example.org") is True
        assert guard.is_in_scope("192.168.1.5") is True
        assert guard.is_in_scope("other.com") is False
    
    def test_case_insensitive(self):
        """Test that matching is case-insensitive."""
        config = ScopeConfig(allowed_targets=["Target.com"])
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("TARGET.COM") is True
        assert guard.is_in_scope("Api.Target.Com") is True
    
    def test_empty_and_invalid_inputs(self):
        """Test handling of empty and invalid inputs."""
        config = ScopeConfig(allowed_targets=["target.com"])
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("") is False
        assert guard.is_in_scope(None) is False
        assert guard.is_in_scope("   ") is False
    
    def test_convenience_function(self):
        """Test the validate_target convenience function."""
        assert validate_target("target.com", ["target.com"]) is True
        assert validate_target("api.target.com", ["target.com"]) is True
        assert validate_target("evil.com", ["target.com"]) is False
        assert validate_target("localhost", ["target.com"]) is False
        assert validate_target("localhost", ["localhost"], allow_localhost=True) is True


class TestEdgeCases:
    """Edge case tests."""
    
    def test_ipv6_addresses(self):
        """Test IPv6 address handling."""
        config = ScopeConfig(allowed_targets=["::1"], allow_localhost=True)
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("::1") is True
        assert guard.is_in_scope("[::1]:8080") is True
    
    def test_trailing_dots(self):
        """Test domains with trailing dots."""
        config = ScopeConfig(allowed_targets=["target.com"])
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("target.com.") is True
        assert guard.is_in_scope("api.target.com.") is True
    
    def test_fragment_and_query_removal(self):
        """Test that fragments and queries are removed."""
        config = ScopeConfig(allowed_targets=["target.com"])
        guard = ScopeGuard(config)
        
        assert guard.is_in_scope("target.com#section") is True
        assert guard.is_in_scope("target.com?foo=bar#section") is True
