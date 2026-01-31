"""
Validation utilities for Fatih.

This module provides common validation functions used across the codebase
to avoid duplication and ensure consistency.
"""

import ipaddress
import re


def is_ip_address(target: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).
    
    Supports both standard notation and bracketed IPv6 notation.
    
    Args:
        target: String to check
        
    Returns:
        True if target is a valid IP address, False otherwise
        
    Examples:
        >>> is_ip_address("192.168.1.1")
        True
        >>> is_ip_address("10.0.0.1")
        True
        >>> is_ip_address("::1")
        True
        >>> is_ip_address("[::1]")
        True
        >>> is_ip_address("example.com")
        False
        >>> is_ip_address("sub.example.com")
        False
    """
    if not target or not isinstance(target, str):
        return False
    
    # Handle bracketed IPv6 notation (e.g., [::1])
    cleaned_target = target.strip()
    if cleaned_target.startswith('[') and cleaned_target.endswith(']'):
        cleaned_target = cleaned_target[1:-1]
    
    try:
        ipaddress.ip_address(cleaned_target)
        return True
    except ValueError:
        return False


def is_ipv4_address(target: str) -> bool:
    """
    Check if a string is a valid IPv4 address.
    
    Args:
        target: String to check
        
    Returns:
        True if target is a valid IPv4 address, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    try:
        ip = ipaddress.ip_address(target.strip())
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False


def is_ipv6_address(target: str) -> bool:
    """
    Check if a string is a valid IPv6 address.
    
    Args:
        target: String to check
        
    Returns:
        True if target is a valid IPv6 address, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    try:
        ip = ipaddress.ip_address(target.strip())
        return isinstance(ip, ipaddress.IPv6Address)
    except ValueError:
        return False


def is_private_ip(target: str) -> bool:
    """
    Check if a string is a private IP address.
    
    Args:
        target: String to check
        
    Returns:
        True if target is a private IP, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    try:
        ip = ipaddress.ip_address(target.strip())
        return ip.is_private
    except ValueError:
        return False


def is_loopback_ip(target: str) -> bool:
    """
    Check if a string is a loopback IP address.
    
    Args:
        target: String to check
        
    Returns:
        True if target is a loopback IP, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    try:
        ip = ipaddress.ip_address(target.strip())
        return ip.is_loopback
    except ValueError:
        return False


def validate_port_number(port: int) -> bool:
    """
    Validate that a port number is within valid range.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if port is valid (1-65535), False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535
