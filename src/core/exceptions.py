"""
Custom exceptions for the Fatih penetration testing agent.

This module defines a clear exception hierarchy that allows the orchestrator
to distinguish between different types of errors and handle them appropriately.
"""


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class TargetOutOfScopeError(SecurityError):
    """
    Raised when attempting to scan a target outside the authorized scope.
    
    This is a critical security violation that should cause the orchestrator
to immediately halt operations and prevent the AI from proceeding.
    
    Example:
        >>> raise TargetOutOfScopeError(
        ...     "Target 'pentagon.gov' is not in authorized scope: ['example.com']"
        ... )
    """
    pass


class ToolExecutionError(Exception):
    """Raised when a security tool fails to execute properly."""
    pass


class ParseError(Exception):
    """Raised when tool output cannot be parsed."""
    pass
