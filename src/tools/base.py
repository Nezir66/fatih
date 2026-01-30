"""
Base tool class for the Fatih penetration testing agent.

This module provides an abstract base class that all security tools must inherit from.
It enforces scope validation before execution and provides a consistent interface
for running tools and parsing their output.
"""

import subprocess
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from src.core.exceptions import TargetOutOfScopeError, ToolExecutionError
from src.core.security import ScopeGuard


class BaseTool(ABC):
    """
    Abstract base class for all security tools.
    
    All tool wrappers must inherit from this class and implement:
    - tool_name: Class attribute with the tool's name
    - _build_command(): Method to construct the shell command
    - _parse_output(): Method to parse tool output into structured data
    
    Example:
        >>> class MyTool(BaseTool):
        ...     tool_name = "mytool"
        ...     
        ...     def _build_command(self, target: str, **kwargs) -> str:
        ...         return f"mytool {target}"
        ...     
        ...     def _parse_output(self, output: str, target: str) -> Any:
        ...         return {"result": output}
    """
    
    tool_name: str = "base"
    
    def __init__(self, scope_guard: ScopeGuard):
        """
        Initialize the tool with a scope guard.
        
        Args:
            scope_guard: ScopeGuard instance for validating targets
        """
        self.scope_guard = scope_guard
    
    def run(self, target: str, **kwargs) -> Any:
        """
        Execute the tool against a target after scope validation.
        
        This method:
        1. Validates the target is within scope
        2. Builds the command string
        3. Executes the command via subprocess
        4. Parses the output into structured data
        
        Args:
            target: The target to scan (domain, IP, or URL)
            **kwargs: Additional tool-specific parameters
            
        Returns:
            Parsed output as structured data (type depends on tool)
            
        Raises:
            TargetOutOfScopeError: If target is not in authorized scope
            ToolExecutionError: If the tool fails to execute
        """
        # Step 1: Validate target is in scope
        if not self.scope_guard.is_in_scope(target):
            raise TargetOutOfScopeError(
                f"Target '{target}' is not in authorized scope. "
                f"Operation blocked for security."
            )
        
        # Step 2: Build the command
        command = self._build_command(target, **kwargs)
        
        # Step 3: Execute the command
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute default timeout
                check=True
            )
            output = result.stdout
        except subprocess.CalledProcessError as e:
            # Tool returned non-zero exit code
            # Return empty result rather than crashing
            return self._handle_error(e, target)
        except subprocess.TimeoutExpired:
            # Tool timed out
            return self._handle_timeout(target)
        except Exception as e:
            # Unexpected error during execution
            raise ToolExecutionError(
                f"Failed to execute {self.tool_name}: {str(e)}"
            ) from e
        
        # Step 4: Parse the output
        return self._parse_output(output, target)
    
    @abstractmethod
    def _build_command(self, target: str, **kwargs) -> str:
        """
        Build the shell command for this tool.
        
        Args:
            target: The target to scan
            **kwargs: Tool-specific parameters
            
        Returns:
            Command string ready for execution
        """
        pass
    
    @abstractmethod
    def _parse_output(self, output: str, target: str) -> Any:
        """
        Parse tool output into structured data.
        
        Args:
            output: Raw stdout from the tool
            target: The target that was scanned
            
        Returns:
            Structured data (type depends on tool implementation)
        """
        pass
    
    def _handle_error(self, error: subprocess.CalledProcessError, target: str) -> Any:
        """
        Handle tool execution errors gracefully.
        
        Override this method to customize error handling.
        Default behavior returns an empty result.
        
        Args:
            error: The CalledProcessError that occurred
            target: The target that was being scanned
            
        Returns:
            Empty or partial result
        """
        # Log the error but don't crash
        # Return empty result based on tool type
        return self._get_empty_result(target)
    
    def _handle_timeout(self, target: str) -> Any:
        """
        Handle tool timeout gracefully.
        
        Args:
            target: The target that was being scanned
            
        Returns:
            Empty or partial result
        """
        return self._get_empty_result(target)
    
    def _get_empty_result(self, target: str) -> Any:
        """
        Return an empty result for this tool type.
        
        Override this method to return appropriate empty results.
        
        Args:
            target: The target that was being scanned
            
        Returns:
            Empty result (type depends on tool)
        """
        return None
