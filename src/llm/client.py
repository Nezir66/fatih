"""
LLM Client for Fatih - Unified interface to OpenAI and Anthropic APIs.

This module provides a generic LLM client that abstracts away provider-specific
details, offering a consistent interface for the orchestrator. It supports:
- OpenAI GPT models (GPT-5.1, GPT-5.2, etc.)
- Configurable parameters (temperature, max_tokens)
- Automatic retry logic with exponential backoff
- Normalized response format regardless of provider
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from dotenv import load_dotenv
from openai import OpenAI
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Load environment variables from .env file
load_dotenv()


@dataclass
class LLMResponse:
    """
    Normalized response from any LLM provider.
    
    This dataclass provides a unified interface for LLM responses,
    abstracting away provider-specific response formats.
    
    Attributes:
        content: The text content of the AI's response (if any)
        tool_calls: List of tool/function calls requested by the AI (if any)
        model: The model name that generated the response
        usage: Token usage statistics (prompt_tokens, completion_tokens, total_tokens)
    """
    content: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    model: Optional[str] = None
    usage: Optional[Dict[str, int]] = None


class LLMClient:
    """
    Generic LLM client supporting OpenAI and Anthropic APIs.
    
    This client provides a unified interface for interacting with LLMs,
    handling authentication, retries, and response normalization automatically.
    
    Usage:
        >>> client = LLMClient()
        >>> response = client.chat(
        ...     messages=[{"role": "user", "content": "Hello"}],
        ...     tools=ALL_TOOLS
        ... )
        >>> print(response.content)
    
    Args:
        model: Model identifier (e.g., 'GPT-5.1', 'claude-3-5-sonnet-20241022').
               Defaults to LLM_MODEL env var or 'GPT-5.1'.
        api_key: API key for authentication. Defaults to provider-specific env var.
        temperature: Sampling temperature (0.0-2.0). Defaults to 0.1 for deterministic output.
        max_tokens: Maximum tokens in response. Defaults to 4096.
        max_retries: Maximum retry attempts for failed requests. Defaults to 3.
    """
    
    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        max_retries: int = 3
    ):
        # Configuration
        self.model = model or os.getenv("LLM_MODEL", "gpt-5.1")
        self.temperature = float(os.getenv("LLM_TEMPERATURE", temperature))
        self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", max_tokens))
        self.max_retries = max_retries
        
        # Initialize appropriate client based on model
        self._init_client(api_key)
    
    def _init_client(self, api_key: Optional[str] = None) -> None:
        """
        Initialize the underlying API client based on model selection.
        
        Currently supports OpenAI. Anthropic support can be added via adapter pattern.
        
        Args:
            api_key: Optional API key override
        """
        # Determine provider from model name
        if self.model.startswith("claude"):
            # Anthropic - would need adapter implementation
            raise NotImplementedError(
                "Anthropic support not yet implemented. "
                "Please use an OpenAI model (GPT-5.1, gpt-5.2, etc.)"
            )
        else:
            # Default to OpenAI
            self.provider = "openai"
            self._init_openai_client(api_key)
    
    def _init_openai_client(self, api_key: Optional[str] = None) -> None:
        """
        Initialize OpenAI client with API key resolution.
        
        API key resolution order:
        1. Provided api_key parameter
        2. OPENAI_API_KEY environment variable
        3. Raise error if neither is available
        
        Args:
            api_key: Optional API key override
        """
        resolved_key = api_key or os.getenv("OPENAI_API_KEY")
        
        if not resolved_key:
            raise ValueError(
                "OpenAI API key not found. Please either:\n"
                "1. Pass api_key parameter to LLMClient\n"
                "2. Set OPENAI_API_KEY in your .env file\n"
                "3. Set OPENAI_API_KEY as an environment variable"
            )
        
        self.client = OpenAI(api_key=resolved_key)
    
    @retry(
        retry=retry_if_exception_type((Exception)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True
    )
    def _make_api_call(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> Any:
        """
        Make the actual API call with retry logic.
        
        Uses tenacity for exponential backoff retry on failures.
        Retries on rate limits (429), server errors (5xx), and timeouts.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            tools: Optional list of tool definitions for function calling
            
        Returns:
            Raw API response object
        """
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_completion_tokens": self.max_tokens,
        }
        
        # Add tools if provided
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        
        return self.client.chat.completions.create(**kwargs)
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> LLMResponse:
        """
        Send a chat completion request to the LLM.
        
        This is the main interface for interacting with the LLM. It handles:
        - API authentication
        - Request formatting
        - Retry logic with exponential backoff
        - Response normalization
        
        Args:
            messages: List of message dictionaries in OpenAI format:
                     [{"role": "system", "content": "..."},
                      {"role": "user", "content": "..."}]
            tools: Optional list of tool definitions from src.tools.definitions.ALL_TOOLS
                  When provided, enables function calling mode
        
        Returns:
            LLMResponse object with normalized fields
            
        Raises:
            ValueError: If API key is not configured
            Exception: If API call fails after all retries
            
        Example:
            >>> client = LLMClient()
            >>> messages = [
            ...     {"role": "system", "content": SYSTEM_PROMPT},
            ...     {"role": "user", "content": "Scan example.com"}
            ... ]
            >>> response = client.chat(messages, tools=ALL_TOOLS)
            >>> 
            >>> # Check for tool calls
            >>> if response.tool_calls:
            ...     for call in response.tool_calls:
            ...         print(f"Tool: {call['name']}, Args: {call['arguments']}")
            >>> else:
            ...     print(f"AI Response: {response.content}")
        """
        try:
            # Make API call with retry logic
            raw_response = self._make_api_call(messages, tools)
            
            # Normalize response to LLMResponse format
            return self._normalize_response(raw_response)
            
        except Exception as e:
            # Log error and re-raise after retries are exhausted
            raise Exception(f"LLM API call failed after {self.max_retries} retries: {str(e)}") from e
    
    def _normalize_response(self, raw_response: Any) -> LLMResponse:
        """
        Convert provider-specific response to normalized LLMResponse.
        
        Currently handles OpenAI response format. Can be extended for
        other providers (Anthropic, etc.) via adapter pattern.
        
        Args:
            raw_response: Raw API response object
            
        Returns:
            Normalized LLMResponse object
        """
        if self.provider == "openai":
            return self._normalize_openai_response(raw_response)
        else:
            raise NotImplementedError(f"Response normalization not implemented for provider: {self.provider}")
    
    def _normalize_openai_response(self, raw_response: Any) -> LLMResponse:
        """
        Normalize OpenAI chat completion response.
        
        Args:
            raw_response: OpenAI chat completion response object
            
        Returns:
            Normalized LLMResponse
        """
        choice = raw_response.choices[0]
        message = choice.message
        
        # Extract content
        content = message.content if message.content else None
        
        # Extract tool calls
        tool_calls = None
        if message.tool_calls:
            tool_calls = []
            for tc in message.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "type": tc.type,
                    "name": tc.function.name,
                    "arguments": tc.function.arguments
                })
        
        # Extract usage stats
        usage = None
        if raw_response.usage:
            usage = {
                "prompt_tokens": raw_response.usage.prompt_tokens,
                "completion_tokens": raw_response.usage.completion_tokens,
                "total_tokens": raw_response.usage.total_tokens
            }
        
        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            model=raw_response.model,
            usage=usage
        )


# =============================================================================
# Convenience Functions
# =============================================================================

def create_llm_client(
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 4096
) -> LLMClient:
    """
    Factory function to create an LLMClient with default settings.
    
    This is a convenience wrapper for quick client creation.
    
    Args:
        model: Model identifier (defaults to env var or 'gpt-5.1')
        api_key: API key (defaults to env var)
        temperature: Sampling temperature (default: 0.1)
        max_tokens: Max response tokens (default: 4096)
        
    Returns:
        Configured LLMClient instance
        
    Example:
        >>> client = create_llm_client()
        >>> response = client.chat([{"role": "user", "content": "Hello"}])
    """
    return LLMClient(
        model=model,
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens
    )
