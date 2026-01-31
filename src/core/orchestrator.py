"""
Orchestrator - The central brain of the Fatih penetration testing agent.

This module implements the ReAct (Reasoning and Acting) loop that drives
the autonomous security assessment. It coordinates between the LLM, security
tools, and state management to perform intelligent penetration testing.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from src.core.exceptions import TargetOutOfScopeError, ToolExecutionError
from src.core.security import ScopeConfig, ScopeGuard
from src.core.state_manager import StateManager
from src.llm.client import LLMClient
from src.llm.prompts import SYSTEM_PROMPT
from src.tools.definitions import ALL_TOOLS
from src.tools.discovery.subfinder import SubfinderTool
from src.tools.network.nmap import NmapTool
from src.tools.web.httpx import HttpxTool
from src.tools.web.katana import KatanaTool
from src.tools.web.nuclei import NucleiTool
from src.tools.web.playwright_crawler import PlaywrightCrawlerTool

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Central orchestrator that manages the ReAct loop for autonomous penetration testing.
    
    The orchestrator connects all components:
    - ScopeGuard: Enforces security boundaries
    - StateManager: Tracks discovered assets and scan history
    - LLMClient: Interfaces with the AI for decision making
    - Tool instances: Execute security scanning commands
    
    The run() method implements the main ReAct loop:
    1. Observe: Get current state from StateManager
    2. Orient: Build context for LLM (system prompt + state + history)
    3. Decide: Call LLM to get next action (thought or tool call)
    4. Act: Execute tool calls, update state, repeat
    
    Example:
        >>> orchestrator = Orchestrator("https://example.com")
        >>> orchestrator.run()
    """
    
    def __init__(self, target_url: str, max_iterations: int = 20):
        """
        Initialize the orchestrator with all required components.
        
        Args:
            target_url: The primary target URL to assess
            max_iterations: Maximum number of ReAct loop iterations (safety limit)
        """
        self.target_url = target_url
        self.max_iterations = max_iterations
        
        # Extract domain from URL for scope configuration
        domain = self._extract_domain(target_url)
        
        # Initialize security components
        scope_config = ScopeConfig(
            allowed_targets=[domain],
            allow_localhost=False,
            allow_private_ips=False
        )
        self.scope_guard = ScopeGuard(scope_config)
        
        # Initialize state management
        self.state_manager = StateManager(target=target_url, auto_save=True)
        
        # Initialize LLM client
        self.llm_client = LLMClient()
        
        # Initialize tool instances
        self.nmap_tool = NmapTool(self.scope_guard)
        self.nuclei_tool = NucleiTool(self.scope_guard)
        self.subfinder_tool = SubfinderTool(self.scope_guard)
        self.katana_tool = KatanaTool(self.scope_guard)
        self.playwright_tool = PlaywrightCrawlerTool(self.scope_guard)
        self.httpx_tool = HttpxTool(self.scope_guard)
        
        # Tool mapping: function names from definitions -> tool instances
        self.tool_map = {
            "run_nmap": self.nmap_tool,
            "run_nuclei": self.nuclei_tool,
            "run_subfinder": self.subfinder_tool,
            "run_katana": self.katana_tool,
            "run_playwright_crawler": self.playwright_tool,
            "run_httpx": self.httpx_tool
        }
        
        # Message history for LLM context
        self.message_history: List[Dict[str, Any]] = []
        
        logger.info(f"Orchestrator initialized for target: {target_url}")
        logger.info(f"Scope: {self.scope_guard.get_scope_summary()}")
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or parsed.path or url
    
    def run(self) -> None:
        """
        Execute the main ReAct loop.
        
        This method runs the autonomous assessment loop until:
        - Maximum iterations reached (safety limit)
        - LLM indicates completion (no more tool calls)
        - Critical error occurs
        
        The loop follows the ReAct pattern:
        1. Get current state summary
        2. Build messages for LLM (system + state + history)
        3. Call LLM with available tools
        4. Process response (thoughts or tool calls)
        5. Execute tools, update state, add to history
        6. Repeat
        """
        logger.info("Starting ReAct loop...")
        
        iteration = 0
        for iteration in range(self.max_iterations):
            logger.info(f"=== Iteration {iteration + 1}/{self.max_iterations} ===")
            
            try:
                # Step A: Get current state summary
                state_summary = self._get_state_summary()
                
                # Step B: Build messages for LLM
                messages = self._build_messages(state_summary)
                
                # Step C: Call LLM with tools
                response = self.llm_client.chat(messages=messages, tools=ALL_TOOLS)
                
                # Step D: Process response
                should_continue = self._process_response(response)
                
                if not should_continue:
                    logger.info("LLM indicated completion. Ending loop.")
                    break
                    
            except Exception as e:
                logger.error(f"Error in iteration {iteration + 1}: {e}")
                # Continue to next iteration unless it's a critical error
                if isinstance(e, TargetOutOfScopeError):
                    logger.critical("Critical security violation detected. Stopping.")
                    raise
        
        logger.info(f"ReAct loop completed after {iteration + 1} iterations")
        
        # Generate final summary
        final_summary = self.state_manager.get_summary()
        logger.info(f"Final state: {json.dumps(final_summary, indent=2)}")
    
    def _get_state_summary(self) -> str:
        """Get current state summary from StateManager."""
        return self.state_manager.get_context_for_ai(detailed=False)
    
    def _build_messages(self, state_summary: str) -> List[Dict[str, str]]:
        """
        Build the messages list for LLM chat completion.
        
        Structure:
        1. System prompt (always first)
        2. Current state summary
        3. Message history (previous interactions)
        """
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Current state:\n{state_summary}\n\nWhat should I do next?"}
        ]
        
        # Add message history (tool results from previous iterations)
        for msg in self.message_history:
            messages.append(msg)
        
        return messages
    
    def _process_response(self, response: Any) -> bool:
        """
        Process the LLM response and execute any tool calls.
        
        Args:
            response: LLMResponse object from LLM client
            
        Returns:
            bool: True to continue loop, False to stop
        """
        # Log AI thought/content if present (but don't add to history yet)
        if response.content:
            logger.info(f"AI Thought: {response.content}")
        
        # Check for tool calls
        if not response.tool_calls:
            # No tool calls means the AI is done or thinking
            if response.content:
                # Add the thought to history as a regular assistant message
                self.message_history.append({
                    "role": "assistant",
                    "content": response.content
                })
            else:
                logger.warning("LLM returned no content and no tool calls")
            return False
        
        # Build the assistant message with tool_calls for history
        # This MUST come before any tool messages
        assistant_message = {
            "role": "assistant",
            "content": response.content or None,
            "tool_calls": [
                {
                    "id": tc.get("id"),
                    "type": tc.get("type", "function"),
                    "function": {
                        "name": tc.get("name"),
                        "arguments": tc.get("arguments", "{}")
                    }
                }
                for tc in response.tool_calls
            ]
        }
        self.message_history.append(assistant_message)
        
        # Process each tool call
        for tool_call in response.tool_calls:
            tool_name = tool_call.get("name")
            tool_id = tool_call.get("id")
            arguments_str = tool_call.get("arguments", "{}")
            
            try:
                arguments = json.loads(arguments_str)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse tool arguments: {arguments_str}")
                continue
            
            logger.info(f"Tool call: {tool_name}({arguments})")
            
            # Check if action was already executed (loop prevention)
            target = arguments.get("target", "")
            params_str = json.dumps(arguments, sort_keys=True)
            
            if self.state_manager.was_action_executed(tool_name, target, params_str):
                logger.warning(f"Skipping duplicate action: {tool_name} on {target}")
                continue
            
            # Execute the tool
            result = self._execute_tool(tool_name, arguments)
            
            # Record the action
            result_summary = self._summarize_result(result)
            self.state_manager.record_action(tool_name, target, params_str, result_summary)
            
            # Add tool output to history for next LLM call
            tool_response = {
                "role": "tool",
                "tool_call_id": tool_id,
                "name": tool_name,
                "content": json.dumps(result, default=str, indent=2)
            }
            self.message_history.append(tool_response)
        
        return True
    
    def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        Execute a tool by name with the given arguments.
        
        Args:
            tool_name: Name of the tool function (e.g., "run_nmap")
            arguments: Dictionary of tool parameters
            
        Returns:
            Tool execution result
        """
        if tool_name not in self.tool_map:
            error_msg = f"Unknown tool: {tool_name}"
            logger.error(error_msg)
            return {"error": error_msg}
        
        tool = self.tool_map[tool_name]
        target = arguments.get("target", "")
        
        try:
            # Remove 'target' from kwargs, pass separately
            kwargs = {k: v for k, v in arguments.items() if k != "target"}
            
            # Execute the tool
            result = tool.run(target, **kwargs)
            
            # Update state manager with results
            self._update_state_from_result(tool_name, target, result)
            
            return result
            
        except TargetOutOfScopeError as e:
            logger.error(f"Scope violation: {e}")
            return {"error": str(e), "type": "out_of_scope"}
        except ToolExecutionError as e:
            logger.error(f"Tool execution failed: {e}")
            return {"error": str(e), "type": "execution_error"}
        except Exception as e:
            logger.error(f"Unexpected error executing {tool_name}: {e}")
            return {"error": str(e), "type": "unexpected_error"}
    
    def _update_state_from_result(self, tool_name: str, target: str, result: Any) -> None:
        """
        Update the StateManager based on tool execution results.
        
        Args:
            tool_name: Name of the tool that was executed
            target: Target that was scanned
            result: Tool execution result
        """
        if tool_name == "run_subfinder":
            # Result is List[Host]
            if isinstance(result, list):
                for host in result:
                    if host.domain:
                        self.state_manager.add_host(host.domain)
                        logger.debug(f"Added host from subfinder: {host.domain}")
        
        elif tool_name == "run_nmap":
            # Result is Host object
            if result and hasattr(result, 'get_open_ports'):
                host_id = result.ip or result.domain or target
                self.state_manager.add_host(host_id)
                
                # Add ports
                for port in result.ports.values():
                    self.state_manager.add_port(
                        host_id=host_id,
                        port_num=port.number,
                        protocol=port.protocol,
                        state=port.state,
                        service=port.service
                    )
                
                logger.info(f"Updated state with nmap results for {host_id}: "
                           f"{len(result.get_open_ports())} open ports")
        
        elif tool_name == "run_nuclei":
            # Result is List[Vulnerability]
            if isinstance(result, list):
                for vuln in result:
                    self.state_manager.add_vulnerability(
                        target_host=target,
                        vuln_id=vuln.vuln_id,
                        title=vuln.title,
                        severity=vuln.severity,
                        location=vuln.location,
                        description=vuln.description,
                        evidence=vuln.evidence,
                        tool="nuclei"
                    )
                logger.info(f"Added {len(result)} vulnerabilities from nuclei scan")
        
        elif tool_name == "run_katana":
            # Result is Dict with endpoints and sitemap
            if isinstance(result, dict) and "endpoints" in result:
                endpoints = result["endpoints"]
                sitemap = result.get("sitemap")
                
                # Add each endpoint to state
                for endpoint in endpoints:
                    self.state_manager.add_web_endpoint(target, endpoint)
                
                # Mark crawl as completed
                self.state_manager.complete_crawl(target, sitemap)
                
                logger.info(f"Added {len(endpoints)} endpoints from katana crawl for {target}")
        
        elif tool_name == "run_playwright_crawler":
            # Result is Dict with endpoints (same format as Katana)
            if isinstance(result, dict) and "endpoints" in result:
                endpoints = result["endpoints"]
                
                # Add each endpoint to state
                for endpoint in endpoints:
                    self.state_manager.add_web_endpoint(target, endpoint)
                
                # Mark crawl as completed
                self.state_manager.complete_crawl(target, None)
                
                logger.info(f"Added {len(endpoints)} endpoints from playwright crawl for {target}")
        
        elif tool_name == "run_httpx":
            # Result is Dict with services and vhosts
            if isinstance(result, dict) and "services" in result:
                services = result["services"]
                vhosts = result.get("vhosts", [])
                
                # Update state with first service info (primary URL)
                if services:
                    primary = services[0]
                    self.state_manager.update_web_host_httpx(
                        base_url=target,
                        status=primary.get("status_code"),
                        title=primary.get("title"),
                        web_server=primary.get("web_server"),
                        content_length=primary.get("content_length"),
                        tech_stack=primary.get("tech_stack", []),
                        vhosts=vhosts
                    )
                
                logger.info(f"Updated HTTP probing data for {target}: "
                           f"{len(services)} services, {len(vhosts)} vhosts")
    
    def _summarize_result(self, result: Any) -> str:
        """Create a brief summary of tool result for action history."""
        if isinstance(result, list):
            return f"List with {len(result)} items"
        elif hasattr(result, 'get_open_ports'):
            return f"Host with {len(result.get_open_ports())} open ports"
        elif isinstance(result, dict):
            if "error" in result:
                return f"Error: {result['error']}"
            elif "endpoints" in result:
                return f"Crawl with {result.get('total_count', 0)} endpoints"
            elif "services" in result:
                # Httpx result
                services_count = result.get('total_count', 0)
                vhosts_count = len(result.get('vhosts', []))
                return f"HTTP probe: {services_count} services, {vhosts_count} vhosts"
        return "Success"
    
    def export_report(self, output_path: str = "outputs/report.json") -> None:
        """
        Export the final assessment report.
        
        Args:
            output_path: Path to save the report
        """
        self.state_manager.export_report(output_path, format="json")
        logger.info(f"Report exported to: {output_path}")
