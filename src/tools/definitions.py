"""
Tool definitions for LLM Function Calling.

This module exports tool schemas in the OpenAI/Anthropic Function Calling format.
These definitions are used by the LLM client to enable the AI to invoke security tools.

All tool schemas use strict mode to ensure 100% schema compliance and prevent
hallucinated parameters.
"""

from typing import Any, Dict, List


def get_tool_definitions() -> List[Dict[str, Any]]:
    """
    Return all tool definitions in OpenAI Function Calling format.
    
    These schemas define the interface between the LLM and the security tools.
    Each tool has:
    - A unique name (used as the function key)
    - A clear description for the AI
    - Strict JSON Schema for parameters
    - strict: True to enforce schema compliance
    
    Returns:
        List of tool definition dictionaries compatible with OpenAI's API
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "run_subfinder",
                "description": "Discover subdomains for a given domain using passive DNS sources and OSINT. Returns a list of discovered subdomains with their host information.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "The root domain to enumerate (e.g., 'example.com'). Do not include protocol (http/https) or paths."
                        }
                    },
                    "required": ["target"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "run_nmap",
                "description": "Scan ports and detect services on a target host. Performs service version detection and returns detailed port information including open ports, services, and versions.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "IP address or hostname to scan (e.g., '192.168.1.1' or 'api.example.com')"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port range to scan. Examples: '80,443' for specific ports, '1-1000' for range, 'top-100' for common ports. Use empty string '' to scan top 1000 common ports (default behavior)."
                        }
                    },
                    "required": ["target", "ports"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "run_nuclei",
                "description": "Scan for known vulnerabilities, CVEs, and security misconfigurations using Nuclei templates. Returns a list of vulnerability findings with severity levels and evidence.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "URL to scan (e.g., 'https://example.com' or 'https://api.example.com/v1'). Must include protocol (http/https)."
                        },
                        "templates": {
                            "type": "string",
                            "description": "Specific template path or filter. Examples: 'cves/' for CVE checks only, 'http/exposures/' for exposure detection, 'misconfiguration/' for misconfigs. Use empty string '' to use all available templates (default behavior)."
                        }
                    },
                    "required": ["target", "templates"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "run_katana",
                "description": "Crawl a website to discover endpoints, forms, APIs, and JavaScript files. Returns structured endpoint data with URLs, HTTP methods, parameters, and endpoint types for further security testing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL to crawl (e.g., 'https://example.com'). Must include protocol (http/https)."
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["standard", "deep", "javascript", "sitemap"],
                            "description": "Crawl mode: 'standard' for normal crawling (default), 'deep' for aggressive deep crawling with higher depth, 'javascript' to parse JavaScript files for dynamic/API endpoints, 'sitemap' to generate XML sitemap"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Maximum crawl depth levels to follow (default: 3, max: 5). Higher values discover more endpoints but take longer."
                        }
                    },
                    "required": ["target", "mode", "depth"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "run_playwright_crawler",
                "description": "Crawl JavaScript-heavy websites and SPAs (Single Page Applications) using a headless browser. This tool renders JavaScript and extracts dynamically loaded content that traditional crawlers miss. Use this for React, Vue, Angular, or other modern web apps.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL to crawl (e.g., 'https://example.com'). Must include protocol (http/https)."
                        },
                        "wait_time": {
                            "type": "integer",
                            "description": "Seconds to wait for JavaScript rendering (default: 5). Increase for slow-loading SPAs."
                        }
                    },
                    "required": ["target", "wait_time"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "run_httpx",
                "description": "Perform HTTP probing with technology detection, status code analysis, and optional screenshot capture. Detects web server type, technology stack (React, WordPress, etc.), page titles, and content length. Use this after discovering subdomains or endpoints to gather detailed HTTP service information.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL to probe (e.g., 'https://example.com' or 'https://api.example.com'). Must include protocol (http/https). For multiple targets discovered by subfinder, run this tool multiple times or use the same domain pattern."
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["probe", "vhost"],
                            "description": "Operation mode: 'probe' for standard HTTP probing with tech detection (default), 'vhost' for virtual host discovery (slower, use when suspicious of shared hosting). Note: Use 'run_playwright_crawler' for screenshots instead."
                        },
                        "follow_redirects": {
                            "type": "boolean",
                            "description": "Follow HTTP redirects (default: true). Set to false to analyze initial response only."
                        }
                    },
                    "required": ["target", "mode", "follow_redirects"],
                    "additionalProperties": False
                },
                "strict": True
            }
        }
    ]


# Convenience export for direct import
ALL_TOOLS = get_tool_definitions()
