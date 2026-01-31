"""
Playwright Crawler - Headless browser crawling for JavaScript-heavy websites.

This tool uses Playwright to render JavaScript and extract endpoints from SPAs
(Single Page Applications) like React, Vue, Angular apps that traditional
crawlers like Katana cannot handle properly.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs

from src.core.state_manager import EndpointType, WebEndpoint
from src.tools.base import BaseTool

logger = logging.getLogger(__name__)


class PlaywrightCrawlerTool(BaseTool):
    """
    Playwright-based crawler for JavaScript-rendered websites.
    
    This tool is designed to handle modern SPAs (Single Page Applications)
    that rely heavily on JavaScript to render content. It uses a headless
    Chromium browser to execute JavaScript and extract endpoints.
    
    Example:
        >>> from src.core.security import ScopeGuard, ScopeConfig
        >>> guard = ScopeGuard(ScopeConfig(["example.com"]))
        >>> tool = PlaywrightCrawlerTool(guard)
        >>> result = tool.run("https://example.com", wait_time=5)
        >>> print(f"Found {len(result['endpoints'])} endpoints")
    """
    
    tool_name = "playwright_crawler"
    
    def _build_command(self, target: str, **kwargs) -> str:
        """
        Build the Playwright crawler command.
        
        Args:
            target: Target URL to crawl
            **kwargs: Additional options:
                - wait_time: Seconds to wait for JS rendering (default: 5)
                - scroll: Whether to scroll the page (default: True)
                - depth: Crawl depth (default: 1, only start page)
                
        Returns:
            Command string (Python script to execute)
        """
        wait_time = kwargs.get("wait_time", 5)
        scroll = kwargs.get("scroll", True)
        depth = kwargs.get("depth", 1)
        
        # Build Python script to run inside container
        script = f"""python3 << 'EOF'
import json
import sys
from playwright.sync_api import sync_playwright

def crawl():
    results = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        page = context.new_page()
        
        try:
            # Navigate and wait for load
            page.goto('{target}', wait_until='networkidle', timeout=30000)
            
            # Additional wait for JS rendering
            import time
            time.sleep({wait_time})
            
            # Scroll to trigger lazy loading
            if {str(scroll).lower()}:
                page.evaluate('() => {{ window.scrollTo(0, document.body.scrollHeight); }}')
                time.sleep(2)
            
            # Extract all links
            links = page.eval_on_selector_all('a[href]', '''elements => elements.map(el => ({{
                url: el.href,
                text: el.textContent.trim(),
                tag: 'a'
            }}))''')
            
            # Extract all forms
            forms = page.eval_on_selector_all('form', '''elements => elements.map(el => {{
                const inputs = Array.from(el.querySelectorAll('input, textarea, select'));
                return {{
                    action: el.action || window.location.href,
                    method: el.method || 'GET',
                    parameters: inputs.map(input => input.name).filter(Boolean)
                }};
            }})''')
            
            # Extract API calls from scripts (basic pattern matching)
            scripts = page.eval_on_selector_all('script', '''elements => {{
                const urls = [];
                elements.forEach(el => {{
                    if (el.textContent) {{
                        // Look for API endpoints in scripts
                        const matches = el.textContent.match(/['"`](\\/api\\/[^'"`]+)['"`]/g);
                        if (matches) {{
                            urls.push(...matches.map(m => m.replace(/['"`]/g, '')));
                        }}
                    }}
                }});
                return urls;
            }}''')
            
            # Get page info
            title = page.title()
            url = page.url
            
            results.append({{
                'url': url,
                'title': title,
                'links': links,
                'forms': forms,
                'scripts': scripts,
                'status_code': 200
            }})
            
        except Exception as e:
            results.append({{
                'error': str(e),
                'url': '{target}'
            }})
        finally:
            browser.close()
    
    print(json.dumps(results))

crawl()
EOF"""
        
        return script
    
    def _parse_output(self, output: str, target: str) -> Dict[str, Any]:
        """
        Parse Playwright crawler output into structured data.
        
        Args:
            output: JSON output from Playwright script
            target: The target URL that was crawled
            
        Returns:
            Dictionary containing:
            - endpoints: List[WebEndpoint]
            - total_count: int
        """
        endpoints = []
        
        if not output or not output.strip():
            logger.warning(f"No output from Playwright crawler for {target}")
            return {"endpoints": [], "total_count": 0}
        
        try:
            data = json.loads(output.strip())
            
            if isinstance(data, list) and len(data) > 0:
                page_data = data[0]
                
                if "error" in page_data:
                    logger.error(f"Playwright error: {page_data['error']}")
                    return {"endpoints": [], "total_count": 0}
                
                base_url = page_data.get("url", target)
                
                # Add the main page
                endpoints.append(WebEndpoint(
                    url=base_url,
                    method="GET",
                    endpoint_type=EndpointType.PAGE,
                    parameters=[],
                    status_code=page_data.get("status_code", 200),
                    content_type="text/html",
                    source="playwright"
                ))
                
                # Process links
                seen_urls = {base_url}
                for link in page_data.get("links", []):
                    url = link.get("url", "").strip()
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        
                        # Skip external links
                        if not self._is_same_domain(url, target):
                            continue
                        
                        # Skip static files
                        if self._is_static_file(url):
                            endpoints.append(WebEndpoint(
                                url=url,
                                method="GET",
                                endpoint_type=EndpointType.STATIC_FILE,
                                parameters=[],
                                status_code=200,
                                content_type="",
                                source="playwright"
                            ))
                        else:
                            endpoints.append(WebEndpoint(
                                url=url,
                                method="GET",
                                endpoint_type=EndpointType.PAGE,
                                parameters=[],
                                status_code=200,
                                content_type="text/html",
                                source="playwright"
                            ))
                
                # Process forms
                for form in page_data.get("forms", []):
                    action = form.get("action", target)
                    method = form.get("method", "GET").upper()
                    parameters = form.get("parameters", [])
                    
                    endpoints.append(WebEndpoint(
                        url=action,
                        method=method,
                        endpoint_type=EndpointType.FORM,
                        parameters=parameters,
                        status_code=200,
                        content_type="text/html",
                        source="playwright"
                    ))
                
                # Process API endpoints found in scripts
                for api_path in page_data.get("scripts", []):
                    # Convert relative to absolute URL
                    if api_path.startswith("/"):
                        api_url = urljoin(target, api_path)
                    else:
                        api_url = api_path
                    
                    if api_url not in seen_urls:
                        seen_urls.add(api_url)
                        endpoints.append(WebEndpoint(
                            url=api_url,
                            method="GET",
                            endpoint_type=EndpointType.API,
                            parameters=[],
                            status_code=200,
                            content_type="application/json",
                            source="playwright"
                        ))
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Playwright output: {e}")
        except Exception as e:
            logger.error(f"Error processing Playwright results: {e}")
        
        logger.info(f"Playwright crawl complete for {target}: {len(endpoints)} endpoints found")
        
        return {
            "endpoints": endpoints,
            "total_count": len(endpoints)
        }
    
    def _is_same_domain(self, url: str, target: str) -> bool:
        """Check if URL belongs to same domain as target."""
        try:
            url_domain = urlparse(url).netloc
            target_domain = urlparse(target).netloc
            return url_domain == target_domain or url_domain.endswith("." + target_domain)
        except:
            return False
    
    def _is_static_file(self, url: str) -> bool:
        """Check if URL is a static file."""
        static_extensions = [".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip"]
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def _get_empty_result(self, target: str) -> Dict[str, Any]:
        """Return empty result when crawler fails."""
        return {"endpoints": [], "total_count": 0}
