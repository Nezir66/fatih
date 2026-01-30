#!/usr/bin/env python3
"""
Test für Playwright Crawler
"""

import sys
sys.path.insert(0, '/Users/nezir/Documents/Projects/fatih')

from src.core.security import ScopeConfig, ScopeGuard
from src.tools.web.playwright_crawler import PlaywrightCrawlerTool

def test_playwright_crawler():
    """Teste Playwright Crawler"""
    print("=== Playwright Crawler Test ===\n")
    
    # Scope konfigurieren
    scope_config = ScopeConfig(
        allowed_targets=["httpbin.org"],
        allow_localhost=False,
        allow_private_ips=False
    )
    scope_guard = ScopeGuard(scope_config)
    
    # Tool initialisieren
    crawler = PlaywrightCrawlerTool(scope_guard)
    
    # Test gegen httpbin.org
    target = "https://httpbin.org"
    print(f"Crawling: {target}")
    print("Waiting for JavaScript rendering...\n")
    
    try:
        result = crawler.run(target, wait_time=3, scroll=True)
        
        print(f"✓ Crawl complete!")
        print(f"  Endpoints found: {result['total_count']}")
        
        if result['endpoints']:
            print("\n  Discovered endpoints:")
            for ep in result['endpoints'][:5]:
                print(f"    - {ep.endpoint_type.value}: {ep.method} {ep.url[:60]}...")
                if ep.parameters:
                    print(f"      Params: {ep.parameters[:3]}...")
        else:
            print("\n  No endpoints found (this is OK for a simple test)")
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_playwright_crawler()
