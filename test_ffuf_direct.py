import logging
import sys
from src.core.security import ScopeGuard, ScopeConfig
from src.tools.web.ffuf import FfufTool

# Setup basic logging to see the output
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

def test_ffuf_tool():
    target = "http://testphp.vulnweb.com"
    print(f"[*] Starting FfufTool test against {target}")
    
    # 1. Initialize ScopeGuard (required for tool execution)
    # We explicitly allow the target domain
    scope_config = ScopeConfig(allowed_domains=["testphp.vulnweb.com"])
    guard = ScopeGuard(config=scope_config)
    
    # 2. Initialize the Tool
    ffuf = FfufTool(scope_guard=guard)
    
    # 3. Run the tool (Directory discovery)
    # Using 'common' wordlist and basic extensions
    print("[*] Running directory discovery...")
    try:
        result = ffuf.run(
            target=target,
            wordlist="common",
            extensions="common", # .php, .html, etc.
            recursion=False # Keep it simple for the test
        )
        
        # 4. Analyze Results
        print("\n" + "="*50)
        print(f"SCAN COMPLETED")
        print("="*50)
        
        endpoints = result.get("endpoints", [])
        print(f"Total endpoints found: {len(endpoints)}")
        
        if endpoints:
            print("\nFound Directories/Files:")
            for endpoint in endpoints:
                print(f" - [{endpoint.status_code}] {endpoint.url} ({endpoint.content_type})")
        else:
            print("No endpoints found (check if ffuf is installed and wordlists are present).")
            
    except Exception as e:
        print(f"\n[!] Error running tool: {e}")

if __name__ == "__main__":
    test_ffuf_tool()
