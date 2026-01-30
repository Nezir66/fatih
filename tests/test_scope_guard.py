#!/usr/bin/env python3
"""
Test für ScopeGuard Erweiterung
"""

import sys
sys.path.insert(0, '/Users/nezir/Documents/Projects/fatih')

from src.core.security import ScopeConfig, ScopeGuard

def test_scope_guard():
    """Teste die erweiterte ScopeGuard Logik"""
    print("=== ScopeGuard Test ===\n")
    
    # Test 1: www.publbee.com als Target
    print("Test 1: Target = https://www.publbee.com/")
    config = ScopeConfig(allowed_targets=["https://www.publbee.com/"])
    guard = ScopeGuard(config)
    
    test_cases = [
        ("www.publbee.com", True, "www variant"),
        ("publbee.com", True, "root domain"),
        ("api.publbee.com", True, "subdomain"),
        ("sub.api.publbee.com", True, "deep subdomain"),
        ("evil.com", False, "unrelated domain"),
        ("publbee.com.evil.com", False, "domain suffix attack"),
    ]
    
    for target, expected, description in test_cases:
        result = guard.is_in_scope(target)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {description}: {target} -> {result} (expected: {expected})")
    
    print("\n" + "="*50)
    print(guard.get_scope_summary())
    
    # Test 2: Root domain als Target
    print("\n\nTest 2: Target = publbee.com (root domain)")
    config2 = ScopeConfig(allowed_targets=["publbee.com"])
    guard2 = ScopeGuard(config2)
    
    test_cases_2 = [
        ("publbee.com", True, "root domain"),
        ("www.publbee.com", True, "www variant"),
        ("api.publbee.com", True, "subdomain"),
    ]
    
    for target, expected, description in test_cases_2:
        result = guard2.is_in_scope(target)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {description}: {target} -> {result}")
    
    print("\n" + "="*50)
    print(guard2.get_scope_summary())

if __name__ == "__main__":
    test_scope_guard()
