#!/usr/bin/env python3
"""
Integration Test: Kompletter ReAct Loop mit Katana
"""

import sys
sys.path.insert(0, '/Users/nezir/Documents/Projects/fatih')

from src.core.orchestrator import Orchestrator

def test_full_integration():
    """Teste kompletten Orchestrator mit Katana"""
    print("=== Full Integration Test ===\n")
    print("Dieser Test startet den Orchestrator und führt einen Katana-Crawl durch.")
    print("Hinweis: Docker Container muss laufen!\n")
    
    # Ziel-URL (verwende httpbin.org als sicheres Test-Ziel)
    target = "https://httpbin.org"
    
    print(f"Starte Assessment für: {target}")
    print("-" * 50)
    
    try:
        # Orchestrator initialisieren (max 3 Iterationen für Test)
        orchestrator = Orchestrator(target_url=target, max_iterations=3)
        
        # Manuell einen Katana-Scan ausführen
        from src.core.security import ScopeConfig, ScopeGuard
        from src.tools.web.katana import KatanaTool
        
        scope_config = ScopeConfig(
            allowed_targets=["httpbin.org"],
            allow_localhost=False,
            allow_private_ips=False
        )
        scope_guard = ScopeGuard(scope_config)
        katana = KatanaTool(scope_guard)
        
        print("\nFühre Katana Crawl durch...")
        result = katana.run(target, mode="standard", depth=2)
        
        print(f"\n✓ Crawl abgeschlossen!")
        print(f"  Endpoints gefunden: {result['total_count']}")
        
        if result['endpoints']:
            print("\n  Gefundene Endpoints:")
            for ep in result['endpoints'][:5]:  # Zeige nur erste 5
                print(f"    - {ep.endpoint_type.value}: {ep.url}")
        
        # In StateManager speichern
        orchestrator.state_manager.complete_crawl(target, result.get('sitemap'))
        for endpoint in result['endpoints']:
            orchestrator.state_manager.add_web_endpoint(target, endpoint)
        
        # Report exportieren
        orchestrator.export_report("outputs/test_katana_report.json")
        print(f"\n✓ Report gespeichert: outputs/test_katana_report.json")
        
        # State Summary anzeigen
        summary = orchestrator.state_manager.get_summary()
        print(f"\nSession Summary:")
        print(f"  - Hosts: {summary['hosts_discovered']}")
        print(f"  - Web Hosts: {len(orchestrator.state_manager.session.web_hosts)}")
        print(f"  - Aktionen: {summary['actions_executed']}")
        
        print("\n🎉 Integration Test erfolgreich!")
        
    except Exception as e:
        print(f"\n❌ Fehler: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    test_full_integration()
