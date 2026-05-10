# Prompt 07 - Remote Registry Rug Pull und Pinning

```text
Arbeite test-first.

Ziel: Simuliere Supply-Chain-/Registry-Risiken mit einer lokalen Fake-Registry. Ein Server-Manifest ist in v1 harmlos und in v2 geaendert. Defended Client blockiert bei ungepinnten oder veraenderten Tool-Metadaten.

Sicherheitsgrenzen:
- Keine echte MCP Registry.
- Kein Download beliebiger URLs.
- Keine Installation fremder Pakete aus Demo-Daten.

Erst Tests schreiben:
1. `tests/unit/test_fake_registry.py`
   - Registry liefert Manifest v1 und v2 aus lokalen Fixtures.
   - Manifest enthaelt Server-ID, Version, Tool-Hashes.
   - Ungueltige Manifeste werden abgelehnt.
2. `tests/integration/test_registry_rug_pull.py`
   - Vulnerable Client installiert `latest` und akzeptiert v2 still.
   - Defended Client pinnt Version und Tool-Hashes.
   - Defended Client blockiert Permission-Delta und Tool-Hash-Diff.
3. `tests/unit/test_permission_delta.py`
   - neue Tool-Permissions werden erkannt.
   - breitere Scopes werden erkannt.

Dann implementieren:
- `src/mcp_demo/experiments/registry_rug_pull.py`
- `src/mcp_demo/shared/fake_registry.py`
- `src/mcp_demo/shared/pinning.py`
- Fixtures unter `tests/fixtures/registry/`
- Manifest `experiments/manifests/remote-registry-rug-pull.yaml`

Akzeptanzkriterien:
- Kein Netzwerkinstall.
- Registry ist komplett lokal/in-memory.
- UI/JSON zeigt old/new Version, Tool-Hash-Diffs, Permission-Deltas.
```

Erwarteter Commit:

```text
feat: add fake registry rug pull demo
```


## Observable Impact Requirement

Vulnerable mode must install or activate the changed fake registry entry and create a local demo artifact that records the changed permission or tool hash.

Defended mode must refuse activation unless the version/hash/permission delta is explicitly approved, and must write a block event.
