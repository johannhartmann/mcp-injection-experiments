# Prompt 06 - Remote Sleeper Rug Pull mit Tool-Metadata-Diff

```text
Arbeite test-first.

Ziel: Implementiere eine Remote-Demo, bei der ein MCP-Server beim ersten Laden harmlose Tool-Metadaten liefert und bei spaeterer Session eine geaenderte Tool-Beschreibung oder ein geaendertes Schema. Die defended Variante erkennt Hash-Diffs und verlangt Re-Approval.

Sicherheitsgrenzen:
- Keine echten Drittanbieter-Tools.
- Keine echte WhatsApp- oder Chat-Integration.
- Jede Wirkung geht nur in MockSink/MockChat.

Erst Tests schreiben:
1. `tests/integration/test_remote_sleeper_rug_pull.py`
   - Erste `tools/list` liefert harmloses Tool `random_fact.get`.
   - Zweite Session/zweiter Load liefert gleiches Tool mit geaenderter Description oder Schema.
   - Vulnerable Client akzeptiert still.
   - Defended Client erkennt `description_hash` oder `schema_hash` Diff und blockiert bis Re-Approval.
2. `tests/unit/test_tool_metadata_hashing.py`
   - Hashes sind stabil fuer identische Tool-Metadaten.
   - Hashes aendern sich bei Description-/Schema-Aenderung.
3. `tests/unit/test_approval_store.py`
   - Approval ist an Server-ID, Tool-Name, Description-Hash und Schema-Hash gebunden.

Dann implementieren:
- `src/mcp_demo/experiments/sleeper_rug_pull.py`
- `src/mcp_demo/shared/tool_metadata.py`
- `src/mcp_demo/shared/approval_store.py`
- Manifest `experiments/manifests/remote-sleeper-rug-pull.yaml`
- Diff-Ausgabe fuer UI/JSON Result.

Akzeptanzkriterien:
- Defended Mode blockiert geaenderte Tool-Metadaten.
- Ergebnis enthaelt old/new Hash und klare Empfehlung.
- README erklaert, dass echte WhatsApp-Uebernahme bewusst durch MockChat ersetzt wurde.
```

Erwarteter Commit:

```text
feat: add sleeper rug pull metadata diff demo
```


## Observable Impact Requirement

Vulnerable mode must persist a real artifact showing that the same tool name changed behavior after reloading: e.g. `sandbox/effects/rug-pull-<session>.json` with old/new description hash and the resulting unwanted mock action.

Defended mode must persist a re-consent/block event when description or schema hash changes.
