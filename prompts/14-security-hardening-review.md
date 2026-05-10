# Prompt 14 - Security Hardening Review

```text
Fuehre einen sicherheitsorientierten Review des bisherigen Umbaus durch. Arbeite mit Tests, nicht nur mit Text.

Ziel: Finde und schliesse Luecken, die fuer eine oeffentliche Demo kritisch waeren.

Pruefe insbesondere:
- echte Datei-/Secret-Zugriffe,
- Outbound Requests,
- Shell-Ausfuehrung,
- Origin/CORS,
- Session-ID-Handling,
- Event Queue Isolation,
- Admin-/Reset-Endpunkte,
- Token-/Log-Scrubbing,
- Manifest-Validierung,
- `.example` Domains fuer Mock-Kommunikation,
- Public Mode Defaults.

Erst Tests schreiben oder erweitern:
1. `tests/security/test_no_real_secret_paths.py`
   - Statische Suche/Policy-Test gegen verbotene Pfadmuster.
2. `tests/security/test_no_unsafe_subprocess.py`
   - Kein `subprocess` fuer Demo-Input.
3. `tests/security/test_no_arbitrary_outbound.py`
   - NetworkGuard wird bei allen URL-Fetch-Simulationen verwendet.
4. `tests/security/test_origin_and_cors.py`
   - Wildcard Origin im Public Mode abgelehnt.
5. `tests/security/test_log_scrubbing.py`
   - Token-artige Werte werden in Telemetrie/Logs gescrubbt.

Dann fixes implementieren.

Akzeptanzkriterien:
- Alle Security Tests laufen.
- `docs/security-review.md` enthaelt Findings, Fixes und Rest-Risiken.
- README enthaelt klare Warnung: Demo nur mit Mock-Daten und sicheren Defaults betreiben.
```

Erwarteter Commit:

```text
security: harden public demo defaults
```
