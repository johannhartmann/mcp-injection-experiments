# Security Review

Stand: nach Schritt 14 (Hardening). Dieser Review fasst die wichtigsten
Befunde, die umgesetzten Fixes und die offenen Restrisiken zusammen.

## Methodik

- Statische Suche im `src/`-Baum nach verbotenen Pfad-/Token-Mustern.
- Statische Suche nach Subprocess-/Eval-Pfaden und nach direkten
  Outbound-Library-Aufrufen.
- HTTP-Integrationstests fuer Origin-Check, Public-Mode-Validation und
  Reset-Endpoint.
- End-to-End-Tests fuer Token-Scrubbing in der Telemetrie.

Die Tests liegen unter `tests/security/`. `uv run pytest tests/security/`
laeuft ohne Netzwerk.

## Befunde + Fixes

### Datei-/Secret-Zugriffe

- **Befund**: kein `~/.ssh`, `~/.cursor`, `~/.aws`, `.env`, `id_rsa`,
  `mcp.json` o.ae. in `src/` ausserhalb der zwei Module, die diese
  Muster *erkennen* sollen (`shared/policy.py`, `shared/mock_filesystem.py`).
- **Fix**: `tests/security/test_no_real_secret_paths.py` mit Allowlist,
  wacht ueber `src/` insgesamt.

### Subprocess / Eval

- **Befund**: kein `os.system`, `subprocess`, `os.exec*`, `os.popen`,
  `eval` oder `exec` in `src/`.
- **Fix**: `tests/security/test_no_unsafe_subprocess.py` als statischer
  Wachtest. Der einzige Subprocess-Anker (`ImpactRunner.run_local_calc_proof`)
  nimmt **keine Argumente** und ist nur durch die ENV
  `DEMO_ENABLE_LOCAL_CALC_PROOF=true` aktivierbar. Tests asserten den
  Default-off.

### Outbound HTTP

- **Befund**: kein Modul in `src/` benutzt `requests`, `httpx`,
  `urllib.request.urlopen`, `http.client.HTTP*Connection` oder
  `import socket`.
- **Fix**: `tests/security/test_no_arbitrary_outbound.py`. SSRF-/Fetch-
  Simulationen nutzen ausschliesslich `MockResolver` plus `classify_url`.
  Pro Experiment-Test gibt es einen `socket.getaddrinfo`/`urllib.request.urlopen`
  Monkeypatch, der einen `AssertionError` raised, falls das Experiment
  doch hinausgeht.

### Origin / CORS

- **Befund**: alle `/mcp/*`- und `/demo/*`-Routen pruefen `Origin` gegen
  `DemoSettings.allowed_origins`. Default-Allowlist enthaelt nur
  `http://127.0.0.1:8000`, `http://localhost:8000` und
  `http://testserver`.
- **Fix**: `tests/security/test_origin_and_cors.py` deckt fremden Origin,
  fehlenden Origin und Wildcard im Public Mode ab.
- **Public Mode**: `DemoSettings.validate_for_public_mode()` raised, wenn
  der Allowlist `*` enthaelt, wenn die Liste leer ist oder wenn
  `admin_token` noch der Default `local-dev` ist.

### Session-ID-Handling

- **Befund**: Session-ID wird ausschliesslich mit
  `secrets.token_urlsafe(24)` erzeugt. Folge-Requests ohne gueltige
  Session-ID werden mit JSON-RPC `-32001/-32002` abgewiesen. Session-ID
  ist explizit *keine* Authentication.
- **Fix**: `tests/integration/test_streamable_http_initialize.py` und
  `tests/security/test_origin_and_cors.py::test_origin_check_does_not_trust_session_id_alone`.

### Event-Queue-Isolation

- **Befund**: `PartitionedSessionStore` und `EventQueue` partitionieren
  per `(user_id, session_id)`. Event-IDs sind prozessweit eindeutig.
- **Fix**: `tests/unit/test_session_store.py`,
  `tests/integration/test_event_queue_partitioning.py`,
  `tests/integration/test_cross_session_context_leak.py`.

### Admin- / Reset-Endpoint

- **Befund**: `POST /demo/reset` verlangt `X-Demo-Admin-Token`. Default
  ist `local-dev`; Public Mode verweigert den Start, falls dieser nicht
  ueberschrieben wird.
- **Fix**: `tests/security/test_public_mode_guards.py`.

### Token-/Log-Scrubbing

- **Befund**: `shared/telemetry.scrub_payload` redacted Bearer-Tokens
  (mind. 16 Zeichen), GitHub-PATs (`gh[pousr]_...`), OpenAI-`sk-` Keys,
  und `api[_-]?key=`/`token=`/`secret=`/`password=` Assignments. Demo-
  Canaries (`CANARY_*`) bleiben sichtbar.
- **Fix**: `tests/security/test_log_scrubbing.py`,
  `tests/unit/test_telemetry_contract.py`,
  `tests/unit/test_mock_sink.py::test_sink_scrubs_obvious_token_patterns`.

### Manifest-Validierung

- **Befund**: `ExperimentManifest` (pydantic strict) refused
  `uses_real_secrets=true`, `safe_mode=false`, fehlende `entrypoint` und
  Entrypoints ausserhalb `/mcp/`. Die Registry weist invalide Manifeste
  beim Laden zurueck.
- **Fix**: `tests/unit/test_manifest_schema.py`.

### `.example`-Domains fuer Mock-Kommunikation

- **Befund**: `MockMailServer` akzeptiert ausschliesslich Empfaenger im
  `.example`-TLD. Tests asserten zusaetzlich, dass kein `smtplib`
  verwendet wird (Monkeypatch).
- **Fix**: `tests/unit/test_mock_mail.py`.

### Public Mode Defaults

- **Befund**: Default-Defaults (lokal): `bind_host=127.0.0.1`,
  `egress_mode=deny`, `admin_token=local-dev`, `public_mode=False`,
  Allowlist auf Loopback. Public Mode aktiviert `validate_for_public_mode`
  und verweigert unsichere Defaults.
- **Fix**: `tests/security/test_public_mode_guards.py`,
  `tests/security/test_origin_and_cors.py`.

## Restrisiken

Folgende Punkte sind **bewusst** akzeptiert oder in spaeteren Schritten
naeher zu betrachten:

- **Mock-Inbox JSONL** (`var/mock-inbox.jsonl`) speichert Nachrichten-
  bodies *roh* (ohne Scrubbing). Das ist Absicht, weil die Inbox als
  forensisches Demo-Artefakt dient. Jeder Pfad, der dieses File via
  Telemetry oder UI ausspielt, durchlaeuft `scrub_payload` zuerst.
- **Lokaler Calc-Proof** (`run_local_calc_proof`): aktiviert per ENV,
  niemals aus User-Input getriggert. Public Hosting darf
  `DEMO_ENABLE_LOCAL_CALC_PROOF` nie auf `true` setzen; das ist im
  Deployment-Doku ausdruecklich notiert.
- **Rate-Limits / Abuse-Schutz**: nicht im Code; muessen vom Reverse-
  Proxy/Hosting-Layer kommen. `docs/deployment.md` haelt das fest.
- **Session-Eviction**: `PartitionedSessionStore` ist lazy-evicted bei
  Lookup. Lange ungenutzte Sessions bleiben bis zum naechsten Zugriff
  im Speicher; in einer langlebigen Public-Demo sollte ein Hintergrund-
  Sweep ergaenzt werden.
- **Browser-CSRF gegen `/demo/scenario/<id>`**: Origin-Check schuetzt
  vor cross-origin-Aufrufen aus dem Browser. Wenn ein Public-Mode-
  Deployment hinter HTTPS in einer `*.example.com`-Domain laeuft und
  ein Angreifer die Allowlist-Domain ebenfalls kontrolliert, koennte
  ein Browser-Tab dort eine Demo-Session ausloesen. Der Effekt bleibt
  in jedem Fall innerhalb der Demo-Zone (kein echter Side-Effect),
  aber Operatoren sollten die Allowlist eng halten.
