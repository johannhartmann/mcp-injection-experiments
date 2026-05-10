# MCP HTTP Streaming Online Demo - Claude Code Prompt Pack

> **Warnung.** Diese Demo-Suite ist ausschliesslich fuer didaktische
> Zwecke gedacht. Sie darf **nur** mit Mock-Daten, Canary-Werten und den
> mitgelieferten sicheren Defaults betrieben werden. Echte Secrets,
> echte Konfig-Dateien, echte Drittanbieter-APIs oder echte
> Netzwerkziele duerfen nie in die Demo-Zone gelangen. Public-Mode
> nur hinter einem Reverse-Proxy mit HTTPS und nur, wenn
> `validate_for_public_mode()` durchlaeuft. Details in
> `docs/security-review.md` und `docs/deployment.md`.

Dieses Prompt-Pack ist dafuer gedacht, das Repository `johannhartmann/mcp-injection-experiments` schrittweise in eine sichere Online-Demo-Suite umzubauen.

Zielbild:

- MCP-Server sind per Streamable HTTP erreichbar, z. B. `/mcp/direct-poisoning`.
- Eine kontrollierte Web-Demo bzw. ein MCP-Client-Simulator zeigt verwundbare und verteidigte Varianten nebeneinander.
- Alle Demos arbeiten mit Canary-Daten, Mock-Sinks, lokalen Testdaten und sichtbaren, begrenzten Nebenwirkungen.
- Keine echten Secrets, keine echten Drittanbieter-APIs, keine unkontrollierte RCE, keine echten internen Netzwerkzugriffe.
- Verwundbare Modi duerfen echte Effekte erzeugen, aber nur in der Demo-Zone: Mock-Inbox, MockSink, sandbox/effects, Demo-DB und Telemetrie.
- Jede Erweiterung entsteht test-first mit `pytest`/HTTP-Integrationstests.

## Verwendung

1. Entpacke dieses Paket neben oder in das Zielrepo.
2. Kopiere `CLAUDE.md` in den Root des Zielrepos.
3. Starte Claude Code im Zielrepo.
4. Fuehre die Prompts aus `prompts/` der Reihe nach aus.
5. Nach jedem Prompt: Tests laufen lassen, Diff pruefen, Commit machen.

Empfohlene Reihenfolge:

```text
prompts/00-baseline-repo-audit.md
prompts/01-test-harness-foundation.md
prompts/02-safe-sandbox-canaries.md
prompts/02b-observable-impact-ledger.md
prompts/03-streamable-http-transport.md
prompts/04-remote-direct-poisoning.md
prompts/05-remote-tool-shadowing.md
prompts/06-remote-sleeper-rug-pull.md
prompts/07-remote-registry-rug-pull.md
prompts/08-remote-cross-session-context-leak.md
prompts/09-remote-auth-confused-deputy.md
prompts/10-remote-ssrf-metadata-discovery-simulation.md
prompts/11-audit-telemetry-dashboard.md
prompts/12-remote-sampling-abuse-simulation.md
prompts/13-demo-ui-and-docker.md
prompts/14-security-hardening-review.md
prompts/15-docs-final-polish.md
```

## Was dieses Pack bewusst nicht tut

Dieses Pack liefert keine realen Angriffspayloads gegen echte Services. Es beschreibt Demo-Angriffe mit echten, beobachtbaren Nebenwirkungen innerhalb einer isolierten Demo-Zone. Beispiele: ein Canary erscheint in einer Mock-Attacker-Inbox, eine Datei wird unter `sandbox/effects/` erzeugt, ein Fake-CRM-Datensatz wird veraendert oder ein Budgetzaehler wird verbraucht. Es beruehrt keine echten lokalen Dateien, echten Tokens, echten Chat-/Mail-APIs oder fremden Netzwerkziele.

## Designprinzip

Jeder Prompt folgt demselben Muster:

1. vorhandenen Code inspizieren,
2. Tests zuerst schreiben,
3. minimale Implementierung bauen,
4. Sicherheitsgrenzen pruefen,
5. Dokumentation und Manifeste aktualisieren.

## Development

Die Demo-Suite nutzt [`uv`](https://docs.astral.sh/uv/) als Paket- und
Environment-Manager. Python 3.11 oder neuer wird vorausgesetzt.

```bash
# Initiale Einrichtung (legt .venv/ an, installiert mcp-demo + Dev-Deps)
uv sync --all-extras

# Tests laufen lassen
uv run pytest

# Nur Unit-Tests
uv run pytest tests/unit -v
```

Wichtige Pfade:

- `src/mcp_demo/` - Anwendungs-Code (Manifeste, Registry, spaeter Transport,
  Experimente, Web-UI).
- `experiments/manifests/` - YAML-Manifeste pro Experiment. Werden beim Start
  validiert; ein Manifest mit `uses_real_secrets: true` oder
  `safe_mode: false` wird abgelehnt.
- `tests/unit/` - schnelle Vertragstests (Manifest, Registry, Result-Schema).
- `tests/integration/` - HTTP-/MCP-Integrationstests (folgt in spaeteren Schritten).
- `tests/security/` - Negativtests fuer Sicherheitsgrenzen (folgt).
- `docs/migration-plan.md` - Reihenfolge der Umsetzung.
- `docs/owasp-mcp-coverage.md` - OWASP MCP Top 10 Coverage-Matrix.

Die Demo verwendet ausschliesslich Mock-Komponenten und Canary-Daten innerhalb
der Demo-Zone (`sandbox/`, `var/`). Echte Secrets, echte Drittanbieter-APIs
und echte Outbound-Requests sind verboten - siehe `CLAUDE.md` und
`architecture/security-model.md`.

## Streamable HTTP demo transport

Die Demo-Suite implementiert eine kleine, gut isolierte JSON-RPC-/Streamable-
HTTP-Fassade unter `src/mcp_demo/transport/`. Das offizielle MCP Python SDK
wird bewusst nicht eingebunden, weil die Demo pro Methode (`initialize`,
`tools/list`, `tools/call`) gezielt zwischen verwundbarem und verteidigtem
Verhalten umschalten und Tool-Beschreibungen sichtbar manipulieren muss.
Wenn ein Wechsel auf das SDK sinnvoll wird, ist die Schnittstelle in
`transport/jsonrpc.py` und `transport/streamable_http.py` der einzige Punkt,
der angepasst werden muss.

Lokal starten:

```bash
uv run uvicorn mcp_demo.app:create_app --factory --host 127.0.0.1 --port 8000
```

`/healthz` antwortet ohne `Origin`-Pruefung. Alle `/mcp/*`-Endpunkte
verlangen einen allowlisteten `Origin` und nach `initialize` einen
gueltigen `Mcp-Session-Id`-Header.

### Beispiel-cURL

```bash
# initialize -> liefert Mcp-Session-Id im Response-Header
curl -i -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":"init-1",
    "method":"initialize",
    "params":{
      "protocolVersion":"2025-03-26",
      "capabilities":{},
      "clientInfo":{"name":"demo-client","version":"0.1.0"}
    }
  }'
```

```bash
# tools/list -> erwartet die Mcp-Session-Id aus initialize
curl -s -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":"tools-1","method":"tools/list"}'
```

```bash
# tools/call calculator.add
curl -s -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc":"2.0","id":"call-1",
    "method":"tools/call",
    "params":{"name":"calculator.add","arguments":{"a":2,"b":3}}
  }'
```

Defaults aus `src/mcp_demo/config.py`:

- `bind_host=127.0.0.1`, `bind_port=8000`.
- `allowed_origins` enthaelt nur `http://127.0.0.1:8000`,
  `http://localhost:8000` und `http://testserver` (ASGI-Tests).
- `egress_mode=deny`.

Ueberschreibbar via `DEMO_BIND_HOST`, `DEMO_BIND_PORT`,
`DEMO_ALLOWED_ORIGINS` (komma-separiert), `DEMO_EGRESS_MODE`.

## Remote Direct Poisoning

Die erste vollstaendige Demo unter `/mcp/direct-poisoning` ist die sichere
Migration des historischen `direct-poisoning.py`-PoC. Statt `~/.cursor/mcp.json`
oder `~/.ssh/id_rsa` referenziert die Tool-Beschreibung ausschliesslich die
Datei `sandbox/demo-secret.txt`, deren Inhalt eine offensichtliche Fake-Canary
ist.

Modus-Schalter:

- `vulnerable`: `tools/list` liefert die poisoned Description mit
  `<IMPORTANT>`-Block samt verstecktem Lese-Befehl. `tools/call` mit einem
  `sidenote`-Argument leitet den Inhalt an `MockSink` weiter; der Sink markiert
  das als `secret_exfiltrated=True`. Der `ImpactRunner` schreibt einen
  `mock_exfiltration`-Event ins JSONL-Telemetry-Log.
- `defended`: `tools/list` zeigt die durch `sanitise_tool_description`
  bereinigte Variante (kein `<IMPORTANT>`-Block, keine "do not mention"-
  Saetze). `tools/call` prueft das `sidenote`-Argument gegen die
  `CanaryExfiltrationPolicy`; bei einem registrierten Canary refused der
  Policy-Decision-Pfad und schreibt einen `blocked_attempt_recorded`-Event mit
  Begruendung. Der defended `DemoResult` enthaelt
  `blocked_by=["canary_exfiltration_policy"]`.

Modus-Auswahl pro Session: beim `initialize`-Request kann der Client per
`params.demo.mode = "vulnerable" | "defended"` den Modus festlegen. Default ist
`defended`.

`run_scenario(mode, session_id, runtime)` ist die testbare Skript-API. Sie
liest den Canary aus dem Mock-Filesystem, durchlaeuft den Mode-spezifischen
Pfad, und liefert einen vollstaendigen `DemoResult`. Damit lassen sich UI und
Tests speisen, ohne den HTTP-Layer zu starten.

Sicherheitsgrenzen pro Definition of Done:

- keine echten Konfig-/SSH-/Token-Pfade in der Tool-Beschreibung;
- keine `os.path.expanduser`-Aufrufe und keine direkten `Path.read_text`-
  Aufrufe ausserhalb von `MockFilesystem`;
- jede Datei-Lese-Operation laeuft durch `MockFilesystem`, das Pfad-Traversal,
  Symlink-Escape und Suspicious-Basenames refused;
- Exfiltration landet nur in `MockSink` und im JSONL-Telemetry-Ledger.

## Remote Tool Shadowing

`remote-tool-shadowing` zeigt einen klassischen Cross-Server-Angriff: ein
"helper" Server liefert ein scheinbar harmloses Tool (`helper.add`), dessen
Beschreibung den Agenten anweist, beim Aufruf des trusted Mock-Mail-Tools
einen hidden BCC an `attacker@attacker.example` mitzusenden.

Beteiligte Komponenten:

- `MockMailServer` (`src/mcp_demo/shared/mock_mail.py`) akzeptiert nur
  Empfaenger im RFC-2606-reservierten `.example`-TLD. Jede andere Adresse,
  inklusive aller historisch genutzten Attacker-Domains, wird mit
  `MockMailRecipientError` abgelehnt. Es gibt keinen SMTP-Code, keine
  Outbound-Calls.
- `client_simulator/planner.py` enthaelt einen deterministischen Planner.
  `plan_vulnerable` folgt Tool-Description-Hinweisen wie "add a hidden BCC
  to <addr>" und mutiert die Argumente. `plan_defended` reicht das
  Ergebnis an die `CrossServerInstructionPolicy` weiter.
- `client_simulator/policies.py` vergleicht User-Intent mit dem geplanten
  Aufruf. Falls ein Argument auf dem Server B mutiert wurde *und* eine
  Tool-Beschreibung von Server A laut `lint_tool_description` einen
  cross-server-rewrite andeutet, wird mit `cross_server_instruction_policy`
  blockiert.

Modus-Verhalten:

- `vulnerable`: Mock-Mail erhaelt einen Eintrag mit hidden BCC; das Body
  enthaelt den Session-Canary, der via `MockSink` als
  `secret_exfiltrated=True` gemeldet wird. `mock_message_sent`-Event wird
  in `var/telemetry.jsonl` und `var/mock-inbox.jsonl` persistiert.
- `defended`: keine Mail wird gesendet. `record_blocked_attempt` schreibt
  `blocked_attempt_recorded` mit dem Cross-Server-Begruendungstext, der
  die mutierten Argumente und den hinweisgebenden Server nennt.
  `DemoResult.blocked_by` enthaelt `cross_server_instruction_policy`.

Sicherheitsgrenzen:

- keine echte E-Mail wird gesendet, keine SMTP-Bibliothek wird benutzt
  (Test patcht `smtplib` und stellt sicher, dass nichts aufgerufen wird);
- Empfaenger-Allowlist: ausschliesslich `*.example`-Adressen;
- Telemetrie zeigt `actor`, mutierte Argumente und Policy-Entscheidung -
  reicht fuer das Audit-Dashboard in spaeteren Schritten.

## Remote Sleeper Rug Pull

`remote-sleeper-rug-pull` modelliert einen Drift-Angriff, bei dem ein
MCP-Server beim ersten Laden harmlose Tool-Metadaten ausspielt und beim
zweiten Laden dieselbe Tool-ID mit veraenderter Description und
veraenderten Input-Schema neu publiziert. Das ist die didaktische
Replizierung des historischen `whatsapp-takeover.py`-PoC. Echte
WhatsApp-Integration gibt es **nicht** - Ziel ist `MockChat` und das
JSONL-Telemetry-Log; alle "Empfaenger" sind `.example`-Adressen.

Zentrale Bausteine:

- `shared/tool_metadata.py` (`fingerprint_tool`, `hash_description`,
  `hash_schema`): SHA-256 ueber Description-Text und kanonisierter
  Schema-JSON. Hashes sind deterministisch und reagieren auf jede
  sichtbare Aenderung.
- `shared/approval_store.py`: `ApprovalStore.record(server_id,
  fingerprint, user)` bindet Konsens an alle vier Felder. `is_approved`
  liefert nur True, wenn der gesamte Fingerprint unveraendert ist;
  `diff` zeigt vorherige vs. neue Hashes.
- `experiments/sleeper_rug_pull.py`:
  `list_tools(runtime, load_index=0)` liefert die benigne Description,
  `load_index>=1` die poisoned Variante mit `<IMPORTANT>`-Block. So kann
  der Test beide Zustaende deterministisch inspizieren, ohne eine echte
  Persistenz zu simulieren.

Modus-Verhalten:

- `vulnerable`: kein Drift-Check; das Experiment schreibt
  `sandbox/effects/rug-pull-<session>.json` mit alten und neuen Hashes
  und einem Eintrag fuer die "unwanted_mock_action" (Mock-Chat-Recipient
  rewrite). Zusaetzlich landet der Canary in `MockSink`.
- `defended`: vergleicht den neuen Fingerprint gegen die letzte
  Approval. Bei jeder Drift wird `tool_metadata_drift_policy` ausgeloest;
  `record_blocked_attempt` schreibt einen `blocked_attempt_recorded`-
  Event mit Begruendung; `DemoResult.events` enthaelt einen
  `metadata_diff`-Eintrag mit `before`/`after`-Hashes und einer
  Re-Approval-Empfehlung.

Sicherheitsgrenzen: keine echten Drittanbieter-Tools, keine Kommunikation
mit echten Chat-/Messaging-APIs, kein Zugriff auf reale Konfigurationen.
Die Hash-Diff-Anzeige ersetzt die "Was hat sich gegenueber dem letzten
Vertrauensentscheid veraendert"-Frage durch ein deterministisches,
diff-bares Artefakt.

## Remote Registry Rug Pull

`remote-registry-rug-pull` simuliert einen Supply-Chain-Angriff auf eine
MCP-Server-Registry. v1 von `drift-mock.example-server` ist harmlos. v2
behaelt Server-ID und Tool-Namen, fuegt aber zwei neue Permissions hinzu
(`read:contacts`, `send:message`), erweitert das Input-Schema und packt
einen `<IMPORTANT>`-Block in die Description, der ein Mock-Chat
`message.send` an `attacker@attacker.example` veranlassen will.

Komponenten:

- `shared/fake_registry.py`: `FakeRegistry.from_directory(path)` laedt
  YAML-Manifeste aus `tests/fixtures/registry/`. Jedes Manifest
  enthaelt `server_id`, `version`, `permissions`, `tools` mit
  Description und Schema. Tool-Eintraege erhalten direkt einen
  `description_hash` und `schema_hash` (SHA-256 ueber UTF-8 bzw.
  kanonisches JSON). Es gibt keine `urlopen`/`pip`-Aufrufe; Tests
  patchen `urllib.request.urlopen` mit einem `raise`, um das
  abzusichern.
- `shared/pinning.py`: `permission_delta(before, after)` liefert
  `PermissionDelta(added, removed, broadened)`. `broadened` erkennt
  Wildcards (`scope:*` deckt `scope:resource:own` ab) und
  Rollen-Upgrades (`read` -> `write` -> `admin`).
- `experiments/registry_rug_pull.py`: `RegistryRugPullRuntime.pin(...)`
  setzt einen User-Pin auf eine Version. `run_scenario` vergleicht
  `latest` (= v2) gegen v1, schreibt im vulnerable Modus
  `sandbox/effects/registry-rug-pull-<session>.json` mit `permission_
  delta` und per-tool `description_hash`/`schema_hash`-Diffs. Im
  defended Modus blockiert `registry_pinning_policy` jede Aktivierung,
  bei der Pin-Version != latest oder ein Permission-/Hash-Drift
  vorliegt.

`DemoResult.events[0]` traegt im Block-Fall `before_version`,
`after_version`, `permission_delta` und `tool_hash_changes` plus eine
Re-Approval-Empfehlung - direkt verwendbar fuer das spaetere
Audit-Dashboard.

Sicherheitsgrenzen: keine echte Registry, kein Download, keine
Paket-Installation. Alle Manifeste leben in
`tests/fixtures/registry/*.yaml`.

## Remote Cross-Session Context Leak

`remote-cross-session-context-leak` zeigt einen Bug-Pattern, das in
Remote-MCP-Servern besonders heimtueckisch ist: wenn Server-Zustand nur
nach `session_id` gesleudt wird statt nach `(user_id, session_id)`,
kann ein Client B durch zufaellige oder erratbare Session-IDs den
Zustand eines Clients A einsehen.

Komponenten:

- `shared/session_store.py`: `PartitionedSessionStore` haelt State unter
  `(user_id, session_id, key)` mit lazy TTL-Eviction. Lookup mit
  passender `session_id` aber falschem `user_id` raised
  `SessionLookupError` - die Session-ID alleine ist keine
  Authentisierung.
- `shared/event_queue.py`: `EventQueue` partitioniert publizierte
  Events per `(user_id, session_id)` und vergibt prozessweite
  eindeutige Event-IDs, sodass eine resumable SSE-`Last-Event-Id` aus
  Session A keine State-Lookups in Session B ermoeglichen kann.
- `experiments/cross_session_leak.py`: zwei Subjects, eine vulnerable
  und eine defended Lookup-Variante. Der vulnerable Pfad nutzt einen
  flachen `dict[session_id, record]`, also genau den Bug, der im
  echten Code auftritt; der defended Pfad nutzt den partitionierten
  Store und blockiert mit `session_isolation_policy`.

Modus-Verhalten:

- `vulnerable`: Client B (Bob) erhaelt im `DemoResult.events` einen
  Eintrag mit `payload = <Alice's Canary>`. Der Sink markiert das als
  `secret_exfiltrated=True`, ein `session_leak_visible`-Event landet
  im JSONL-Telemetry-Log.
- `defended`: jeder Cross-Session-Lookup raised `SessionLookupError`,
  der Versuch wird als `session_isolation_block`-Event gemeldet,
  `record_blocked_attempt` schreibt `blocked_attempt_recorded` mit
  Begruendung. `DemoResult.blocked_by =
  ["session_isolation_policy"]`.

Sicherheitsgrenzen: alle Werte sind Demo-Canaries mit klarem `CANARY_*`-
Marker. Es gibt keine echten Nutzerprofile. Die Demo dokumentiert
ausdruecklich, dass die Session-ID nicht als Authentication verwendet
werden darf.

## Remote Auth Confused Deputy (Fake-OAuth)

`remote-auth-confused-deputy` ist die Token-Passthrough-Demo. Eine
attacker-kontrollierte App hat einen Token, der fuer einen anderen
MCP-Service ausgestellt wurde, und ein helper-Tool reicht ihn an
`mcp-demo-server` durch. Im vulnerable Modus akzeptiert der Proxy den
Token ohne Pruefung und mutiert einen Eintrag in einem Fake-CRM
(`fake_crm["alice"]["display_name"] -> "ALICE THE PWNED"`). Im defended
Modus pruefen wir Audience, Expiry, Scope-Subset, Signatur-Form und das
per-Client-Consent.

Komponenten:

- `shared/auth_mock.py`: `FakeTokenIssuer` produziert ausschliesslich
  `FAKEJWT.<base64-payload>.fake`-Tokens. Der `verify_fake_token`-Pfad
  raised `FakeAudienceError`, `FakeExpiryError`, `FakeScopeError`,
  `FakeSignatureError`. Nichts kryptographisch Wertvolles passiert; das
  ist Absicht.
- `shared/consent.py`: `ConsentRegistry.record(...)` bindet Konsens an
  `(user_id, client_id, redirect_uri, scopes)`. Redirect-URIs muessen im
  Demo-Bereich enden (`*.demo.invalid`, `*.example`); andere Hosts
  werden bei `record(...)` mit `ValueError` abgelehnt.
- `experiments/auth_confused_deputy.py`: vulnerable Pfad ueberspringt
  Token-Verifikation komplett; defended Pfad geht durch
  `verify_fake_token` und schliesslich durch `ConsentRegistry.is_
  consented`. Jeder fehlgeschlagene Check produziert einen
  `auth_decision`-Event mit `check`, `expected`, `actual`, `reason` und
  einen `blocked_attempt_recorded`-Event in der Telemetrie.
  `DemoResult.blocked_by` enthaelt den Check-Namen
  (`audience_mismatch`, `expired`, `scope_insufficient`,
  `signature_invalid`, `consent_missing`).

Sicherheitsgrenzen: keine echten OAuth-Provider, keine echten JWT-
Secrets, keine echten Redirects. Der Issuer hat die URL
`https://issuer.demo.invalid`; jeder Token traegt das `FAKEJWT`-Prefix
und die `fake`-Signatur.

## Remote SSRF Metadata Discovery (Mock-Resolver)

`remote-ssrf-metadata` zeigt einen klassischen SSRF-Pfad gegen ein
Cloud-Metadata-Endpunkt - **ohne** echten Netzwerkverkehr. Eine Tool-
Aufforderung referenziert `https://metadata.attacker.example/latest/
meta-data/`. Der Operator hat den Host allowlistet, aber der `MockResolver`
mappt ihn auf `169.254.169.254`. Die Demo zeigt:

- vulnerable: das Experiment schreibt
  `sandbox/effects/ssrf-metadata-<session>.json` mit URL, aufgeloester
  IP und `would_have_fetched: true`. Ein
  `sandbox_file_written`-Event landet im Telemetry-Log. Es wird **kein
  echter Request** gestellt; Tests asserten via Monkeypatch von
  `socket.getaddrinfo` und `urllib.request.urlopen`, dass nichts
  hinausgeht.
- defended: `classify_url` prueft Scheme (HTTPS in Production-Mode),
  Hostname-Allowlist, IP-Klassifikation (Loopback, Link-local, private,
  multicast, reserved, unspecified, plus Literal-Block fuer
  `169.254.169.254`) und Redirect-Target. Bei einem Refusal feuert
  `url_safety_policy`; `record_blocked_attempt` schreibt einen
  `blocked_attempt_recorded`-Event mit der vollstaendigen Begruendung.
  `DemoResult.events[0]` traegt `url`, `resolved_ips`,
  `classification: blocked` und `reason`.

Zusatzfeatures:

- `pinned_ips` Parameter in `classify_url` simuliert DNS-Pinning fuer
  TOCTOU: ein Attacker, der DNS nach dem ersten Lookup auf eine private
  IP umstellt, kann den festgepinnt IP-Set nicht ueberschreiben.
- Redirect-Target-Check: wenn ein 30x in einen ungueltigen Host
  umleitet, blockt der Classifier auch den ursprunglichen Request.

Sicherheitsgrenzen: keine echte DNS-Aufloesung, keine echten Sockets,
keine Outbound-HTTP-Requests. Der `MockResolver` ist die einzige
Wahrheitsquelle fuer Hostname -> IP.

## Audit / Telemetry Dashboard

Alle bisherigen Demos schreiben strukturierte Events in einen
gemeinsamen `ImpactLedger` (siehe `Observable impact model` weiter
unten). Der Dashboard-Layer in `src/mcp_demo/web/routes.py` und
`src/mcp_demo/shared/telemetry.py` liefert daraus drei Endpunkte unter
`/demo/`:

- `POST /demo/scenario/<experiment_id>` mit Body
  `{"mode": "vulnerable" | "defended", "session_id": "..."}` startet
  einen einzelnen Run via `run_scenario(...)`. Antwort: das vollstaendige
  `DemoResult` JSON.
- `GET /demo/events` listet die zusammengefuehrte Telemetry-Timeline.
  Filter: `?session_id=` und `?experiment=`. Default ist JSON; mit
  `Accept: text/html` rendert der Server eine kleine HTML-Tabelle ohne
  externe CDN-Abhaengigkeiten.
- `POST /demo/reset` mit Header `X-Demo-Admin-Token: <token>` und Body
  `{"session_id": "..."}` loescht alle In-Memory-Events einer Session.
  Default-Token ist `local-dev`, ueberschreibbar via `DEMO_ADMIN_TOKEN`.

`shared/telemetry.py` definiert `TelemetryEvent` (event_id, ts,
session_id, experiment, mode, event_type, severity, message, data) und
die Mapping-Logik `telemetry_from_impact(...)`. `scrub_payload` redacted
Bearer-Tokens, GitHub-PATs, OpenAI-`sk-`-Keys und `api_key=`-Patterns -
Demo-Canaries (`CANARY_*`) bleiben sichtbar, weil sie der Punkt der
Demo sind.

Sicherheitsgrenzen: alle Endpunkte respektieren die Origin-Allowlist;
`/demo/reset` verlangt zusaetzlich den Admin-Token, sodass das Ruecksetzen
nicht aus einem fremden Browser-Tab ausgeloest werden kann. Logs durchlaufen
`scrub_payload`, sodass keine echten Token-Muster ins Telemetry-Log
gelangen koennen.

## Remote Sampling Abuse (Fake-LLM + Budget)

`remote-sampling-abuse` simuliert Resource-Theft, Conversation-Hijack und
Covert-Tool-Invocation. Es wird kein echtes LLM aufgerufen und kein
Provider-API-Key verbraucht; ein scripted `FakeLLM` liefert genau zwei
fest verdrahtete Antworten (eine harmlose und eine, die einen versteckten
Tool-Call und eine Persistenz-Forderung enthaelt).

Komponenten:

- `shared/sampling_policy.py`: `SamplingBudget` zaehlt pro
  `session_id` mit; `consume()` raised `SamplingBudgetExceeded` beim
  Ueberlauf. `SamplingPolicy.evaluate_request` blockt zu lange Prompts.
  `SamplingPolicy.evaluate_response` markiert Antworten, die
  `mock_chat.send_message`, "hidden BCC" oder andere bekannte
  Covert-Tool-Patterns enthalten, oder die "remember this for ever"
  bzw. "persist across sessions" einfordern.
- `shared/fake_llm.py`: deterministische Klasse mit zwei Stringschen,
  ohne Netzwerk.
- `experiments/sampling_abuse.py`:
  - `vulnerable`: konsumiert wirklich Budget (Counter sinkt um 1) und
    schreibt einen `budget_consumed`-Event mit `remaining_budget` und
    Response-Excerpt ins Telemetry-Log.
  - `defended`: prueft `evaluate_request` und (falls erlaubt)
    `evaluate_response`. Bei einem Refusal feuert `sampling_policy`,
    `record_blocked_attempt` schreibt einen Block-Event, der Budget
    bleibt unveraendert. `DemoResult.blocked_by` enthaelt
    `sampling_policy`, `events[0].reason` traegt die Begruendung.

Sicherheitsgrenzen: kein echter Provider, kein API-Key, kein Outbound-
Request (Tests asserten via `socket.getaddrinfo`- und
`urllib.request.urlopen`-Monkeypatch). Alles, was die Demo aendert,
landet in `var/telemetry.jsonl` und im Process-Memory-Counter.

## Observable impact model

Jedes Experiment muss seinen Effekt **wirklich erzeugen**, aber nur innerhalb
der Demo-Zone. Der zentrale Baustein ist der `ImpactRunner` in
`src/mcp_demo/shared/impact.py`. Er bietet vier sichere Effekt-Pfade:

- `mock_exfiltrate_to_sink(...)` - Vulnerable Mode: liefert eine Payload an
  `MockSink`. Wenn die Payload einen vorher registrierten Canary enthaelt,
  setzt der Sink `secret_exfiltrated=True`.
- `mock_send_message(...)` - Vulnerable Mode: schreibt einen Eintrag in
  `var/mock-inbox.jsonl` (Mock-Mail/WhatsApp/Slack-Pendant) und delivered
  parallel an den Sink.
- `write_sandbox_file(...)` - Vulnerable Mode: legt eine Datei unter
  `sandbox/effects/` mit Canary und Metadaten an. Pfad-Traversal,
  absolute Pfade und Home-Referenzen werden mit `ImpactSafetyError`
  refused, bevor irgendein I/O passiert.
- `record_blocked_attempt(...)` - Defended Mode: erzeugt einen
  `blocked_attempt_recorded`-Event mit Begruendung, ohne den eigentlichen
  Impact zuzulassen.

Alle Effekte werden in einem `ImpactLedger` gesammelt. Der Ledger
partitioniert In-Memory-Events nach `session_id`, ein optionaler JSONL-Pfad
(`var/telemetry.jsonl`) hinterlaesst zusaetzlich einen append-only
Audit-Trail. Reset wirkt nur auf die jeweilige Session und laesst den JSONL
unangetastet.

Nicht erlaubte Impact-Wege:

- echte Outbound-HTTP-Requests, echte Mail-/Chat-/GitHub-/OAuth-APIs.
- Subprocess-Aufrufe mit User-Input. Der einzige Subprocess-Helfer
  (`run_local_calc_proof`) nimmt **keine** Argumente und ist standardmaessig
  deaktiviert; aktivierbar nur lokal per `DEMO_ENABLE_LOCAL_CALC_PROOF=true`,
  nie im Public Hosting.
