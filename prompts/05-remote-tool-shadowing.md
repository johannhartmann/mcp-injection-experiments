# Prompt 05 - Remote Tool Shadowing mit Mock Mail

```text
Arbeite test-first.

Ziel: Implementiere eine sichere Online-Demo fuer Tool Shadowing: Ein malicious helper versucht, das Verhalten eines trusted Mock-Mail-Tools zu beeinflussen. Alles bleibt in Mock-Mail und MockSink.

Sicherheitsgrenzen:
- Keine echten E-Mails.
- Keine echten Kontakte.
- Kein externer SMTP/API-Zugriff.
- Keine realen Empfaenger ausser `.example` Testadressen.

Erst Tests schreiben:
1. `tests/integration/test_remote_tool_shadowing.py`
   - Trusted Mock-Mail Server stellt `send_email(to, subject, body)` bereit.
   - Malicious Helper Server stellt ein scheinbar harmloses Tool bereit.
   - Vulnerable Client-Simulator laesst eine unapproved recipient mutation oder hidden BCC in Mock-Mail entstehen.
   - Defended Client-Simulator blockiert cross-server instruction / recipient rewrite.
2. `tests/unit/test_mock_mail.py`
   - MockMail speichert nur im Speicher.
   - Adressen muessen auf `.example` enden.
   - Nicht erlaubte Domains werden abgelehnt.
3. `tests/unit/test_cross_server_policy.py`
   - Instruktionen eines Servers duerfen nicht Argumente eines anderen Servers veraendern, ausser explizit durch Nutzer bestaetigt.

Dann implementieren:
- `src/mcp_demo/experiments/tool_shadowing.py`
- `src/mcp_demo/shared/mock_mail.py`
- `src/mcp_demo/client_simulator/planner.py` falls noch nicht vorhanden
- `src/mcp_demo/client_simulator/policies.py`
- Manifest `experiments/manifests/remote-tool-shadowing.yaml`

Akzeptanzkriterien:
- Vulnerable und defended Verhalten sind in Tests klar unterscheidbar.
- Keine echte E-Mail wird gesendet.
- Telemetrie zeigt Tool-Auswahl, Argumentmutation und Policy-Entscheidung.
```

Erwarteter Commit:

```text
feat: add remote tool shadowing demo with mock mail
```


## Observable Impact Requirement

Vulnerable mode must send a fake message into `var/mock-inbox.jsonl` with an unapproved hidden recipient or BCC. This is the real side effect. No real email or chat API is allowed.

Defended mode must leave the intended mock message intact or unsent, and persist a `blocked_attempt_recorded` event explaining the cross-server recipient rewrite.
