# Demo-Skript

Drei Setups: 15-Minuten-Pitch, 30-Minuten-Deep-Dive und der typische
Q&A-Pool. Alle Run-Befehle setzen `uv run uvicorn ...` lokal voraus
(siehe [`docs/deployment.md`](deployment.md)).

## 15-Minuten-Demo

Ziel: Einer Audience zeigen, dass MCP-Tool-Beschreibungen, Cross-Server-
Trust und Session-Bindings wirklich kaputt gehen koennen, *und* dass die
Defenses mit kleinem Aufwand funktionieren.

| Min | Schritt | Notizen |
|---|---|---|
| 0:00 | Intro: "MCP ist neu, Angriffe sind alt" | Tool-Poisoning, Tool-Shadowing, Rug Pull, Confused Deputy. |
| 1:00 | Browser auf `http://127.0.0.1:8000/demo` | Karten pro Experiment, OWASP-Mapping, Run-Buttons. |
| 2:30 | `direct-poisoning` -> vulnerable | Canary erscheint in `/demo/events` mit `mock_exfiltration`. |
| 4:00 | `direct-poisoning` -> defended | Selbe Aktion, aber `policy_decision: canary_exfiltration_policy`. |
| 5:30 | `tool-shadowing` -> vulnerable | Hidden BCC in `var/mock-inbox.jsonl` zeigen (HTML-Timeline reicht). |
| 7:00 | `tool-shadowing` -> defended | `cross_server_instruction_policy` blockt; Begruendung sichtbar. |
| 8:30 | `auth-confused-deputy` | FAKEJWT mit falscher Audience; vulnerable mutiert Fake-CRM, defended liefert `audience_mismatch`. |
| 10:30 | `cross-session-context-leak` | Bob sieht Alice's Canary in Session B; defended blockt. |
| 12:00 | "Wo bleiben die Effekte?" | `var/telemetry.jsonl`, `var/mock-inbox.jsonl`, `sandbox/effects/`. |
| 13:00 | Safety-Modell zusammenfassen | keine echten Tokens, keine Outbound-Requests, alles Mock. |
| 14:00 | Q&A-Buffer | siehe Abschnitt unten. |

## 30-Minuten-Deep-Dive

Erweitert die 15-Minuten-Variante um:

- `sleeper-rug-pull` und `registry-rug-pull` mit Hash-Diff-/Permission-
  Delta-Anzeige im Block-Event.
- `ssrf-metadata` mit Mock-Resolver, der `metadata.attacker.example` auf
  `169.254.169.254` mappt; `socket`/`urllib`-Monkeypatch im Test-Auszug
  zeigen, dass kein echter Request rausgeht.
- `sampling-abuse` mit Budget-Counter und scripted FakeLLM-Antwort.
- Code-Lesen: `shared/policy.py` als Linter-Beispiel; `client_simulator/
  policies.py` mit Argument-Diff und Cross-Server-Origin-Check.
- Tests anschauen: `uv run pytest tests/security/ -v` zeigt die statischen
  Wachposten (kein `~/.ssh`, kein `subprocess`, kein `requests`, kein
  Wildcard-Origin im Public Mode, Token-Scrubbing).
- Kurzer Schwenk in `docs/security-review.md` mit den vier akzeptierten
  Restrisiken.
- Public-Mode-Demo: `DEMO_PUBLIC_MODE=true` ohne `admin_token`-Override
  startet **nicht** -> Ausfuehrlich vorzeigen, weil das die wichtigste
  Selbstverteidigung der Demo ist.

## Was nicht live gezeigt wird

- **Kein echter Mail-/Chat-/OAuth-/Registry-Provider.** Empfaenger sind
  ausschliesslich `.example`. Die Frage "Schickst du das wirklich an Gmail?"
  beantwortet die `MockMailServer.send_email`-Validation: `MockMailRecipientError`.
- **Kein echtes LLM.** `shared/fake_llm.FakeLLM.complete` liefert zwei
  fest verdrahtete Strings. Es gibt keinen Provider-API-Key.
- **Kein RCE-Beweis ueber GUI-Calc.** `run_local_calc_proof` hat keine
  Argumente und ist standardmaessig deaktiviert. Public Hosting setzt
  `DEMO_ENABLE_LOCAL_CALC_PROOF=false`. Der Demo-Effekt ist immer eine
  Datei unter `sandbox/effects/`.
- **Kein echtes SSRF.** `MockResolver` mappt Hostnames in-memory; der
  Klassifikator blockt Cloud-Metadata-IPs auch dann, wenn die Allowlist
  `*` enthielte. `socket.getaddrinfo` ist im Test gepatcht.

## Typische Fragen

- *"Werden hier echte E-Mails gesendet?"* Nein. Der `MockMailServer`
  refused alles, was nicht im `.example`-TLD liegt, und es gibt keinen
  SMTP-Code. Tests asserten via `smtplib`-Monkeypatch, dass kein
  Outbound-Pfad existiert.
- *"Was passiert, wenn der Demo-Server gehackt wird?"* `var/telemetry.jsonl`
  und `var/mock-inbox.jsonl` enthalten ausschliesslich Demo-Canaries,
  keine echten Tokens. Der `FAKEJWT`-Issuer hat keinen kryptographischen
  Wert. Die Sandbox enthaelt eine Datei mit der String
  `CANARY_DEMO_FAKE_SECRET_DO_NOT_USE_FOR_REAL_AUTH`.
- *"Wie blockiert ihr Tool-Beschreibungen?"* `lint_tool_description`
  erkennt `<IMPORTANT>`-Bloecke, "do not mention"-Phrasen, Credential-
  Path-Referenzen und Cross-Tool-Argument-Rewrites. `sanitise_tool_
  description` zeigt im defended Mode die bereinigte Variante in
  `tools/list`.
- *"Wie verhindert ihr Replay/Hijack?"* `Mcp-Session-Id` ist
  `secrets.token_urlsafe(24)`, prozessweit eindeutig, **nicht** als Auth
  zu verwenden. State ist nach `(user_id, session_id)` partitioniert.
  Origin-Check ist Pflicht.
- *"Wo sind die Defaults dokumentiert?"* `src/mcp_demo/config.py` und
  `docs/deployment.md`. Public Mode laeuft nur durch
  `validate_for_public_mode()` (admin_token != "local-dev",
  allowed_origins != "*", nicht leer).

## Reset zwischen Demo-Runs

```bash
TOKEN="${DEMO_ADMIN_TOKEN:-local-dev}"
curl -s -X POST http://127.0.0.1:8000/demo/reset \
  -H 'Origin: http://127.0.0.1:8000' \
  -H "X-Demo-Admin-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"sess-a"}'
```

JSONL-Audit-Trails bleiben absichtlich erhalten - Reset wirkt nur auf
In-Memory-Events. Fuer einen vollstaendigen Reset Container neu starten;
`docker-compose.yml` mountet `var/` als `tmpfs`.
