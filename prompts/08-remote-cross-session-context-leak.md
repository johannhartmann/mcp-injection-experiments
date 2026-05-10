# Prompt 08 - Cross-Session Context Leak fuer Streamable HTTP

```text
Arbeite test-first.

Ziel: Implementiere eine Remote-Demo fuer Cross-Client-/Cross-Session-Leaks. Zwei Demo-Sessions bekommen unterschiedliche Canaries. Die vulnerable Variante nutzt versehentlich globalen State; die defended Variante isoliert nach `user_id:session_id`.

Sicherheitsgrenzen:
- Nur Demo-Canaries.
- Keine echten Nutzerprofile.
- Session-ID ist keine Authentisierung.

Erst Tests schreiben:
1. `tests/integration/test_cross_session_context_leak.py`
   - Session A bekommt Canary A.
   - Session B bekommt Canary B.
   - Vulnerable Mode kann Canary A in Ergebnis von B sichtbar machen.
   - Defended Mode verhindert Cross-Session-Leak.
2. `tests/unit/test_session_store.py`
   - State wird nach `user_id:session_id` partitioniert.
   - Session-ID allein reicht nicht fuer Zugriff auf anderen User-State.
   - abgelaufene Sessions werden entfernt.
3. `tests/integration/test_event_queue_partitioning.py`
   - Events fuer A werden nicht an B ausgeliefert.
   - Resumable/SSE Event IDs werden nicht streamuebergreifend wiederverwendet.

Dann implementieren:
- `src/mcp_demo/experiments/cross_session_leak.py`
- `src/mcp_demo/shared/session_store.py`
- `src/mcp_demo/shared/event_queue.py`
- Manifest `experiments/manifests/remote-cross-session-context-leak.yaml`

Akzeptanzkriterien:
- Tests zeigen eine kontrollierte verwundbare Simulation und eine sichere Variante.
- Defended Mode bindet State an User + Session.
- Telemetrie markiert Cross-Session-Leak-Versuch.
```

Erwarteter Commit:

```text
feat: add cross-session context leak demo
```


## Observable Impact Requirement

Vulnerable mode must make the leak visible across two demo clients: Client B receives or displays Client A's Canary through the HTTP/SSE/session path. This is allowed because the canary is fake and session-scoped.

Defended mode must prove isolation by showing separate session ledgers and a `blocked_attempt_recorded` or `no_cross_session_leak` event.
