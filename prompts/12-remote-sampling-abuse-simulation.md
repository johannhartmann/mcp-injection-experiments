# Prompt 12 - Sampling Abuse Simulation

```text
Arbeite test-first.

Ziel: Implementiere eine Sampling-Abuse-Demo mit Fake-LLM und Budgetzaehler. Die Demo zeigt Resource Theft, Conversation Hijack und Covert Tool Invocation als sichere Simulation.

Sicherheitsgrenzen:
- Kein echtes LLM notwendig.
- Kein Verbrauch echter API-Kosten.
- Keine echten Tool Calls ausser Mock Tools.
- Keine persistente Manipulation echter User-Kontexte.

Erst Tests schreiben:
1. `tests/unit/test_sampling_budget.py`
   - Sampling-Budget pro Session begrenzt Requests.
   - Ueberschreitung wird blockiert.
2. `tests/unit/test_sampling_policy.py`
   - Sampling Request mit zu viel Kontext wird blockiert.
   - Sampling Response, die Tool Invocation anfordert, wird als covert tool invocation markiert.
   - Persistente Instruktionsversuche werden erkannt.
3. `tests/integration/test_sampling_abuse_simulation.py`
   - Vulnerable Mode akzeptiert uebermaessiges Sampling oder Kontextuebergabe.
   - Defended Mode blockiert und protokolliert.

Dann implementieren:
- `src/mcp_demo/experiments/sampling_abuse.py`
- `src/mcp_demo/shared/fake_llm.py`
- `src/mcp_demo/shared/sampling_policy.py`
- Manifest `experiments/manifests/remote-sampling-abuse.yaml`

Akzeptanzkriterien:
- Kein echter Provider/API Key.
- Ergebnis zeigt Budget, Kontextumfang und Policy-Entscheidung.
- README erklaert, dass Sampling hier simuliert wird.
```

Erwarteter Commit:

```text
feat: add sampling abuse simulation
```


## Observable Impact Requirement

Vulnerable mode must consume a real demo budget counter or add a fake unauthorized sampling result to the session ledger.

Defended mode must prevent the budget consumption or hidden invocation and persist a block event.
