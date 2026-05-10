# Prompt 10 - SSRF Metadata Discovery Simulation

```text
Arbeite test-first.

Ziel: Implementiere eine SSRF-Demo fuer OAuth-/Metadata-Discovery als reine Simulation mit Mock-Resolver. Der Code darf keine echten Requests an private, link-local oder User-gelieferte Ziele senden.

Sicherheitsgrenzen:
- Kein echter Fetch zu User-URLs.
- Kein Request an private IPs, loopback, link-local oder Cloud-Metadata.
- Keine DNS-Aufloesung fremder Domains in Tests.

Erst Tests schreiben:
1. `tests/unit/test_url_safety.py`
   - `https://auth.example/.well-known/oauth-authorization-server` ist erlaubt, wenn `auth.example` explizit erlaubt ist.
   - `http://` wird in Production Mode abgelehnt.
   - Private IPv4/IPv6, loopback und link-local werden abgelehnt.
   - Redirect zu internem Ziel wird abgelehnt.
   - DNS TOCTOU wird durch Resolver-Pinning simuliert.
2. `tests/integration/test_ssrf_metadata_simulation.py`
   - Vulnerable Mode wuerde laut Simulation ein internes Ziel anfragen.
   - Defended Mode blockiert vor dem Fetch.
   - Es findet kein echter Netzwerkrequest statt.

Dann implementieren:
- `src/mcp_demo/experiments/ssrf_metadata.py`
- `src/mcp_demo/shared/url_safety.py`
- `src/mcp_demo/shared/mock_resolver.py`
- Manifest `experiments/manifests/remote-ssrf-metadata-discovery.yaml`

Akzeptanzkriterien:
- Tests koennen ohne Internet laufen.
- MockResolver ist die einzige Quelle fuer Ziel-IP-Entscheidungen.
- Ergebnis zeigt Entscheidungspfad: URL -> resolved IP -> policy decision.
```

Erwarteter Commit:

```text
feat: add SSRF metadata discovery simulation
```


## Observable Impact Requirement

Vulnerable mode may only use the MockResolver, but it must persist a clear event showing that the client would have fetched a forbidden metadata target. No real request to private/link-local/cloud metadata addresses is allowed.

Defended mode must persist a `blocked_attempt_recorded` event with the resolver classification.
