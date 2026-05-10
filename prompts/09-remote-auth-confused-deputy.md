# Prompt 09 - Auth Confused Deputy und Token Passthrough Simulation

```text
Arbeite test-first.

Ziel: Implementiere eine sichere Fake-OAuth-Demo fuer Confused Deputy und Token Passthrough. Keine echten Provider, keine echten Tokens. Nutze signierte oder klar als Fake markierte Testtokens.

Sicherheitsgrenzen:
- Keine echten OAuth Provider.
- Keine echten JWT Secrets.
- Keine echten Redirects zu externen Domains.
- Keine echten Access Tokens speichern.

Erst Tests schreiben:
1. `tests/unit/test_fake_tokens.py`
   - Fake Token enthaelt `aud`, `sub`, `client_id`, `scope`.
   - Token mit falscher Audience wird im defended Mode abgelehnt.
   - Abgelaufenes Token wird abgelehnt.
2. `tests/unit/test_consent_registry.py`
   - Consent ist an `user_id`, `client_id`, `redirect_uri`, `scopes` gebunden.
   - Geaenderte Redirect URI erzwingt Re-Consent.
   - Consent fuer Client A gilt nicht fuer Client B.
3. `tests/integration/test_auth_confused_deputy.py`
   - Vulnerable Proxy akzeptiert Token/Consent zu breit.
   - Defended Proxy verlangt Audience `mcp-demo-server` und per-client consent.

Dann implementieren:
- `src/mcp_demo/experiments/auth_confused_deputy.py`
- `src/mcp_demo/shared/auth_mock.py`
- `src/mcp_demo/shared/consent.py`
- Manifest `experiments/manifests/remote-auth-confused-deputy.yaml`

Akzeptanzkriterien:
- Alles ist Fake/In-Memory.
- Defended Mode prueft Audience, Expiry, Client-ID, Redirect-URI und Scopes.
- Ergebnis erklaert klar, warum Token Passthrough blockiert wurde.
```

Erwarteter Commit:

```text
feat: add fake OAuth confused deputy demo
```


## Observable Impact Requirement

Vulnerable mode must apply a real fake-state change, such as modifying a Fake-CRM record or granting a fake permission with a token whose audience should not have been accepted.

Defended mode must reject the token and write a block event with the failed audience/client/scope check.
