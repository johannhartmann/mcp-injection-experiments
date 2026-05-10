# Operations

Diese Notiz zaehlt die Stellschrauben fuer einen Reviewer oder Operator,
der die Demo lokal oder oeffentlich (hinter Reverse-Proxy) betreibt.

## Sichere Defaults

`mcp_demo.config.DemoSettings`:

| Feld | Default | Wirkung |
|---|---|---|
| `bind_host` | `127.0.0.1` | Server bindet auf Loopback. Fuer Container `0.0.0.0` setzen, aber nur via Compose `127.0.0.1:8000:8000` exponieren. |
| `bind_port` | `8000` | |
| `egress_mode` | `deny` | NetworkGuard refused per Default jede Outbound-URL. |
| `allowed_origins` | `127.0.0.1:8000`, `localhost:8000`, `testserver` | Origin-Allowlist fuer alle `/mcp/*` und `/demo/*`-Routen. |
| `admin_token` | `local-dev` | Pflicht-Header `X-Demo-Admin-Token` fuer `/demo/reset`. |
| `public_mode` | `False` | Wenn `True`, validiert `validate_for_public_mode` die Settings beim App-Build. |

ENV-Overrides: `DEMO_BIND_HOST`, `DEMO_BIND_PORT`, `DEMO_EGRESS_MODE`,
`DEMO_ALLOWED_ORIGINS` (komma-separiert), `DEMO_ADMIN_TOKEN`,
`DEMO_PUBLIC_MODE` (`true|1|yes`).

## Public Mode

Pflichtbedingungen, sonst raised `DemoSettings.validate_for_public_mode`:

- `admin_token` ist nicht leer und nicht `local-dev`.
- `allowed_origins` ist nicht leer und enthaelt kein `*`.

Empfohlener Workflow:

```bash
export DEMO_PUBLIC_MODE=true
export DEMO_ADMIN_TOKEN="$(openssl rand -base64 32)"
export DEMO_ALLOWED_ORIGINS="https://demo.example.com"
docker compose up -d
```

Ein Reverse-Proxy (Caddy, Traefik, nginx) terminiert HTTPS und leitet
nur die Pfade weiter, die die Demo wirklich braucht (`/demo/*`,
`/mcp/*`, `/healthz`, `/readyz`).

## Reset

`POST /demo/reset` loescht in-memory Events fuer eine Session. JSONL-
Audit-Trails (`var/telemetry.jsonl`, `var/mock-inbox.jsonl`) bleiben
append-only. Vollstaendiger Reset:

```bash
docker compose restart
# oder, wenn lokal ausserhalb des Containers:
rm -f var/telemetry.jsonl var/mock-inbox.jsonl sandbox/effects/*
```

Die Standard-`docker-compose.yml` mountet `var/` und `sandbox/effects/`
als `tmpfs`, sodass jeder Container-Restart bereits einen vollstaendigen
Reset bedeutet.

## Logging

- `mcp_demo.shared.telemetry.scrub_payload` redacted in jeder Render-
  Pfad-Stelle Bearer / GitHub-PAT / `sk-` / `api[_-]?key=`-Muster. Demo-
  Canaries (`CANARY_*`) werden absichtlich nicht entfernt.
- `var/telemetry.jsonl` ist append-only. Es enthaelt nur ImpactEvents
  aus dem `ImpactRunner`/`ImpactLedger`-Pfad. Mock-Inbox-Bodies werden
  in `var/mock-inbox.jsonl` *roh* abgelegt, weil das das forensische
  Demo-Artefakt ist; die HTML-/JSON-Dashboard-Sicht laeuft nicht ueber
  diese Datei, sondern ueber die TelemetryView, die scrub_payload
  anwendet.
- Uvicorn laeuft im Container mit `--no-access-log`, damit keine HTTP-
  Bodies in stdout landen.

## Rate Limits

Es gibt keinen built-in Rate Limiter. Fuer eine oeffentliche Demo den
Reverse-Proxy konfigurieren:

```nginx
limit_req_zone $binary_remote_addr zone=mcp_demo:10m rate=20r/s;
location / {
    limit_req zone=mcp_demo burst=40 nodelay;
    proxy_pass http://127.0.0.1:8000;
}
```

oder Caddy `rate_limit`. Die Demo selbst tut absichtlich nichts hier -
das gehoert in den Hosting-Layer.

## Troubleshooting

| Symptom | Ursache | Fix |
|---|---|---|
| `403 origin not allowlisted` | `Origin` fehlt oder nicht in der Liste. | Header setzen: `Origin: http://127.0.0.1:8000`. |
| `400 -32001 SESSION_REQUIRED` | Kein `Mcp-Session-Id` nach `initialize`. | `initialize` zuerst, Header weiter mitsenden. |
| `400 -32002 SESSION_INVALID` | Sessionid nicht bekannt (z. B. Server-Restart). | Erneut `initialize`. |
| `401 admin_token_required` | Reset ohne Token. | `X-Demo-Admin-Token: $DEMO_ADMIN_TOKEN`. |
| `ValueError: ... unsafe for public deployment` | `DEMO_PUBLIC_MODE=true` mit unsicheren Settings. | Token + Allowlist setzen. |
| `MockResolverError` bei SSRF-Demo | Hostname nicht in `MockResolver.records`. | Resolver-Map erweitern oder Test-Fixture nutzen. |
| `MockMailRecipientError` | Empfaenger nicht im `.example`-TLD. | Demo-Empfaenger im `.example`-TLD waehlen; in vulnerable Modes ist das gewollt der Block. |
| `pytest` schlaegt fehl mit `ModuleNotFoundError: mcp_demo` | Editable Install nicht synchronisiert. | `uv sync --reinstall-package mcp-demo --all-extras`. |
| `docker compose up` haengt | Healthcheck wartet auf `/healthz`. | Im Container: `python -m uvicorn mcp_demo.app:create_app --factory --host 0.0.0.0`. Port-Konflikt? `docker compose down`. |

## Wartung

- `uv sync --all-extras` aktualisiert die Lockfile, wenn `pyproject.toml`
  veraendert wird.
- `uv run pytest` ist der einzige Vertragstest. Vor jedem Tag-/Release-
  Schritt ausfuehren.
- `docs/security-review.md` enthaelt die akzeptierten Restrisiken;
  bei einem neuen Experiment dort einen Eintrag ergaenzen.
