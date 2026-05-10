# Deployment

Diese Demo-Suite ist in zwei Modi nutzbar: lokal (Default) und hinter einem
Reverse-Proxy als oeffentliche Demo. Lokal ist die einfachere Variante und
sollte fuer alles ausserhalb einer kontrollierten Demo-Umgebung der Default
sein. Public Mode ist ausschliesslich fuer geplante, ueberwachte Vortrags-/
Workshop-Deployments gedacht.

## Lokal

```bash
uv sync --all-extras
uv run uvicorn mcp_demo.app:create_app --factory --host 127.0.0.1 --port 8000
```

Anschliessend:

- `http://127.0.0.1:8000/demo` zeigt die Experiment-Liste.
- `http://127.0.0.1:8000/demo/events` zeigt die Telemetry-Timeline.
- `http://127.0.0.1:8000/healthz` und `/readyz` liefern Status.

## Lokal via Docker

```bash
docker compose up --build
```

`docker-compose.yml` setzt Defaults, die fuer lokale Entwicklung sicher sind:

- bindet im Container auf `0.0.0.0:8000`, publisht aber nur an
  `127.0.0.1:8000` auf dem Host;
- `DEMO_EGRESS_MODE=deny`, `DEMO_ADMIN_TOKEN=local-dev`,
  `DEMO_ALLOWED_ORIGINS=http://127.0.0.1:8000,http://localhost:8000`;
- Container laeuft als unprivilegierter User (`mcp`, UID 10001), `read_only`
  Filesystem mit `tmpfs` fuer `var/` und `sandbox/effects/`;
- `cap_drop: ALL` und `no-new-privileges`.

## Public Mode

Fuer eine oeffentlich erreichbare Workshop-Demo:

1. Einen Reverse-Proxy mit HTTPS davorstellen (Caddy, Traefik, nginx, ...).
2. Die folgenden Variablen explizit setzen:
   ```bash
   export DEMO_PUBLIC_MODE=true
   export DEMO_ADMIN_TOKEN="$(openssl rand -base64 32)"
   export DEMO_ALLOWED_ORIGINS="https://demo.example.com"
   ```
3. `create_app(...)` ruft `DemoSettings.validate_for_public_mode()` und
   verweigert den Start, falls `admin_token` noch der Default `local-dev`
   ist oder `*` in der Allowlist steht.
4. Den Container hinter dem Proxy starten:
   ```bash
   docker compose up -d
   ```
5. `DEMO_ENABLE_LOCAL_CALC_PROOF` muss in Public Hosting auf `false`
   bleiben. Der Local-Calc-Proof startet nie aus User-Input und ist nur
   fuer lokale Demos vorgesehen.

## Reset

`POST /demo/reset` mit Body `{"session_id": "..."}` und Header
`X-Demo-Admin-Token: <token>` loescht die In-Memory-Events einer Session.
JSONL-Audit-Trails (`var/telemetry.jsonl`, `var/mock-inbox.jsonl`) bleiben
append-only. Fuer ein vollstaendiges Reset einfach das `var/`-Volume
loeschen oder den Container neu starten - Compose mountet `var/` als
`tmpfs`.

## Logs / Datenschutz

- Logs durchlaufen `mcp_demo.shared.telemetry.scrub_payload`. Bearer-,
  GitHub-, OpenAI- und `api_key=`-Muster werden redacted; `CANARY_*`-
  Marker bleiben sichtbar.
- Es gibt keine persistente Sammlung echter Nutzerdaten.
- Sessions sind kurzlebig und nur fuer den jeweiligen Demo-Run sinnvoll.
