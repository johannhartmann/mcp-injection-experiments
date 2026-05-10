# Deployment Checklist

## Lokal

- [ ] `python -m venv .venv`
- [ ] Dependencies installiert.
- [ ] `pytest` erfolgreich.
- [ ] `uvicorn mcp_demo.app:app --host 127.0.0.1 --port 8000` funktioniert.
- [ ] `/healthz` antwortet.
- [ ] `/demo` zeigt die UI.
- [ ] `/mcp/...` akzeptiert nur erlaubte Origins.

## Public Demo

- [ ] Hinter HTTPS Reverse Proxy.
- [ ] Admin-/Reset-Endpunkte geschuetzt.
- [ ] CORS/Origin-Allowlist restriktiv.
- [ ] Egress deny by default.
- [ ] Keine echten API Keys in Umgebung.
- [ ] Logs ohne sensible Bodies.
- [ ] Ressourcenlimits gesetzt.
- [ ] Rate Limits gesetzt.
- [ ] Keine Debug Tracebacks fuer Nutzer.
- [ ] Demo-Daten werden regelmaessig geloescht.
