# Prompt 13 - Demo UI und Docker Deployment

```text
Arbeite test-first.

Ziel: Baue eine kleine Web-Demo und ein sicheres lokales Deployment. Fokus auf Bedienbarkeit, nicht auf grosses Frontend.

Sicherheitsgrenzen:
- Keine Admin-Funktion ohne Schutz im Public Mode.
- Kein Debug Mode in Docker Default.
- Kein eingebauter echter API Key.

Erst Tests schreiben:
1. `tests/integration/test_demo_ui.py`
   - `/demo` zeigt Liste der Experimente.
   - Jedes Experiment kann mit `vulnerable` und `defended` gestartet werden, sofern unterstuetzt.
   - Ergebnis enthaelt JSON und Event-Timeline.
2. `tests/integration/test_healthz.py`
   - `/healthz` funktioniert.
   - `/readyz` prueft Registry/Manifeste.
3. `tests/security/test_public_mode_guards.py`
   - Reset/Admin Endpoint erfordert Admin Token oder ist disabled.
   - Debug Tracebacks sind disabled.
   - Origin-Allowlist ist nicht wildcard im Public Mode.

Dann implementieren:
- Server-rendered HTML Templates oder sehr simples statisches Frontend.
- `Dockerfile`
- `.dockerignore`
- `docker-compose.yml` fuer lokale Demo.
- `docs/deployment.md`

Akzeptanzkriterien:
- Lokale Demo startet per `docker compose up`.
- UI ist ohne externe CDN-Abhaengigkeit nutzbar oder faellt sauber zurueck.
- Docker laeuft nicht als root, falls praktikabel.
- Public Mode hat sichere Defaults.
```

Erwarteter Commit:

```text
feat: add demo UI and local Docker deployment
```


## Observable Impact Requirement

The UI must include an `Observable Impact` panel for every experiment. The panel must link to the exact demo artifact: mock inbox entry, telemetry JSONL line, sandbox file, demo DB row, or session-leak event. It must also include a Reset button that deletes artifacts for the current demo session.
