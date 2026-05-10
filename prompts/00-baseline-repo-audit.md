# Prompt 00 - Baseline Repo Audit und Migrationsplan

Kopiere diesen Prompt in Claude Code im Root des Zielrepos.

```text
Du arbeitest in diesem Repository als sicherheitsorientierter Senior Python Engineer.

Ziel: Erstelle zuerst einen Repo-Audit und einen inkrementellen Migrationsplan fuer eine sichere MCP Streamable HTTP Online-Demo. Implementiere noch keine grosse Architektur.

Kontext:
- Das Repo enthaelt historische MCP Tool Poisoning Snippets.
- Ziel ist eine sichere Online-Demo mit Streamable HTTP, Mock-Sinks, Canary-Daten und vulnerable/defended Modi.
- Keine echten Secrets, keine echte Exfiltration, keine echte RCE, keine echten Drittanbieter-APIs.

Aufgaben:
1. Inspiziere alle Dateien im Repo.
2. Identifiziere bestehende Angriffsbeispiele und ordne sie einer sicheren Remote-Demo zu.
3. Erstelle `docs/migration-plan.md` mit:
   - Ist-Zustand,
   - Zielarchitektur,
   - Liste der geplanten Experimente,
   - Sicherheitsgrenzen,
   - Teststrategie,
   - Reihenfolge der Umsetzung.
4. Erstelle `docs/owasp-mcp-coverage.md` mit einer Coverage-Matrix:
   - MCP01 bis MCP10,
   - aktuelle Abdeckung,
   - geplante Remote-Demo,
   - Teststatus.
5. Erstelle noch keine produktiven Server-Endpunkte.
6. Fuehre keine Shell-Kommandos aus, die ueber Inspektion, Tests oder Dateierstellung hinausgehen.

Akzeptanzkriterien:
- `docs/migration-plan.md` existiert.
- `docs/owasp-mcp-coverage.md` existiert.
- Es gibt eine klare Liste der ersten 5 Implementierungsschritte.
- Sicherheitsgrenzen sind explizit dokumentiert.
```

Erwarteter Commit:

```text
docs: add migration plan for safe MCP HTTP demo
```
