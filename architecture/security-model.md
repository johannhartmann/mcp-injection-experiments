# Sicherheitsmodell fuer die Online-Demo

## Erlaubt

- Lokale Canary-Dateien unter `sandbox/`.
- Mock-Mail, Mock-WhatsApp, Mock-GitHub, Mock-OAuth, Mock-Registry.
- Echte, begrenzte Canary-Exfiltration in `MockSink` oder lokale Mock-Inbox.
- Simulierte SSRF-Entscheidungen ueber Mock-DNS/Mock-Resolver.
- Echte Demo-Sampling-Kosten ueber lokale Zaehler.
- Simulierte Tool-Poisoning-Texte in Demo-Metadaten, sofern sie keine realen Ziele adressieren.

## Verboten

- Lesen echter Benutzerdateien oder Secrets.
- Ausfuehren von Shell-Kommandos aus User-/Demo-Input.
- Echte HTTP-Requests zu beliebigen User-Zielen.
- Zugriff auf private IPs, Link-Local-Netze oder Cloud-Metadata-Adressen.
- Nutzung echter Mail-/WhatsApp-/Slack-/GitHub-/OAuth-Konten.
- Speichern echter Tokens oder personenbezogener Daten.

## Public Demo Guardrails

- `DEMO_EGRESS_MODE=deny` als Default.
- `DEMO_BIND_HOST=127.0.0.1` fuer lokale Entwicklung.
- In Produktion hinter Reverse Proxy mit HTTPS.
- Origin Allowlist.
- Rate Limits.
- Kurze Session TTL.
- Demo Reset.
- Logs ohne Request-Bodies, die Tokens enthalten koennten.

## Sichere Darstellung von Angriffen

Jedes Angriffsmuster wird mit Canary-Daten gezeigt. Beispiel:

```text
CANARY_REMOTE_TOOL_SHADOWING_abc123
```

Ein Leak gilt als gelungen, wenn dieser Canary in `MockSink` auftaucht. Es darf nie versucht werden, echte Dateien, echte Tokens oder echte Kontakte zu exfiltrieren.

## Erlaubte echte Nebenwirkungen

Die Demo darf reale Nebenwirkungen erzeugen, wenn alle Bedingungen gelten:

1. Der Effekt bleibt innerhalb der Demo-Zone.
2. Der Effekt nutzt nur Canary- oder Fake-Daten.
3. Der Effekt ist sichtbar und reversibel.
4. Der Effekt ist in Telemetrie und UI erklaert.
5. Der Effekt kann per Reset geloescht werden.

Beispiele:

```text
sandbox/effects/direct-poisoning-leak-<session>.json
var/mock-inbox.jsonl
var/demo.db
var/telemetry.jsonl
```

Fuer calc.exe-artige Beweise gilt: Public Demo nutzt Datei-/DB-Impact. Lokaler Dev-Modus darf optional einen festen, nicht parametrisierten Calc-Proof starten, aber nur mit Feature Flag und nie durch User-Input.

