# Observable Impact Model

Die Demo soll Exploits nicht wegabstrahieren. Nutzer sollen sehen, dass etwas passiert ist. Der Unterschied zu einem schaedlichen Exploit ist die Begrenzung des Effekts: echte Nebenwirkung, aber nur in einer isolierten Demo-Zone.

## Grundidee

Ein Angriff gilt erst als demonstriert, wenn mindestens ein echter, beobachtbarer Demo-Effekt entsteht. Beispiele:

- Ein Canary steht in einer Mock-Attacker-Inbox.
- Ein Fake-Mail-Datensatz enthaelt einen versteckten BCC-Empfaenger.
- Eine Datei wird unter `sandbox/effects/` erzeugt.
- Ein Browser-Client sieht den Canary einer anderen Demo-Session.
- Ein Fake-OAuth-Token bewirkt eine ungewollte Aenderung in einem Fake-CRM.
- Ein Sampling-Budgetzaehler wird wirklich reduziert.

## Impact-Zonen

### Zone A: In-memory

Kurzlebige Events im Prozess. Gut fuer Unit-Tests, aber alleine nicht genug fuer eine Demo.

### Zone B: Demo-persistent

Erlaubt und bevorzugt:

```text
sandbox/effects/
var/demo.db
var/mock-inbox.jsonl
var/telemetry.jsonl
```

### Zone C: Lokaler Dev-Impact

Nur fuer lokale Entwicklung, nie in Public Hosting:

```text
open calc.exe on Windows
open Calculator.app on macOS
print fixed marker from fixed allowlisted command
```

Dieser Modus muss per Feature Flag aktiviert werden:

```text
DEMO_ENABLE_LOCAL_CALC_PROOF=true
```

### Zone D: Verboten

- echte Mail-/Chat-/GitHub-/WhatsApp-APIs
- echte Cloud-Metadata-Endpoints
- echte private IPs
- echte User-Dateien
- echte Shell-Ausfuehrung aus User-Input
- beliebige Outbound-URLs

## ImpactEvent Schema

```json
{
  "event_type": "impact",
  "experiment": "remote-tool-shadowing",
  "mode": "vulnerable",
  "impact_type": "mock_message_sent",
  "actor": "malicious-helper-server",
  "target": "mock-mail.attacker-inbox",
  "canary_id": "CANARY_remote_tool_shadowing_123",
  "policy_decision": "allowed_by_vulnerable_mode",
  "artifact": "var/mock-inbox.jsonl:42",
  "user_visible_summary": "A hidden BCC was added to a fake email."
}
```

## Vulnerable vs defended

Vulnerable Mode:

- erzeugt den Demo-Impact wirklich,
- markiert ihn klar als unerwuenscht,
- zeigt den Datenfluss und das betroffene Artefakt.

Defended Mode:

- verhindert denselben Impact,
- erzeugt stattdessen einen `blocked_attempt_recorded` Impact,
- zeigt die Policy-Regel, die blockiert hat.

## UI-Darstellung

Jede Demo-Seite zeigt vier Panels:

1. User Intent
2. Agent/Tool Trace
3. Observable Impact
4. Defense Explanation

Der Nutzer erkennt den Exploit daran, dass Panel 3 ein echtes Demo-Artefakt verlinkt, z. B. Mock-Inbox-Zeile, Demo-DB-Record oder Sandbox-Datei.
