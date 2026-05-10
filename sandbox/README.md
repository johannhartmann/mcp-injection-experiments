# sandbox/

Dieses Verzeichnis ist die einzige Datei-Lese-Oberflaeche, die die Demo
Experimenten zur Verfuegung stellt. Alle Inhalte sind **bewusst fake** und
dienen ausschliesslich der Sichtbarmachung von Angriffen.

## Regeln

- Keine echten Secrets, Tokens oder personenbezogenen Daten ablegen.
- Jede Datei beginnt mit einem auffaelligen `CANARY_*`-Marker, damit ein
  Leak in `MockSink`, in Logs oder in der Telemetrie sofort als
  Demo-Canary erkennbar ist.
- Lese-Zugriff geht ausschliesslich ueber
  `mcp_demo.shared.mock_filesystem.MockFilesystem`. Diese Klasse refused
  absolute Pfade, Home-Referenzen, `..`-Traversals und Symlinks, die aus
  `sandbox/` herausfuehren.
- Schreib-Effekte landen unter `sandbox/effects/` (wird zur Laufzeit
  erstellt) oder in `var/`.

## Inhalte

- `demo-secret.txt` - sichtbarer Demo-Canary, ersetzt das echte
  `~/.cursor/mcp.json` aus dem historischen `direct-poisoning.py`-PoC.
- `demo-ssh-pub.txt` - Demo-Pendant zu `~/.ssh/id_rsa.pub`. Echter Schluessel
  wird **nie** abgelegt; statt dessen ein offensichtlich gefakter Public-Key.

## Was hier nicht passiert

- Keine `~/.ssh`-, `~/.cursor`-, `~/.config`-Reads.
- Keine `.env`-Reads.
- Keine `/etc/passwd`- oder anderer Systemdatei-Zugriff.
- Keine echten API-Schluessel, OAuth-Tokens oder Webhook-URLs.

Wenn ein Experiment versuchen wuerde, eine Datei ausserhalb von `sandbox/`
zu lesen, schlaegt der `MockFilesystem`-Pfad-Check mit einer
`MockFilesystemPathError` fehl, bevor irgendein I/O passiert.
