# Demo Safety Checklist

Vor jeder oeffentlichen Demo pruefen:

- [ ] Keine Demo liest aus Home-Verzeichnissen oder echten Config-Pfaden.
- [ ] Alle Secrets sind Canaries aus `sandbox/` oder runtime-generiert.
- [ ] Alle Exfiltrationen gehen nur an `MockSink`.
- [ ] Alle Mail-/Chat-/GitHub-/OAuth-/Registry-Ziele sind Mock-Komponenten.
- [ ] Keine Demo fuehrt Shell-Kommandos aus User-Input aus.
- [ ] SSRF-Demo nutzt Mock-Resolver, keine echten Zielrequests.
- [ ] Origin-Allowlist ist aktiv.
- [ ] Session-IDs sind zufaellig und kurzlebig.
- [ ] Session-ID wird nicht als Authentisierung verwendet.
- [ ] Event Queues sind nach `user_id:session_id` partitioniert.
- [ ] Logs werden auf Tokens/Secrets gescrubbt.
- [ ] Rate Limits sind aktiv.
- [ ] Demo Reset funktioniert.
- [ ] `pytest` ist gruen.


## Observable Impact Checklist

- [ ] Vulnerable mode erzeugt mindestens einen echten Demo-Impact.
- [ ] Impact bleibt in MockSink, Mock-Inbox, Demo-DB oder `sandbox/effects/`.
- [ ] Defended mode verhindert denselben Impact und erzeugt einen Block-Event.
- [ ] UI zeigt User Intent, Trace, Impact und Defense.
- [ ] Reset loescht alle Demo-Artefakte der Session.
- [ ] Kein Impact nutzt echte Secrets, echte Accounts, echte fremde Netzwerkziele oder User-Dateien.
- [ ] Local calc-proof ist per Default aus und nur lokal per Feature Flag verfuegbar.
