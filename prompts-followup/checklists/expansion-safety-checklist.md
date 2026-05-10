# Expansion safety checklist

Use this checklist before merging each expansion prompt.

## Hard no

- [ ] No arbitrary shell execution from untrusted data.
- [ ] No real third-party API calls.
- [ ] No real outbound exfiltration.
- [ ] No cloud metadata requests.
- [ ] No private IP SSRF attempts.
- [ ] No reads outside demo sandbox, except project files required for the app itself.
- [ ] No real secrets in fixtures or docs.
- [ ] No copy-pasteable malicious payloads for real systems.

## Required safe impact

- [ ] Vulnerable mode creates a real bounded artifact.
- [ ] Defended mode blocks the same attempted artifact.
- [ ] Impact ledger records both attempted and actual impact.
- [ ] Telemetry records MCP surface and source provenance.
- [ ] UI displays artifact evidence.
- [ ] Sandbox reset removes all artifacts.

## Public demo readiness

- [ ] Rate limits are present.
- [ ] Session IDs are random and not user-chosen.
- [ ] Origin/CORS rules are restrictive.
- [ ] Network egress is denied by default.
- [ ] Demo reset is available.
- [ ] Docs clearly say all integrations are mocks.
