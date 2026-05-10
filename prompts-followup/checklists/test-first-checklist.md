# Test-first checklist

For each prompt, create tests before implementation.

Minimum tests:

```text
1. manifest loads and maps to OWASP / Agent Trap families.
2. vulnerable run creates expected artifact.
3. vulnerable telemetry contains MCP surface and untrusted source.
4. defended run does not create vulnerable artifact.
5. defended telemetry contains block reason.
6. reset removes artifacts.
7. HTTP streaming endpoint exercises the same code path as local runner.
8. UI card can render from impact ledger fixture.
```

Useful test names:

```text
test_<experiment>_vulnerable_creates_bounded_impact
test_<experiment>_defended_blocks_same_impact
test_<experiment>_uses_streamable_http_route
test_<experiment>_emits_telemetry_with_provenance
test_<experiment>_reset_cleans_artifacts
test_<experiment>_ui_card_renders_artifact_evidence
```
