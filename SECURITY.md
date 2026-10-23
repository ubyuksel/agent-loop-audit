# Security policy

## Current status

0.1.0 is an unpublished private candidate, not a supported public release.
No public
security reporting channel is currently available. No email/contact identity or
response-time guarantee has been approved. Never post vulnerability details,
credentials, personal data or real logs in a public issue.

On 2026-10-23 the authenticated repository API confirmed PRIVATE visibility;
`GET /repos/ubyuksel/agent-loop-audit/private-vulnerability-reporting` returned
HTTP 404. This is not evidence of an enabled route. GitHub documents private
vulnerability reporting for **public repositories**:
[configuration](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository).
Activation and availability remain a release blocker while the repository is
private. Visibility must not change during preparation. No alternative private
address has been invented.

## Intended GitHub private reporting procedure (pending activation)

After separately authorized publication, the administrator must enable
**Settings > Advanced Security > Private vulnerability reporting**, verify the
API returns `enabled: true`, and verify a researcher can see **Security >
Advisories > Report a vulnerability**. Until verified, do not describe the route
as available or declare public release readiness.

Once verified, use that private form in
[this repository's advisories](https://github.com/ubyuksel/agent-loop-audit/security/advisories).
See [GitHub's instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).
Provide version/commit, minimal invented JSONL reproduction, physical lines,
expected/actual behavior and impact. Use synthetic values only; never attach a
real rollout or suspected secret value. The form notifies maintainers. This
policy makes no response-time SLA. No report needs to be submitted to test setup.

If the button is absent, keep details private. An owner-approved private route
is required before accepting reports; public issues are unsuitable.

## Threat model and limits

The runtime handles malicious log strings, terminal controls, bounded resource
exhaustion, ambiguous identity, misleading counters and referenced paths.
It reads only the supplied input, with normal interpreter/package loading allowed.
It performs no network, subprocess, telemetry, plugin execution or repair.
Counts/line relationships may reveal activity. Filesystem races and host compromise
are outside complete portable protection. No zero-vulnerability or complete
anonymization claim is made.

If a real secret appears, stop release preparation and arrange owner-controlled
rotation/revocation. Keep values out of evidence; do not automatically rewrite
history, delete evidence or disclose the finding.
