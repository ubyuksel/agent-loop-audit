# Security policy

## Supported versions

Security reports are accepted for the current 0.1.x release line. No response-time
SLA is promised. Use an updated release when reporting a vulnerability.

## Report privately through GitHub

**Private vulnerability reporting is enabled** for this public repository.
On 2026-10-23 the authenticated GitHub API returned `enabled: true` and the public
Advisories page displayed **Report a vulnerability**. No test report was submitted.

Use the [private vulnerability reporting form](https://github.com/ubyuksel/agent-loop-audit/security/advisories/new):

1. Sign in to GitHub, then open **Security > Advisories > Report a vulnerability**.
2. Include the affected version/commit, impact and minimal invented JSONL
   reproduction, with physical lines and expected/actual safe behavior.
3. Submit the private report to notify the repository maintainers.

See [GitHub's reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).
Never post vulnerability details, credentials, personal data or real Codex logs
in public issues. Do not include suspected real secret values even in private
reports. Use synthetic values throughout. Routine non-security issues should
also use invented fixtures. No email/contact identity has been invented here.

If the form is unavailable, keep vulnerability details private. A public issue
may ask for restoration of the reporting channel without revealing the issue.

## Threat model and limits

The runtime handles malicious log strings, terminal controls, bounded resource
exhaustion, ambiguous identity, misleading counters and referenced paths.
It reads only the supplied input, with normal interpreter/package loading allowed.
It performs no network, subprocess, telemetry, plugin execution or repair.
Counts/line relationships may reveal activity. Filesystem races and host compromise
are outside complete portable protection. No zero-vulnerability or complete
anonymization claim is made.

If a real secret appears during development, stop publication and arrange
owner-controlled rotation/revocation. Keep values out of evidence; do not
automatically rewrite history, delete evidence or disclose the finding.
