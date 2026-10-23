# Security status

0.1.x is a private candidate line, not a published supported release. No public
security reporting channel has been approved/configured. That remains a release
blocker. Do not invent a contact address or post vulnerabilities, credentials,
personal data or real logs publicly. The owner must establish an approved private
reporting route before publication. No response-time SLA is offered.

Prepare only a minimal invented reproduction, affected candidate version/hash,
physical lines and expected/actual safe behavior for later private review.
Never include suspected real secret values in evidence. If a real secret appears,
stop release and arrange owner-controlled revocation; do not rewrite history or
delete evidence automatically.

The runtime threat model covers malicious log strings, terminal controls,
resource exhaustion, ambiguous identity, misleading counters and referenced paths.
It reads only one supplied file; normal interpreter/package loading is allowed.
It performs no network, subprocess, telemetry, dynamic plugin execution or repair.
No claim of zero vulnerabilities, exact billing or complete anonymization is made.
