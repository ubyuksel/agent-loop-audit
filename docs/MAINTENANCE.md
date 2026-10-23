# Maintenance

Revisit the pinned Codex wire shapes monthly or when a synthetic incompatibility
is reported; competitor evidence older than30 days requires a scoped refresh.
Do not add providers, fuzzy loop scores or pricing features without a new scope.
Exact identity/report/counter changes require contract docs, positive and negative
fixtures and independent affected QA. Keep developer and reviewer verdicts separate.

Target weekly voluntary issue/security triage after a reporting route is approved;
this is an operational proposal, not an owner-accepted SLA. Rebuild only when
artifact inputs change. Verify source/artifact hashes before reusing evidence.
Version CLI/report contracts and document pre-1.0 breaking behavior explicitly.

Setuptools may include optional synthetic test source modules in the sdist;
the wheel contains only the runtime package, license and distribution metadata.
The checkout, rather than the installation archive, supplies all test fixtures.
No source archive is a substitute for independently checking candidate bytes.

Never push to trigger CI or publish without separately scoped owner authority.
Mark missing platform/scanner/license/reporting evidence pending. Re-evaluate or
archive the narrow product if its native audit value becomes redundant.
